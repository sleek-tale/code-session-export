#!/usr/bin/env python3
"""Export and sanitize code assistant sessions — strip PII, secrets, and paths.

Launch modes:
  Double-click / no args:  GUI
  CLI:  python code_session_export.py -o ~/backup/sessions
  GUI:  python code_session_export.py --gui
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from collections import defaultdict
from pathlib import Path

__version__ = "0.4.0"


class _Cancelled(Exception):
    pass


# Python 3.14's re module has a segfault bug on large inputs.
# Detect and re-exec with a safe Python if available.
_UNSAFE_PY = sys.version_info[:2] >= (3, 14)

def _find_safe_python():
    for name in ("python3.13", "python3.12", "python3.11", "python3.10", "python3.9"):
        p = shutil.which(name)
        if p:
            return p
    return None

if _UNSAFE_PY and "_CSE_REEXEC" not in os.environ:
    _safe = _find_safe_python()
    if _safe:
        os.environ["_CSE_REEXEC"] = "1"
        os.execv(_safe, [_safe] + sys.argv)
    else:
        print(
            f"WARNING: Python {sys.version_info[0]}.{sys.version_info[1]} has a known regex bug "
            f"that can crash on large session files.\n"
            f"Install Python 3.12 or 3.13 for reliable operation.\n"
            f"Continuing anyway — large files may cause crashes.\n",
            file=sys.stderr,
        )

# ---------------------------------------------------------------------------
# Session discovery
# ---------------------------------------------------------------------------

def find_claude_dir():
    return Path.home() / ".claude"


def find_sessions(claude_dir, filter_model=None):
    projects_dir = claude_dir / "projects"
    if not projects_dir.exists():
        return []

    sessions = []
    for jsonl in projects_dir.rglob("*.jsonl"):
        if jsonl.name == "history.jsonl":
            continue

        if filter_model:
            found = False
            try:
                with open(jsonl, errors="replace") as f:
                    for line in f:
                        if filter_model.lower() in line.lower():
                            found = True
                            break
            except Exception:
                found = True
            if not found:
                continue

        try:
            size = jsonl.stat().st_size
        except OSError:
            continue

        first_ts = None
        msg_count = 0
        has_thinking = False
        project = jsonl.parent.name
        try:
            with open(jsonl) as f:
                for line in f:
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if d.get("type") in ("user", "assistant"):
                        msg_count += 1
                    if d.get("type") == "user" and d.get("timestamp") and not first_ts:
                        first_ts = d["timestamp"]
                    if not has_thinking and d.get("type") == "assistant" and '"thinking"' in line:
                        msg = d.get("message", {})
                        if isinstance(msg, dict):
                            content = msg.get("content", [])
                            if isinstance(content, list) and any(
                                isinstance(b, dict) and b.get("type") == "thinking" for b in content
                            ):
                                has_thinking = True
        except Exception:
            pass

        sessions.append({
            "path": jsonl,
            "size": size,
            "msg_count": msg_count,
            "first_timestamp": first_ts,
            "session_id": jsonl.stem,
            "project": project,
            "has_thinking": has_thinking,
        })

    sessions.sort(key=lambda s: s.get("first_timestamp") or "", reverse=True)
    return sessions


def export_readable(src_path, dst_path):
    first_ts = None
    msg_count = 0

    with open(src_path) as f:
        for line in f:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = d.get("type")
            if t in ("user", "assistant", "summary"):
                msg_count += 1
                if "timestamp" in d and not first_ts:
                    first_ts = d["timestamp"]

    with open(dst_path, "w") as out:
        out.write('{\n')
        out.write(f'  "session_id": {json.dumps(Path(src_path).stem, ensure_ascii=False)},\n')
        out.write(f'  "first_timestamp": {json.dumps(first_ts, ensure_ascii=False)},\n')
        out.write(f'  "message_count": {msg_count},\n')
        out.write('  "messages": [\n')

        first_entry = True
        with open(src_path) as f:
            for line in f:
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                t = d.get("type")
                if t not in ("user", "assistant", "summary"):
                    continue
                entry = {"type": t}
                if "timestamp" in d:
                    entry["timestamp"] = d["timestamp"]
                if "model" in d:
                    entry["model"] = d["model"]

                msg = d.get("message", {})
                if isinstance(msg, dict):
                    content = msg.get("content", "")
                    if isinstance(content, list):
                        parts = []
                        for block in content:
                            if isinstance(block, dict):
                                bt = block.get("type")
                                if bt == "text":
                                    parts.append({"type": "text", "text": block.get("text", "")})
                                elif bt == "thinking":
                                    parts.append({"type": "thinking", "thinking": block.get("thinking", "")})
                                elif bt == "tool_use":
                                    parts.append({"type": "tool_use", "name": block.get("name", ""), "input": block.get("input", {})})
                                elif bt == "tool_result":
                                    parts.append({"type": "tool_result", "content": str(block.get("content", ""))[:50000]})
                                else:
                                    parts.append(block)
                            elif isinstance(block, str):
                                parts.append({"type": "text", "text": block})
                        entry["content"] = parts
                    else:
                        entry["content"] = content
                elif isinstance(msg, str):
                    entry["content"] = msg

                if not first_entry:
                    out.write(",\n")
                json.dump(entry, out, indent=4, ensure_ascii=False)
                first_entry = False

        out.write('\n  ]\n')
        out.write('}\n')


# ---------------------------------------------------------------------------
# PII / secret detection
# ---------------------------------------------------------------------------

# --- Paths ---
_USER_CH = r'a-zA-ZÀ-ÖØ-öø-ÿ0-9._\-'
HOME_PATH_RE = re.compile(
    r'(?:'
    rf'/home/([{_USER_CH}]+)'
    rf'|/Users/([{_USER_CH}]+)'
    rf'|C:\\\\Users\\\\([{_USER_CH}]+)'
    rf'|C:/Users/([{_USER_CH}]+)'
    rf'|C:\\Users\\([{_USER_CH}]+)'
    r')'
)

# --- SMB/CIFS ---
SMB_URL_RE = re.compile(r'smb://(?:([a-zA-Z0-9._\-]+)@)?([a-zA-Z0-9._\-]+)/([a-zA-Z0-9._\-/]+)')
UNC_PATH_RE = re.compile(
    r'(?<!:)(?://|\\\\)'
    r'([a-zA-Z][a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+)'
    r'/([a-zA-Z0-9._\-/]+)',
)
CIFS_MOUNT_RE = re.compile(r'(?:username|user)=([a-zA-Z0-9._\-]+)', re.IGNORECASE)
CIFS_CREDS_RE = re.compile(r'credentials?=([^\s,]+)')

# --- SSH ---
SSH_USER_HOST_RE = re.compile(r'(?:ssh|scp|rsync|sftp)\s+(?:-[^\s]+\s+)*([a-zA-Z0-9._\-]+)@([a-zA-Z0-9._\-]+(?:\.[a-zA-Z0-9._\-]+)*)')
BARE_USER_HOST_RE = re.compile(r'([a-zA-Z0-9._\-]{1,128})@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
SSH_CONFIG_HOST_RE = re.compile(r'^\s*Host(?:Name)?\s+([a-zA-Z0-9._\-]+(?:\.[a-zA-Z]{2,}))', re.MULTILINE | re.IGNORECASE)
SSH_CONFIG_USER_RE = re.compile(r'^\s*User\s+([a-zA-Z0-9._\-]{2,})\s*$', re.MULTILINE)
KNOWN_HOSTS_RE = re.compile(
    r'^(\|1\|[a-zA-Z0-9+/=]+\|[a-zA-Z0-9+/=]+|[a-zA-Z0-9._\-,\[\]:]+)\s+'
    r'(?:ssh-rsa|ecdsa-sha2-\S+|ssh-ed25519|ssh-dss)\s+[a-zA-Z0-9+/]{20,}=*',
    re.MULTILINE,
)

# --- Network ---
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]{1,128}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,63}')
IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
MAC_RE = re.compile(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
HOSTNAME_LOCAL_RE = re.compile(r'[a-zA-Z0-9\-]{1,63}\.local\b')
TAILSCALE_IP_RE = re.compile(r'\b100\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

# --- Shell prompts ---
SHELL_PROMPT_RE = re.compile(r'\[?([a-zA-Z0-9._\-]{2,32})@([a-zA-Z0-9._\-]{2,64})\s*[~\]][^\n]*[$#]\s')
SUDO_PROMPT_RE = re.compile(r'(?:\[sudo\]\s+password\s+for\s+|sudo:\s+)([a-zA-Z0-9._\-]+)', re.IGNORECASE)
PASSWD_ENTRY_RE = re.compile(r'^([a-zA-Z0-9._\-]+):x:\d+:\d+:[^:]*:/[^:]*:/[^\s]+$', re.MULTILINE)

# --- Database connection strings ---
DB_CONN_RE = re.compile(
    r'(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|amqps|mssql)'
    r'://(?:([a-zA-Z0-9._\-]+)(?::([^@\s]{3,}))?@)?([a-zA-Z0-9._\-]+(?::\d+)?)',
    re.IGNORECASE,
)

# --- Service-specific tokens ---
HF_TOKEN_RE = re.compile(r'hf_[a-zA-Z0-9]{20,}')
SK_TOKEN_RE = re.compile(r'sk-[a-zA-Z0-9\-]{20,}')
AWS_KEY_RE = re.compile(r'(?:AKIA|ASIA)[0-9A-Z]{16}')
GH_TOKEN_RE = re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}')
NPM_TOKEN_RE = re.compile(r'npm_[a-zA-Z0-9]{36,}')
NPM_AUTH_RE = re.compile(r'_authToken\s*=\s*([a-zA-Z0-9\-._~+/]{20,})')
PYPI_TOKEN_RE = re.compile(r'pypi-[a-zA-Z0-9\-_]{32,}')
STRIPE_KEY_RE = re.compile(r'(?:sk|pk|rk|whsec)_(?:live|test)_[a-zA-Z0-9]{20,}')
SENDGRID_KEY_RE = re.compile(r'SG\.[a-zA-Z0-9\-_]{20,}\.[a-zA-Z0-9\-_]{20,}')
SLACK_TOKEN_RE = re.compile(r'xox[abposr]\-[a-zA-Z0-9\-]{10,}')
GITLAB_TOKEN_RE = re.compile(r'glpat-[a-zA-Z0-9_\-]{20,}')
GH_FINE_GRAINED_TOKEN_RE = re.compile(r'github_pat_[a-zA-Z0-9_]{20,}_[a-zA-Z0-9_]{20,}')
GOOGLE_API_KEY_RE = re.compile(r'AIza[a-zA-Z0-9\-_]{35}')
TWILIO_SID_RE = re.compile(r'AC[a-f0-9]{32}\b')
TWILIO_AUTH_TOKEN_RE = re.compile(r'(?i)(?:twilio[_-]?(?:auth[_-]?)?token)\s*[=:]\s*["\']?([a-f0-9]{32})["\']?')
DO_TOKEN_RE = re.compile(r'dop_v1_[a-f0-9]{64}')
MAILGUN_KEY_RE = re.compile(r'key-[a-f0-9]{32}')
MAILGUN_SIGNING_KEY_RE = re.compile(r'(?i)(?:mailgun[_-]?signing[_-]?key)\s*[=:]\s*["\']?([a-f0-9]{32})["\']?')
VAULT_TOKEN_RE = re.compile(r'\b(?:hvs|s)\.[a-zA-Z0-9]{24,}')
TELEGRAM_BOT_RE = re.compile(r'\d{8,10}:[a-zA-Z0-9_\-]{35}')
SENTRY_DSN_RE = re.compile(r'https://([a-f0-9]{32})@(?:o\d+\.ingest\.)?sentry\.io/\d+')
OPENROUTER_KEY_RE = re.compile(r'sk-or-v1-[a-zA-Z0-9_\-]{32,}')
GROQ_KEY_RE = re.compile(r'gsk_[a-zA-Z0-9]{40,}')
MISTRAL_KEY_RE = re.compile(r'(?i)(?:mistral[_-]?(?:api[_-]?)?key)\s*[=:]\s*["\']?([a-zA-Z0-9]{32,})["\']?')
VERCEL_TOKEN_RE = re.compile(r'(?i)(?:vercel[_-]?token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?')
NETLIFY_TOKEN_RE = re.compile(r'(?i)(?:netlify[_-]?(?:auth[_-]?)?token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?')
CLOUDFLARE_TOKEN_RE = re.compile(r'(?i)(?:cloudflare[_-]?(?:api[_-]?)?(?:token|key))\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?')
DATABRICKS_TOKEN_RE = re.compile(r'dapi[a-f0-9]{32}\b')
SUPABASE_KEY_RE = re.compile(r'sbp_[a-zA-Z0-9_\-]{30,}')

# --- Generic secrets ---
BEARER_RE = re.compile(r'Bearer\s+[a-zA-Z0-9\-._~+/]{20,}=*')
JWT_RE = re.compile(r'eyJ[a-zA-Z0-9\-_]{20,}\.eyJ[a-zA-Z0-9\-_]{20,}\.[a-zA-Z0-9\-_]+')
GENERIC_SECRET_RE = re.compile(
    r'(?:api[_-]?key|secret[_-]?key|token|password|passwd|credential|private[_-]?key|auth[_-]?token|access[_-]?key)'
    r'\s*[=:]\s*["\']?([a-zA-Z0-9\-._~+/]{16,})["\']?',
    re.IGNORECASE,
)
OAUTH_TOKEN_RE = re.compile(
    r'(?:access_token|refresh_token|id_token)\s*[=:]\s*["\']?([a-zA-Z0-9\-._~+/]{30,})["\']?',
    re.IGNORECASE,
)
COOKIE_SESSION_RE = re.compile(
    r'(?:Set-Cookie|Cookie)\s*:\s*[^\r\n]*?(?:session|sess|auth|token|jwt)[^=]*=([a-zA-Z0-9\-._~+/%]{20,})',
    re.IGNORECASE,
)
DOCKER_AUTH_RE = re.compile(r'"auth"\s*:\s*"([a-zA-Z0-9+/]{20,}={0,2})"')

# --- Crypto ---
WALLET_RE = re.compile(r'0x[0-9a-fA-F]{40}')
SSH_PRIVATE_RE = re.compile(r'-----BEGIN (?:RSA |EC |DSA |ED25519 |OPENSSH )?PRIVATE KEY-----')
PGP_PRIVATE_RE = re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----')
WG_PRIVATE_RE = re.compile(r'(?:PrivateKey|private[_\s]?key)\s*=\s*([a-zA-Z0-9+/]{43}=)', re.IGNORECASE)
AGE_SECRET_RE = re.compile(r'AGE-SECRET-KEY-1[AC-HJ-NP-Z02-9]{58}')

# --- Webhooks ---
DISCORD_WEBHOOK_RE = re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_\-]+')
SLACK_WEBHOOK_RE = re.compile(r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+')

# --- Git ---
GIT_AUTHOR_RE = re.compile(r'Author:\s+(.+?)\s+<([^>]+)>')
GIT_REMOTE_RE = re.compile(r'(?:github|gitlab|bitbucket)\.com[:/]([a-zA-Z0-9._\-]+)/')
GIT_CONFIG_NAME_RE = re.compile(r'^\s*name\s*=\s*(.+)$', re.MULTILINE)
GIT_CONFIG_EMAIL_RE = re.compile(r'^\s*email\s*=\s*(.+)$', re.MULTILINE)

# --- .netrc ---
NETRC_RE = re.compile(r'machine\s+(\S+)\s+login\s+(\S+)\s+password\s+(\S+)', re.IGNORECASE)

# --- Phone / CC / Address ---
PHONE_RE = re.compile(
    r'(?<!\d)(?:\+1[\s\-.]?)?'
    r'\(?(\d{3})\)?[\s\-.](\d{3})[\s\-.](\d{4})'
    r'(?!\d)',
)
CC_NUMBER_RE = re.compile(
    r'(?<!\d)(?:'
    r'4\d{3}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}'
    r'|5[1-5]\d{2}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}'
    r'|3[47]\d{2}[\s\-]\d{6}[\s\-]\d{5}'
    r')(?!\d)',
)

# --- GCP ---
GCP_SA_EMAIL_RE = re.compile(r'[a-zA-Z0-9\-]{1,128}@[a-zA-Z0-9\-]{1,63}\.iam\.gserviceaccount\.com')

# --- International phone ---
INTL_PHONE_RE = re.compile(
    r'(?<!\d)\+(?:44|33|49|34|39|31|46|47|48|61|64|81|82|86|91|7|55|52|27|90|62|63|66)'
    r'[\s\-.]?\(?\d{1,4}\)?[\d\s\-.]{5,13}\d(?!\d)',
)

# --- US SSN ---
SSN_RE = re.compile(r'(?<!\d)(?!000|666|9\d\d)(\d{3})[\s\-](?!00)(\d{2})[\s\-](?!0000)(\d{4})(?!\d)')

# --- Additional API keys ---
SK_ANT_KEY_RE = re.compile(r'sk-ant-[a-zA-Z0-9\-]{20,}')
AWS_SECRET_RE = re.compile(
    r'(?:aws_secret_access_key|secret_access_key)\s*[=:]\s*["\']?([a-zA-Z0-9+/]{40})["\']?',
    re.IGNORECASE,
)
GOCSPX_RE = re.compile(r'GOCSPX-[a-zA-Z0-9_\-]{24,}')
AZURE_SECRET_RE = re.compile(
    r'(?:client_secret|AZURE_CLIENT_SECRET|AZURE_SECRET)\s*[=:]\s*["\']?([a-zA-Z0-9~._\-]{34,})["\']?',
    re.IGNORECASE,
)

# --- URL with embedded credentials ---
URL_AUTH_RE = re.compile(r'https?://([a-zA-Z0-9._\-]+):([^@\s]{3,})@([a-zA-Z0-9._\-]+(?::\d+)?)')

# --- GPS coordinates (4+ decimal places, valid lat/lon ranges) ---
GPS_RE = re.compile(r'(?<!\d)(-?\d{1,3}\.\d{4,8})\s*,\s*(-?\d{1,3}\.\d{4,8})(?!\d)')

# --- Environment variable secrets ---
ENV_SECRET_RE = re.compile(
    r'\b([A-Z][A-Z0-9_]*(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PASSWD|_CREDENTIAL|_AUTH))\s*='
    r'\s*["\']?([^\s"\']{16,})["\']?',
)

# --- Safe lists ---
SAFE_EMAILS = {
    "jane@co.com", "john@co.com",
    "john@example.com", "user@example.com", "test@example.com",
}
SAFE_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
SAFE_USERNAMES = {
    "root", "admin", "user", "nobody", "www-data", "daemon", "bin",
    "sys", "guest", "bokken", "person", "assistant", "bot",
    "true", "false", "null", "none", "test", "dev", "app", "api",
    "home", "local", "tmp", "var", "opt", "etc", "usr", "lib",
    "a", "b", "c", "x", "...", ".",
}
SAFE_HOSTNAMES = {
    "localhost", "localhost.local", "settings.local", "storage.local",
    "config.local", "ubuntu", "debian", "fedora", "archlinux",
}
DOCKER_IP_RE = re.compile(r'^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$')
SAFE_DB_HOSTS = {"localhost", "127.0.0.1", "db", "database", "postgres", "mysql", "mongo", "redis"}

DISABLE_SCAN_PREFILTER_ENV = "CSE_DISABLE_SCAN_PREFILTER"

_SCAN_PREFILTER_ANCHORS = [
    (HOME_PATH_RE, ("/home/", "/Users/", "C:\\\\Users\\\\", "C:/Users/", "C:\\Users\\")),
    (SMB_URL_RE, ("smb://",)),
    (UNC_PATH_RE, ("//", "\\\\")),
    (CIFS_MOUNT_RE, ("user",)),
    (CIFS_CREDS_RE, ("credential",)),
    (SSH_USER_HOST_RE, ("ssh ", "scp ", "rsync ", "sftp ")),
    (BARE_USER_HOST_RE, ("@",)),
    (SSH_CONFIG_HOST_RE, ("Host",)),
    (SSH_CONFIG_USER_RE, ("User",)),
    (KNOWN_HOSTS_RE, ("ssh-rsa", "ecdsa-sha2-", "ssh-ed25519", "ssh-dss")),
    (EMAIL_RE, ("@",)),
    (MAC_RE, (":",)),
    (HOSTNAME_LOCAL_RE, (".local",)),
    (TAILSCALE_IP_RE, ("100.",)),
    (SHELL_PROMPT_RE, ("@",)),
    (SUDO_PROMPT_RE, ("sudo",)),
    (PASSWD_ENTRY_RE, (":x:",)),
    (DB_CONN_RE, ("://",)),
    (HF_TOKEN_RE, ("hf_",)),
    (SK_TOKEN_RE, ("sk-",)),
    (AWS_KEY_RE, ("AKIA", "ASIA")),
    (GH_TOKEN_RE, ("gh",)),
    (NPM_TOKEN_RE, ("npm_",)),
    (NPM_AUTH_RE, ("_authToken",)),
    (PYPI_TOKEN_RE, ("pypi-",)),
    (STRIPE_KEY_RE, ("_live_", "_test_")),
    (SENDGRID_KEY_RE, ("SG.",)),
    (SLACK_TOKEN_RE, ("xox",)),
    (GITLAB_TOKEN_RE, ("glpat-",)),
    (GH_FINE_GRAINED_TOKEN_RE, ("github_pat_",)),
    (GOOGLE_API_KEY_RE, ("AIza",)),
    (TWILIO_SID_RE, ("AC",)),
    (TWILIO_AUTH_TOKEN_RE, ("twilio",)),
    (DO_TOKEN_RE, ("dop_v1_",)),
    (MAILGUN_KEY_RE, ("key-",)),
    (MAILGUN_SIGNING_KEY_RE, ("mailgun",)),
    (VAULT_TOKEN_RE, ("hvs.", "s.")),
    (SENTRY_DSN_RE, ("sentry.io",)),
    (OPENROUTER_KEY_RE, ("sk-or-v1-",)),
    (GROQ_KEY_RE, ("gsk_",)),
    (MISTRAL_KEY_RE, ("mistral",)),
    (VERCEL_TOKEN_RE, ("vercel",)),
    (NETLIFY_TOKEN_RE, ("netlify",)),
    (CLOUDFLARE_TOKEN_RE, ("cloudflare",)),
    (DATABRICKS_TOKEN_RE, ("dapi",)),
    (SUPABASE_KEY_RE, ("sbp_",)),
    (BEARER_RE, ("Bearer",)),
    (JWT_RE, ("eyJ",)),
    (GENERIC_SECRET_RE, ("key", "secret", "token", "password", "passwd", "credential", "private", "auth")),
    (OAUTH_TOKEN_RE, ("access_token", "refresh_token", "id_token")),
    (COOKIE_SESSION_RE, ("Cookie",)),
    (DOCKER_AUTH_RE, ('"auth"',)),
    (WALLET_RE, ("0x",)),
    (SSH_PRIVATE_RE, ("-----BEGIN", "PRIVATE KEY-----")),
    (PGP_PRIVATE_RE, ("-----BEGIN PGP PRIVATE KEY BLOCK-----",)),
    (WG_PRIVATE_RE, ("PrivateKey", "private", "key")),
    (AGE_SECRET_RE, ("AGE-SECRET-KEY-1",)),
    (DISCORD_WEBHOOK_RE, ("discord", "/api/webhooks/")),
    (SLACK_WEBHOOK_RE, ("hooks.slack.com/services",)),
    (GIT_AUTHOR_RE, ("Author:",)),
    (GIT_REMOTE_RE, ("github.com", "gitlab.com", "bitbucket.com")),
    (GIT_CONFIG_NAME_RE, ("name",)),
    (GIT_CONFIG_EMAIL_RE, ("email",)),
    (NETRC_RE, ("machine",)),
    (GCP_SA_EMAIL_RE, (".iam.gserviceaccount.com",)),
    (SK_ANT_KEY_RE, ("sk-ant-",)),
    (AWS_SECRET_RE, ("secret_access_key",)),
    (GOCSPX_RE, ("GOCSPX-",)),
    (AZURE_SECRET_RE, ("client_secret", "AZURE_CLIENT_SECRET", "AZURE_SECRET")),
    (URL_AUTH_RE, ("://", "@")),
    (ENV_SECRET_RE, ("_KEY", "_SECRET", "_TOKEN", "_PASSWORD", "_PASSWD", "_CREDENTIAL", "_AUTH")),
]
_SCAN_PREFILTER_ANCHOR_MAP = dict(_SCAN_PREFILTER_ANCHORS)


def _luhn_check(digits):
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def scan_text(text):
    findings = set()
    prefilter_enabled = os.environ.get(DISABLE_SCAN_PREFILTER_ENV, "").lower() not in ("1", "true", "yes", "on")
    text_lower = None

    def should_scan(pat):
        nonlocal text_lower
        anchors = _SCAN_PREFILTER_ANCHOR_MAP.get(pat)
        if not prefilter_enabled or not anchors:
            return True
        if pat.flags & re.IGNORECASE:
            if text_lower is None:
                text_lower = text.lower()
            return any(anchor.lower() in text_lower for anchor in anchors)
        return any(anchor in text for anchor in anchors)

    def matches(pat):
        return pat.finditer(text) if should_scan(pat) else ()

    # Emails
    _CODE_DOMAINS = {"app", "model", "get", "post", "put", "delete", "patch", "route", "router"}
    for m in matches(EMAIL_RE):
        email = m.group(0)
        local = email.split("@")[0]
        domain_parts = email.split("@")[1].split(".")
        pos = m.start()
        if pos > 0 and text[pos - 1] == "\\":
            continue
        if (email.lower() not in SAFE_EMAILS
                and len(local) >= 2
                and domain_parts[0].lower() not in _CODE_DOMAINS
                and not email.startswith("+")):
            findings.add((email, "email"))

    # GCP service account emails
    for m in matches(GCP_SA_EMAIL_RE):
        findings.add((m.group(0), "email"))

    # Home paths
    for m in matches(HOME_PATH_RE):
        username = next((g for g in m.groups() if g), None)
        if username and username.lower() not in SAFE_USERNAMES:
            findings.add((username, "username"))

    # IPs
    for m in matches(IP_RE):
        ip = m.group(1)
        parts = ip.split(".")
        try:
            octets = [int(p) for p in parts]
            is_private = (
                octets[0] == 10
                or octets[0] == 127
                or (octets[0] == 172 and 16 <= octets[1] <= 31)
                or (octets[0] == 192 and octets[1] == 168)
            )
            before = text[max(0, m.start() - 16):m.start()].lower()
            if (all(0 <= o <= 255 for o in octets)
                    and ip not in SAFE_IPS
                    and not is_private
                    and octets[3] != 0 and octets[2:] != [0, 0]
                    and octets[1:] != [0, 0, 0]
                    and not re.search(r'(?:^|[^a-z0-9])(?:version|ver|v)(?:\s|["=:\'])*$', before)):
                findings.add((ip, "ip"))
        except ValueError:
            pass
    for m in matches(TAILSCALE_IP_RE):
        findings.add((m.group(0), "ip"))

    # MACs
    for m in matches(MAC_RE):
        findings.add((m.group(0), "mac"))

    # Hostnames (.local)
    for m in matches(HOSTNAME_LOCAL_RE):
        hostname = m.group(0)
        if hostname.lower() not in SAFE_HOSTNAMES:
            pos = m.start()
            if pos > 0 and text[pos - 1] == "\\":
                continue
            findings.add((hostname, "hostname"))

    # SMB
    for m in matches(SMB_URL_RE):
        if m.group(1) and m.group(1).lower() not in SAFE_USERNAMES:
            findings.add((m.group(1), "smb_user"))
        findings.add((m.group(2), "smb_host"))
    for m in matches(UNC_PATH_RE):
        findings.add((m.group(1), "smb_host"))
    for m in matches(CIFS_MOUNT_RE):
        if m.group(1).lower() not in SAFE_USERNAMES:
            findings.add((m.group(1), "smb_user"))
    for m in matches(CIFS_CREDS_RE):
        findings.add((m.group(1), "creds_path"))

    # SSH
    for m in matches(SSH_USER_HOST_RE):
        if m.group(1).lower() not in SAFE_USERNAMES:
            findings.add((m.group(1), "ssh_user"))
        findings.add((m.group(2), "ssh_host"))
    for m in matches(BARE_USER_HOST_RE):
        if m.group(1).lower() not in SAFE_USERNAMES:
            findings.add((m.group(1), "ssh_user"))
    for m in matches(SSH_CONFIG_HOST_RE):
        if m.group(1).lower() not in ("*", "localhost"):
            findings.add((m.group(1), "ssh_host"))
    for m in matches(SSH_CONFIG_USER_RE):
        if m.group(1).lower() not in SAFE_USERNAMES:
            findings.add((m.group(1), "username"))
    for m in matches(KNOWN_HOSTS_RE):
        host_field = m.group(1)
        if not host_field.startswith("|1|"):
            for part in host_field.split(","):
                part = part.strip().strip("[]").split(":")[0]
                if part and part not in ("localhost", "127.0.0.1"):
                    findings.add((part, "ssh_host"))

    # Shell prompts
    for m in matches(SHELL_PROMPT_RE):
        u, h = m.group(1), m.group(2)
        if u.lower() not in SAFE_USERNAMES:
            findings.add((u, "username"))
        if h.lower() not in SAFE_HOSTNAMES:
            findings.add((h, "hostname"))
    for m in matches(SUDO_PROMPT_RE):
        if m.group(1).lower() not in SAFE_USERNAMES:
            findings.add((m.group(1), "username"))
    for m in matches(PASSWD_ENTRY_RE):
        if m.group(1).lower() not in SAFE_USERNAMES:
            findings.add((m.group(1), "username"))

    # Database connection strings
    for m in matches(DB_CONN_RE):
        if m.group(1) and m.group(1).lower() not in SAFE_USERNAMES:
            findings.add((m.group(1), "db_user"))
        if m.group(2):
            findings.add((m.group(2), "secret"))
        host = m.group(3).split(":")[0]
        if host and host not in SAFE_DB_HOSTS:
            findings.add((host, "db_host"))

    # .netrc
    for m in matches(NETRC_RE):
        findings.add((m.group(1), "ssh_host"))
        if m.group(2).lower() not in SAFE_USERNAMES:
            findings.add((m.group(2), "username"))
        findings.add((m.group(3), "secret"))

    # Git
    for m in matches(GIT_AUTHOR_RE):
        name = m.group(1).strip()
        if (name.lower() not in SAFE_USERNAMES
                and 1 < len(name) <= 80
                and not name.startswith("\\n")
                and not name.startswith("\n")):
            findings.add((name, "git_author"))
    for m in matches(GIT_REMOTE_RE):
        findings.add((m.group(1), "github_user"))
    for m in matches(GIT_CONFIG_NAME_RE):
        name = m.group(1).strip()
        if name.lower() not in SAFE_USERNAMES and len(name) > 1:
            findings.add((name, "git_author"))
    for m in matches(GIT_CONFIG_EMAIL_RE):
        email = m.group(1).strip()
        if email.lower() not in SAFE_EMAILS:
            findings.add((email, "email"))

    # --- All tokens/secrets ---
    _token_patterns = [
        (HF_TOKEN_RE, 0), (SK_TOKEN_RE, 0), (AWS_KEY_RE, 0), (GH_TOKEN_RE, 0),
        (GH_FINE_GRAINED_TOKEN_RE, 0), (GITLAB_TOKEN_RE, 0),
        (NPM_TOKEN_RE, 0), (PYPI_TOKEN_RE, 0), (STRIPE_KEY_RE, 0),
        (SENDGRID_KEY_RE, 0), (SLACK_TOKEN_RE, 0), (GOOGLE_API_KEY_RE, 0),
        (TWILIO_SID_RE, 0), (DO_TOKEN_RE, 0), (MAILGUN_KEY_RE, 0),
        (VAULT_TOKEN_RE, 0), (TELEGRAM_BOT_RE, 0), (AGE_SECRET_RE, 0),
        (JWT_RE, 0), (OPENROUTER_KEY_RE, 0), (GROQ_KEY_RE, 0),
        (DATABRICKS_TOKEN_RE, 0), (SUPABASE_KEY_RE, 0),
    ]
    for pat, grp in _token_patterns:
        for m in matches(pat):
            findings.add((m.group(grp), "apikey"))

    for m in matches(NPM_AUTH_RE):
        findings.add((m.group(1), "apikey"))
    for pat in (
            TWILIO_AUTH_TOKEN_RE, MAILGUN_SIGNING_KEY_RE, MISTRAL_KEY_RE,
            VERCEL_TOKEN_RE, NETLIFY_TOKEN_RE, CLOUDFLARE_TOKEN_RE):
        for m in matches(pat):
            findings.add((m.group(1), "apikey"))
    for m in matches(SENTRY_DSN_RE):
        findings.add((m.group(0), "apikey"))
    for m in matches(BEARER_RE):
        findings.add((m.group(0), "bearer"))
    for m in matches(GENERIC_SECRET_RE):
        val = m.group(1)
        if not re.fullmatch(r'[a-z_]+(?:\.[a-z_]+)*', val):
            findings.add((val, "secret"))
    for m in matches(OAUTH_TOKEN_RE):
        findings.add((m.group(1), "apikey"))
    for m in matches(COOKIE_SESSION_RE):
        findings.add((m.group(1), "secret"))
    for m in matches(DOCKER_AUTH_RE):
        findings.add((m.group(1), "apikey"))
    for m in matches(WG_PRIVATE_RE):
        findings.add((m.group(1), "apikey"))

    # Webhooks
    for m in matches(DISCORD_WEBHOOK_RE):
        findings.add((m.group(0), "webhook"))
    for m in matches(SLACK_WEBHOOK_RE):
        findings.add((m.group(0), "webhook"))

    # Wallets (skip zero-padded constants/precompile addresses — not real wallets)
    for m in matches(WALLET_RE):
        if not m.group(0)[2:].startswith("0" * 16):
            findings.add((m.group(0), "wallet"))

    # Private keys
    if should_scan(SSH_PRIVATE_RE) and SSH_PRIVATE_RE.search(text):
        findings.add(("SSH_PRIVATE_KEY_BLOCK", "sshkey"))
    if should_scan(PGP_PRIVATE_RE) and PGP_PRIVATE_RE.search(text):
        findings.add(("PGP_PRIVATE_KEY_BLOCK", "pgpkey"))

    # Phone numbers (regex now requires separators between groups)
    for m in matches(PHONE_RE):
        findings.add((m.group(0).strip(), "phone"))

    # Credit cards (require separators + Luhn check)
    for m in matches(CC_NUMBER_RE):
        original = m.group(0)
        digits = original.replace(" ", "").replace("-", "")
        if _luhn_check(digits):
            findings.add((original, "cc_number"))

    # International phone numbers (require country code)
    for m in matches(INTL_PHONE_RE):
        findings.add((m.group(0).strip(), "phone"))

    # US Social Security Numbers
    for m in matches(SSN_RE):
        findings.add((m.group(0), "ssn"))

    # sk-ant API keys
    for m in matches(SK_ANT_KEY_RE):
        findings.add((m.group(0), "apikey"))

    # AWS secret access keys
    for m in matches(AWS_SECRET_RE):
        findings.add((m.group(1), "secret"))

    # Google OAuth client secrets
    for m in matches(GOCSPX_RE):
        findings.add((m.group(0), "apikey"))

    # Azure client secrets
    for m in matches(AZURE_SECRET_RE):
        val = m.group(1)
        if not re.fullmatch(r'[a-z_]+(?:\.[a-z_]+)*', val):
            findings.add((val, "secret"))

    # URLs with embedded credentials
    for m in matches(URL_AUTH_RE):
        if m.group(1).lower() not in SAFE_USERNAMES:
            findings.add((m.group(1), "username"))
        findings.add((m.group(2), "secret"))

    # GPS coordinates (validate ranges: lat -90..90, lon -180..180)
    for m in matches(GPS_RE):
        try:
            lat, lon = float(m.group(1)), float(m.group(2))
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                findings.add((m.group(0), "gps"))
        except ValueError:
            pass

    # Environment variable secrets
    for m in matches(ENV_SECRET_RE):
        val = m.group(2)
        if not re.fullmatch(r'[a-z_]+(?:\.[a-z_]+)*', val) and not val.startswith("$"):
            findings.add((val, "secret"))

    return findings


def scan_files(file_paths, progress_cb=None):
    findings = set()
    total = len(file_paths) if file_paths else 1
    for i, fpath in enumerate(file_paths):
        if Path(fpath).name.startswith("_"):
            continue
        with open(fpath, errors="replace") as f:
            for chunk in _read_chunks(f):
                findings.update(scan_text(chunk))
        if progress_cb:
            progress_cb(i + 1, total)
    return findings


MAX_SCAN_CHARS = 50_000
_OVERLAP = 500


def _read_chunks(fh, chunk_lines=2000):
    buf = []
    buf_chars = 0
    for line in fh:
        if len(line) > MAX_SCAN_CHARS:
            if buf:
                yield "".join(buf)
                buf, buf_chars = [], 0
            step = MAX_SCAN_CHARS - _OVERLAP
            for start in range(0, len(line), step):
                yield line[start:start + MAX_SCAN_CHARS]
            continue
        buf.append(line)
        buf_chars += len(line)
        if len(buf) >= chunk_lines or buf_chars >= MAX_SCAN_CHARS:
            yield "".join(buf)
            buf, buf_chars = [], 0
    if buf:
        yield "".join(buf)


# ---------------------------------------------------------------------------
# Replacement map
# ---------------------------------------------------------------------------

def _stable_hash(value, category, salt=""):
    return hashlib.sha256(f"{salt}:{category}:{value}".encode()).hexdigest()

_FAKE_FIRST = [
    "alex", "jordan", "casey", "morgan", "taylor", "riley", "drew", "quinn",
    "blake", "avery", "sam", "charlie", "robin", "pat", "lee", "jamie",
    "chris", "dana", "sky", "hayden",
]
_FAKE_LAST = [
    "chen", "santos", "kumar", "fischer", "baker", "park", "silva", "meyer",
    "ross", "cole", "fox", "reed", "bell", "ward", "hunt", "lane", "west",
    "nash", "hale", "voss",
]
_FAKE_HOSTS = [
    "aurora", "nimbus", "cedar", "basalt", "quartz", "marble", "cobalt",
    "obsidian", "granite", "copper", "jasper", "flint", "onyx", "slate",
    "iron", "zinc", "pearl", "amber",
]
_FAKE_DOMAINS = ["devbox.internal", "workstation.lan", "studio.home", "lab.internal"]


def _pick(pool, h):
    return pool[int(h[:8], 16) % len(pool)]


def build_replacement_map(findings, salt=""):
    rmap = {}
    original_values = {value for value, _category in findings}
    used_values = set(original_values)

    def _conflicts(candidate):
        return candidate in used_values or any(value and value in candidate for value in original_values)

    def _unique(pool, h_str, suffix_fn=None, fallback_prefix="person"):
        base = _pick(pool, h_str)
        candidate = base if suffix_fn is None else suffix_fn(base)
        i = 2
        while _conflicts(candidate):
            candidate = f"{base}{i}" if suffix_fn is None else suffix_fn(f"{base}{i}")
            i += 1
            if i > len(pool) + len(original_values) + 10:
                for j in range(1000):
                    base = f"{fallback_prefix}{h_str[:8]}{j or ''}"
                    candidate = base if suffix_fn is None else suffix_fn(base)
                    if not _conflicts(candidate):
                        break
                else:
                    candidate = f"REDACTED_{h_str[:16]}"
                break
        used_values.add(candidate)
        return candidate

    for value, category in sorted(findings, key=lambda x: (-len(x[0]), x[0], x[1])):
        if value in rmap:
            continue
        h = _stable_hash(value, category, salt)

        if category == "email":
            first = _pick(_FAKE_FIRST, h)
            last = _pick(_FAKE_LAST, h[8:])
            email = f"{first}.{last}@example.com"
            i = 2
            while _conflicts(email):
                email = f"{first}.{last}{i}@example.com"
                i += 1
                if i > len(_FAKE_FIRST) + len(_FAKE_LAST) + len(original_values) + 10:
                    for j in range(1000):
                        email = f"person.{h[:8]}{j or ''}@example.com"
                        if not _conflicts(email):
                            break
                    else:
                        email = f"redacted.{h[:16]}@example.com"
                    break
            used_values.add(email)
            rmap[value] = email

        elif category in ("username", "ssh_user", "smb_user", "db_user"):
            rmap[value] = _unique(_FAKE_FIRST, h, fallback_prefix="person")

        elif category == "git_author":
            first = _pick(_FAKE_FIRST, h)
            last = _pick(_FAKE_LAST, h[8:])
            name = f"{first.title()} {last.title()}"
            i = 2
            while _conflicts(name):
                name = f"{first.title()} {last.title()} {i}"
                i += 1
                if i > len(_FAKE_FIRST) + len(_FAKE_LAST) + len(original_values) + 10:
                    for j in range(1000):
                        name = f"Person {h[:8]}{j or ''}"
                        if not _conflicts(name):
                            break
                    else:
                        name = f"Redacted {h[:16]}"
                    break
            used_values.add(name)
            rmap[value] = name

        elif category == "github_user":
            rmap[value] = _unique(_FAKE_FIRST, h, lambda n: f"{n}-dev", fallback_prefix="person")

        elif category == "ip":
            nets = [(192, 0, 2), (198, 51, 100), (203, 0, 113)]
            net = nets[int(h[:2], 16) % len(nets)]
            host = int(h[2:4], 16) % 254 + 1
            ip = f"{net[0]}.{net[1]}.{net[2]}.{host}"
            i = 0
            while ip in used_values:
                host = (host % 254) + 1
                ip = f"{net[0]}.{net[1]}.{net[2]}.{host}"
                i += 1
                if i > 254:
                    break
            used_values.add(ip)
            rmap[value] = ip

        elif category in ("ssh_host", "smb_host", "hostname", "db_host"):
            domain = _pick(_FAKE_DOMAINS, h[8:])
            rmap[value] = _unique(_FAKE_HOSTS, h, lambda n: f"{n}.{domain}", fallback_prefix="host")

        elif category in ("apikey", "secret", "bearer", "jwt", "webhook"):
            rmap[value] = f"REDACTED_{category.upper()}_{h[:16]}"

        elif category == "mac":
            octets = [int(h[i:i+2], 16) for i in range(0, 12, 2)]
            octets[0] = (octets[0] | 0x02) & 0xFE
            mac = ":".join(f"{o:02x}" for o in octets)
            i = 0
            while mac in used_values:
                octets[5] = (octets[5] + 1) % 256
                mac = ":".join(f"{o:02x}" for o in octets)
                i += 1
                if i > 255:
                    break
            used_values.add(mac)
            rmap[value] = mac

        elif category == "wallet":
            rmap[value] = f"0x{h[:40]}"

        elif category == "creds_path":
            rmap[value] = f"/etc/credentials/{_pick(_FAKE_HOSTS, h)}"

        elif category == "phone":
            last4 = int(h[:4], 16) % 100
            rmap[value] = f"+1-555-010-{last4:02d}"

        elif category == "cc_number":
            rmap[value] = "XXXX-XXXX-XXXX-XXXX"

        elif category == "ssn":
            rmap[value] = f"078-05-{int(h[:4], 16) % 9000 + 1000:04d}"

        elif category == "gps":
            flat = (int(h[:4], 16) % 18000 - 9000) / 100.0
            flon = (int(h[4:8], 16) % 36000 - 18000) / 100.0
            rmap[value] = f"{flat:.4f}, {flon:.4f}"

        elif category in ("sshkey", "pgpkey"):
            pass

        else:
            rmap[value] = f"REDACTED_{h[:16]}"

    return rmap


# ---------------------------------------------------------------------------
# JSON-aware replacement
# ---------------------------------------------------------------------------

def _replace_in_str(s, rmap_sorted):
    for old, new in rmap_sorted:
        s = s.replace(old, new)
    for m in HOME_PATH_RE.finditer(s):
        username = next((g for g in m.groups() if g), None)
        if username and username.lower() not in SAFE_USERNAMES and not username.startswith("person"):
            s = s.replace(f"/home/{username}", "/home/person")
            s = s.replace(f"/Users/{username}", "/Users/person")
            s = s.replace(f"C:\\Users\\{username}", "C:\\Users\\person")
            s = s.replace(f"C:/Users/{username}", "C:/Users/person")
    s = re.sub(
        r'-----BEGIN (?:RSA |EC |DSA |ED25519 |OPENSSH )?PRIVATE KEY-----.*?'
        r'-----END (?:RSA |EC |DSA |ED25519 |OPENSSH )?PRIVATE KEY-----',
        'REDACTED_PRIVATE_KEY', s, flags=re.DOTALL,
    )
    s = re.sub(
        r'-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----',
        'REDACTED_PGP_PRIVATE_KEY', s, flags=re.DOTALL,
    )
    return s


def _walk_and_replace(obj, rmap_sorted):
    if isinstance(obj, str):
        return _replace_in_str(obj, rmap_sorted)
    elif isinstance(obj, list):
        return [_walk_and_replace(item, rmap_sorted) for item in obj]
    elif isinstance(obj, dict):
        return {_walk_and_replace(k, rmap_sorted): _walk_and_replace(v, rmap_sorted) for k, v in obj.items()}
    return obj


def sanitize_files(out_dir, rmap, quiet=False, progress_cb=None):
    rmap_sorted = sorted(rmap.items(), key=lambda x: -len(x[0]))
    files = sorted(
        f for f in (
            list(Path(out_dir).glob("*.json"))
            + list(Path(out_dir).glob("*.jsonl"))
            + list(Path(out_dir).glob("*.tmp"))
        )
        if not f.name.startswith("_")
    )
    total = len(files) or 1
    for idx, fpath in enumerate(files):
        changed = False
        if fpath.suffix == ".jsonl":
            tmp = fpath.with_suffix(".tmp")
            with open(fpath, errors="replace") as fin, open(tmp, "w") as fout:
                for line in fin:
                    try:
                        obj = json.loads(line)
                        replaced = _walk_and_replace(obj, rmap_sorted)
                        new_line = json.dumps(replaced, ensure_ascii=False) + "\n"
                        if new_line != line:
                            changed = True
                    except json.JSONDecodeError:
                        new_line = _replace_in_str(line, rmap_sorted)
                        if new_line != line:
                            changed = True
                    fout.write(new_line)
            if changed:
                tmp.replace(fpath)
            else:
                tmp.unlink()
        else:
            file_size = fpath.stat().st_size
            if file_size > 10 * 1024 * 1024:
                tmp = fpath.with_suffix(".tmp")
                with open(fpath, errors="replace") as fin, open(tmp, "w") as fout:
                    for line in fin:
                        new_line = _replace_in_str(line, rmap_sorted)
                        if new_line != line:
                            changed = True
                        fout.write(new_line)
                if changed:
                    tmp.replace(fpath)
                else:
                    tmp.unlink()
            else:
                try:
                    obj = json.loads(fpath.read_text(errors="replace"))
                    replaced = _walk_and_replace(obj, rmap_sorted)
                    new_text = json.dumps(replaced, indent=2, ensure_ascii=False)
                    original_text = json.dumps(obj, indent=2, ensure_ascii=False)
                    if new_text != original_text:
                        changed = True
                        fpath.write_text(new_text)
                except json.JSONDecodeError:
                    original = fpath.read_text(errors="replace")
                    modified = _replace_in_str(original, rmap_sorted)
                    if modified != original:
                        changed = True
                        fpath.write_text(modified)

        if not quiet:
            print(f"  {'sanitized' if changed else 'clean':>9}: {fpath.name}")
        if progress_cb:
            progress_cb(idx + 1, total)


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

_FAKE_NAMES_SET = set(
    _FAKE_FIRST + _FAKE_LAST + _FAKE_HOSTS
    + [f"{f}-dev" for f in _FAKE_FIRST]
    + [f"{f.title()} {ln.title()}" for f in _FAKE_FIRST for ln in _FAKE_LAST]
)
_FAKE_DOMAINS_SET = set(_FAKE_DOMAINS)


_SAFE_EMAILS_LOWER = {e.lower() for e in SAFE_EMAILS}
_SAFE_HOSTNAMES_LOWER = {h.lower() for h in SAFE_HOSTNAMES}


def _is_own_replacement(value, category):
    v = value.lower().strip()
    if v.startswith("redacted"):
        return True
    if v in ("ssh_private_key_block", "pgp_private_key_block", "redacted_private_key", "redacted_pgp_private_key"):
        return True
    if v in {n.lower() for n in _FAKE_NAMES_SET}:
        return True
    if any(v.endswith(d) for d in _FAKE_DOMAINS_SET):
        return True
    if "@example.com" in v:
        return True
    if re.match(r'^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$', v):
        return True
    if category == "mac" and re.match(r'^[a-f0-9]{2}:', v):
        return True
    if v.startswith("0x") and len(v) == 42 and category == "wallet":
        return True
    if v.startswith("/etc/credentials/"):
        return True
    if re.match(r'^\+1-555-01', v):
        return True
    if v == "xxxx-xxxx-xxxx-xxxx":
        return True
    _safe_usernames_lower = {u.lower() for u in SAFE_USERNAMES}
    _fake_names_lower = {n.lower() for n in _FAKE_NAMES_SET}
    # n-prefixed values from \n in JSON strings
    if v.startswith("n") and len(v) > 2:
        stripped = v[1:]
        if (stripped in _SAFE_EMAILS_LOWER or stripped in _SAFE_HOSTNAMES_LOWER
                or stripped in _safe_usernames_lower or stripped in _fake_names_lower):
            return True
    if v in _SAFE_EMAILS_LOWER or v in _SAFE_HOSTNAMES_LOWER:
        return True
    # \\n-prefixed or metadata-style git authors
    if v.startswith("\\n") or v.startswith("\n") or "author-email:" in v:
        return True
    # SSN replacement uses the Woolworth test number prefix
    if category == "ssn" and v.startswith("078-05-"):
        return True
    # GPS replacements
    if category == "gps" and re.match(r'^-?\d+\.\d{4},\s*-?\d+\.\d{4}$', v):
        return True
    return False


def verify(out_dir):
    issues = []
    for fpath in sorted(Path(out_dir).glob("*.json")):
        if fpath.name.startswith("_"):
            continue
        try:
            json.loads(fpath.read_text(errors="replace"))
        except json.JSONDecodeError as e:
            issues.append(f"  BROKEN JSON: {fpath.name}: {e}")

    for fpath in sorted(Path(out_dir).glob("*.jsonl")):
        bad = 0
        with open(fpath, errors="replace") as f:
            for line in f:
                try:
                    json.loads(line)
                except json.JSONDecodeError:
                    bad += 1
        if bad:
            issues.append(f"  BROKEN JSONL: {fpath.name}: {bad} bad lines")

    files = [f for f in (
        list(Path(out_dir).glob("*.json"))
        + list(Path(out_dir).glob("*.jsonl"))
        + list(Path(out_dir).glob("*.tmp"))
    )
             if not f.name.startswith("_")]
    residual = scan_files(files)
    residual = {(v, c) for v, c in residual if not _is_own_replacement(v, c)}

    return issues, residual


# ---------------------------------------------------------------------------
# Archive
# ---------------------------------------------------------------------------

CHUNK_SIZE_MB = 500


def create_archive(out_dir, jsonl_only=False):
    out_dir = Path(out_dir)
    archive_dir = out_dir / "_archives"
    archive_dir.mkdir(exist_ok=True)

    if jsonl_only:
        files = sorted(out_dir.glob("*.jsonl"))
    else:
        files = sorted(f for f in out_dir.iterdir()
                       if f.is_file() and not f.name.startswith("_") and f.suffix in (".json", ".jsonl"))
    if not files:
        return []

    total_size = sum(f.stat().st_size for f in files)
    total_mb = total_size / 1024 / 1024

    archives = []
    if total_mb <= CHUNK_SIZE_MB:
        archive_path = archive_dir / "sessions.7z"
        _run_7z(archive_path, [str(f) for f in files])
        archives.append(archive_path)
    else:
        chunks, current_chunk, current_size = [], [], 0
        for f in files:
            fsize = f.stat().st_size
            if current_size + fsize > CHUNK_SIZE_MB * 1024 * 1024 and current_chunk:
                chunks.append(current_chunk)
                current_chunk, current_size = [], 0
            current_chunk.append(f)
            current_size += fsize
        if current_chunk:
            chunks.append(current_chunk)
        for i, chunk in enumerate(chunks):
            archive_path = archive_dir / f"sessions-{i + 1:03d}.7z"
            _run_7z(archive_path, [str(f) for f in chunk])
            archives.append(archive_path)

    return archives


def _run_7z(archive_path, file_list):
    for cmd in ["7z", "7za"]:
        try:
            subprocess.run([cmd, "a", "-mx=9", str(archive_path)] + file_list,
                           check=True, capture_output=True, text=True)
            return
        except FileNotFoundError:
            continue
    raise FileNotFoundError("7z/7za not found. Install p7zip to create archives.")


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

def run_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
    except ImportError:
        print("error: tkinter not available. Install python3-tk (Linux) or use CLI mode.", file=sys.stderr)
        sys.exit(1)

    root = tk.Tk()
    root.title(f"Code Session Export v{__version__}")
    root.geometry("1100x750")
    root.minsize(800, 500)
    root.configure(bg="#1e1e2e")

    # --- Style ---
    style = ttk.Style()
    style.theme_use("clam")
    bg = "#1e1e2e"
    fg = "#cdd6f4"
    bg2 = "#313244"
    bg3 = "#45475a"
    accent = "#89b4fa"
    yellow = "#f9e2af"
    green = "#a6e3a1"

    style.configure(".", background=bg, foreground=fg, fieldbackground=bg2)
    style.configure("TButton", padding=(12, 6), font=("", 10))
    style.configure("TLabel", background=bg, foreground=fg)
    style.configure("TFrame", background=bg)
    style.configure("Header.TLabel", font=("", 16, "bold"), foreground=accent)
    style.configure("Sub.TLabel", font=("", 9), foreground="#a6adc8")
    style.configure("Cat.TLabel", font=("", 11, "bold"), foreground=yellow)
    style.configure("Status.TLabel", background=bg3, foreground=fg, font=("", 9), padding=4)
    style.configure("Accent.TButton", foreground="#1e1e2e", background=accent)
    style.configure("Treeview", background=bg2, foreground=fg, fieldbackground=bg2, rowheight=22, font=("", 9))
    style.configure("Treeview.Heading", background=bg3, foreground=fg, font=("", 9, "bold"))
    style.map("Treeview", background=[("selected", "#585b70")])
    style.configure("green.Horizontal.TProgressbar", troughcolor=bg2, background=green)

    cancel_event = threading.Event()
    state = {"sessions": [], "findings": set(), "rmap": {}, "out_dir": None, "busy": False}

    def _check_cancel():
        if cancel_event.is_set():
            raise _Cancelled()

    def _run_threaded(fn, *args):
        if state["busy"]:
            return
        state["busy"] = True
        cancel_event.clear()
        _set_buttons_state("disabled")
        cancel_btn.configure(state="normal")

        def wrapper():
            try:
                fn(*args)
            except _Cancelled:
                root.after(0, lambda: status_var.set("Cancelled."))
            except Exception as e:
                msg = str(e)
                root.after(0, lambda: messagebox.showerror("Error", msg))
            finally:
                state["busy"] = False
                root.after(0, lambda: (_set_buttons_state("normal"), cancel_btn.configure(state="disabled")))

        threading.Thread(target=wrapper, daemon=True).start()

    def _status(msg):
        root.after(0, lambda: status_var.set(msg))

    def _set_progress(pct):
        root.after(0, lambda: progress_var.set(pct))

    # === Top bar ===
    top = ttk.Frame(root)
    top.pack(fill="x", padx=12, pady=(12, 4))

    ttk.Label(top, text="Code Session Export", style="Header.TLabel").pack(side="left")
    ttk.Label(top, text=f"v{__version__}", style="Sub.TLabel").pack(side="left", padx=(6, 0), pady=(6, 0))

    controls = ttk.Frame(top)
    controls.pack(side="right")
    model_var = tk.StringVar(value="")
    ttk.Label(controls, text="Model filter:").pack(side="left", padx=(0, 4))
    ttk.Entry(controls, textvariable=model_var, width=10).pack(side="left", padx=(0, 12))
    sanitize_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(controls, text="Sanitize PII", variable=sanitize_var).pack(side="left", padx=(0, 12))
    salt_var = tk.StringVar(value="")
    ttk.Label(controls, text="Salt:").pack(side="left", padx=(0, 4))
    ttk.Entry(controls, textvariable=salt_var, width=12).pack(side="left")

    # === Progress bar ===
    progress_var = tk.DoubleVar(value=0)
    progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100,
                                   style="green.Horizontal.TProgressbar")
    progress_bar.pack(fill="x", padx=12, pady=(0, 4))

    # === Main paned ===
    paned = ttk.PanedWindow(root, orient="horizontal")
    paned.pack(fill="both", expand=True, padx=12, pady=4)

    # -- Left: sessions --
    left = ttk.Frame(paned)
    paned.add(left, weight=1)
    left_header = ttk.Frame(left)
    left_header.pack(fill="x")
    ttk.Label(left_header, text="Sessions", style="Cat.TLabel").pack(side="left")
    session_count_var = tk.StringVar(value="")
    ttk.Label(left_header, textvariable=session_count_var, style="Sub.TLabel").pack(side="right")

    session_frame = ttk.Frame(left)
    session_frame.pack(fill="both", expand=True)
    session_tree = ttk.Treeview(
        session_frame,
        columns=("project", "msgs", "think", "size", "date"),
        show="headings", selectmode="extended",
    )
    session_tree.heading("project", text="Project")
    session_tree.heading("msgs", text="Msgs")
    session_tree.heading("think", text="Blocks")
    session_tree.heading("size", text="Size")
    session_tree.heading("date", text="Date")
    session_tree.column("project", width=140)
    session_tree.column("msgs", width=45, anchor="e")
    session_tree.column("think", width=35, anchor="center")
    session_tree.column("size", width=60, anchor="e")
    session_tree.column("date", width=130)
    sb1 = ttk.Scrollbar(session_frame, orient="vertical", command=session_tree.yview)
    session_tree.configure(yscrollcommand=sb1.set)
    sb1.pack(side="right", fill="y")
    session_tree.pack(fill="both", expand=True)

    sel_frame = ttk.Frame(left)
    sel_frame.pack(fill="x", pady=(4, 0))

    def _select_all():
        session_tree.selection_set(session_tree.get_children())

    def _select_none():
        session_tree.selection_remove(*session_tree.selection())

    def _select_with_thinking():
        ids = [s["session_id"] for s in state["sessions"] if s.get("has_thinking")]
        session_tree.selection_set(ids)

    ttk.Button(sel_frame, text="All", command=_select_all).pack(side="left", padx=(0, 4))
    ttk.Button(sel_frame, text="None", command=_select_none).pack(side="left", padx=(0, 4))
    ttk.Button(sel_frame, text="With Blocks", command=_select_with_thinking).pack(side="left")

    # -- Right: findings --
    right = ttk.Frame(paned)
    paned.add(right, weight=2)
    right_header = ttk.Frame(right)
    right_header.pack(fill="x")
    ttk.Label(right_header, text="PII / Secrets Found", style="Cat.TLabel").pack(side="left")
    findings_count_var = tk.StringVar(value="")
    ttk.Label(right_header, textvariable=findings_count_var, style="Sub.TLabel").pack(side="right")

    findings_frame = ttk.Frame(right)
    findings_frame.pack(fill="both", expand=True)
    findings_tree = ttk.Treeview(findings_frame, columns=("category", "original", "replacement"), show="headings")
    findings_tree.heading("category", text="Category")
    findings_tree.heading("original", text="Original")
    findings_tree.heading("replacement", text="Replaced With")
    findings_tree.column("category", width=90)
    findings_tree.column("original", width=280)
    findings_tree.column("replacement", width=240)
    sb2 = ttk.Scrollbar(findings_frame, orient="vertical", command=findings_tree.yview)
    findings_tree.configure(yscrollcommand=sb2.set)
    sb2.pack(side="right", fill="y")
    findings_tree.pack(fill="both", expand=True)

    # === Status bar ===
    status_var = tk.StringVar(value="Click 'Scan Sessions' to start")
    ttk.Label(root, textvariable=status_var, style="Status.TLabel").pack(fill="x", padx=12, pady=(0, 4))

    # === Bottom buttons ===
    bottom = ttk.Frame(root)
    bottom.pack(fill="x", padx=12, pady=(0, 12))

    def _set_buttons_state(s):
        for btn in all_buttons:
            btn.configure(state=s)

    def _do_scan(model_filter):
        claude_dir = find_claude_dir()
        if not claude_dir.exists():
            root.after(0, lambda: messagebox.showerror("Error",
                f"Session directory not found:\n{claude_dir}\n\nMake sure the source app is installed."))
            return
        _status("Scanning for sessions...")
        _check_cancel()

        sessions = find_sessions(claude_dir, filter_model=model_filter)
        _check_cancel()
        state["sessions"] = sessions

        def update_tree():
            session_tree.delete(*session_tree.get_children())
            for s in sessions:
                size_str = f"{s['size'] / 1024:.0f}K" if s["size"] < 1024 * 1024 else f"{s['size'] / 1024 / 1024:.1f}M"
                ts = s.get("first_timestamp", "")
                if isinstance(ts, str) and len(ts) > 19:
                    ts = ts[:19]
                proj = s.get("project", "")
                if proj.startswith("-"):
                    proj = proj[1:].replace("-", "/")
                think = "Y" if s.get("has_thinking") else ""
                session_tree.insert("", "end", iid=s["session_id"],
                                    values=(proj, s["msg_count"], think, size_str, ts))
            session_tree.selection_set([s["session_id"] for s in sessions])
            total_mb = sum(s["size"] for s in sessions) / 1024 / 1024
            with_cot = sum(1 for s in sessions if s.get("has_thinking"))
            session_count_var.set(f"{len(sessions)} sessions ({with_cot} with blocks), {total_mb:.1f} MB")
            status_var.set(f"Found {len(sessions)} sessions. Select the ones you want, then click 'Analyze PII'.")

        root.after(0, update_tree)

    def _do_analyze(selected, salt):
        _status("Analyzing for PII and secrets...")
        _set_progress(0)

        selected_paths = [s["path"] for s in state["sessions"] if s["session_id"] in selected]

        def progress_cb(c, t):
            _check_cancel()
            _set_progress((c / t) * 100 if t else 0)

        findings = scan_files(selected_paths, progress_cb=progress_cb)
        state["findings"] = findings
        rmap = build_replacement_map(findings, salt=salt)
        state["rmap"] = rmap

        def update_findings():
            findings_tree.delete(*findings_tree.get_children())
            for value, category in sorted(findings, key=lambda x: (x[1], x[0])):
                replacement = rmap.get(value, "—")
                findings_tree.insert("", "end", values=(
                    category,
                    value[:80] + "..." if len(value) > 80 else value,
                    replacement[:60] + "..." if len(replacement) > 60 else replacement,
                ))
            findings_count_var.set(f"{len(findings)} items found")
            progress_var.set(100)
            status_var.set(f"Found {len(findings)} PII items. Review, then click 'Export & Sanitize'.")

        root.after(0, update_findings)

    def _do_export(out_dir_str, selected, salt, do_sanitize):
        out_dir = Path(out_dir_str)
        out_dir.mkdir(parents=True, exist_ok=True)
        state["out_dir"] = out_dir

        _status("Exporting sessions...")
        _set_progress(0)

        selected_sessions = [s for s in state["sessions"] if s["session_id"] in selected]
        n = len(selected_sessions)
        total_steps = n * 3 if do_sanitize else n

        for i, s in enumerate(selected_sessions):
            _check_cancel()
            shutil.copy2(s["path"], out_dir / s["path"].name)
            export_readable(s["path"], out_dir / f"{s['session_id']}.json")
            _status(f"Exporting {i + 1}/{n}...")
            _set_progress((i + 1) / total_steps * 100)

        if do_sanitize:
            _check_cancel()
            _status("Sanitizing PII...")

            def _sanitize_progress(c, t):
                _check_cancel()
                _set_progress((n + c) / total_steps * 100)

            sanitize_files(out_dir, state["rmap"], quiet=True, progress_cb=_sanitize_progress)

            for pass_num in range(3):
                files = [f for f in (
                    list(out_dir.glob("*.json"))
                    + list(out_dir.glob("*.jsonl"))
                    + list(out_dir.glob("*.tmp"))
                )
                         if not f.name.startswith("_")]
                residual = scan_files(files, progress_cb=lambda _c, _t: _check_cancel())
                residual = {(v, c) for v, c in residual if not _is_own_replacement(v, c)}
                if not residual:
                    break
                _status(f"Fixing {len(residual)} residuals (pass {pass_num + 2})...")
                rmap2 = build_replacement_map(residual, salt=salt)
                state["rmap"].update(rmap2)
                sanitize_files(out_dir, rmap2, quiet=True)

            map_path = out_dir / "_replacement_map.json"
            with open(map_path, "w") as f:
                json.dump(state["rmap"], f, indent=2, ensure_ascii=False)

            _status("Verifying...")
            issues, residual = verify(out_dir)
        else:
            issues, residual = [], set()

        _set_progress(100)

        total_mb = sum(f.stat().st_size for f in out_dir.iterdir() if f.is_file()) / 1024 / 1024
        msg = f"Exported {n} sessions to:\n{out_dir}\n\nSize: {total_mb:.1f} MB"
        if not do_sanitize:
            msg += "\n\nRaw export — no PII sanitization applied"
        elif issues:
            msg += f"\n\n{len(issues)} JSON issues found"
        elif residual:
            msg += f"\n\n{len(residual)} potential PII items remain — review manually"
        else:
            msg += "\n\nAll PII sanitized, all JSON valid"

        label = "raw" if not do_sanitize else "sanitized"
        _status(f"Export complete ({label}) — {n} sessions, {total_mb:.1f} MB")
        root.after(0, lambda: messagebox.showinfo("Export Complete", msg))

    def _do_archive(jsonl_only):
        _status("Creating .7z archive(s)...")
        try:
            archives = create_archive(state["out_dir"], jsonl_only=jsonl_only)
            total = sum(a.stat().st_size for a in archives) / 1024 / 1024
            _status(f"Created {len(archives)} archive(s), {total:.1f} MB")
            root.after(0, lambda: messagebox.showinfo("Archive Created",
                f"Created {len(archives)} archive(s)\n\nLocation: {state['out_dir']}/_archives/\nSize: {total:.1f} MB"))
        except FileNotFoundError as e:
            msg = str(e)
            root.after(0, lambda: messagebox.showerror("Error", msg))

    def do_open_folder():
        if not state["out_dir"] or not state["out_dir"].exists():
            messagebox.showwarning("No Output", "Export sessions first.")
            return
        d = str(state["out_dir"])
        if sys.platform == "darwin":
            subprocess.Popen(["open", d])
        elif sys.platform == "win32":
            os.startfile(d)
        else:
            subprocess.Popen(["xdg-open", d])

    def _start_scan():
        _run_threaded(_do_scan, model_var.get().strip() or None)

    def _start_analyze():
        selected = session_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Select at least one session first.")
            return
        _run_threaded(_do_analyze, selected, salt_var.get())

    scan_btn = ttk.Button(bottom, text="1. Scan Sessions", command=_start_scan)
    scan_btn.pack(side="left", padx=(0, 6))
    analyze_btn = ttk.Button(bottom, text="2. Analyze PII", command=_start_analyze)
    analyze_btn.pack(side="left", padx=(0, 6))
    def _start_export():
        selected = session_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Select at least one session first.")
            return
        do_sanitize = sanitize_var.get()
        if do_sanitize and not state["rmap"] and not state["findings"]:
            messagebox.showwarning("Analyze First", "Click 'Analyze PII' before exporting.")
            return
        out_dir_str = filedialog.askdirectory(title="Choose output directory")
        if not out_dir_str:
            return
        _run_threaded(_do_export, out_dir_str, list(selected), salt_var.get(), do_sanitize)

    def _start_archive():
        if not state["out_dir"]:
            messagebox.showwarning("Export First", "Export sessions before creating an archive.")
            return
        jsonl_only = messagebox.askyesno("Archive Format",
            "Archive JSONL files only?\n\nYes = smaller (raw transcripts only)\nNo = both .json and .jsonl")
        _run_threaded(_do_archive, jsonl_only)

    export_btn = ttk.Button(bottom, text="3. Export & Sanitize", command=_start_export)
    export_btn.pack(side="left", padx=(0, 6))
    archive_btn = ttk.Button(bottom, text="4. Create .7z", command=_start_archive)
    archive_btn.pack(side="left", padx=(0, 6))
    cancel_btn = ttk.Button(bottom, text="Cancel", command=lambda: cancel_event.set(), state="disabled")
    cancel_btn.pack(side="right", padx=(0, 6))
    open_btn = ttk.Button(bottom, text="Open Folder", command=do_open_folder)
    open_btn.pack(side="right")

    all_buttons = [scan_btn, analyze_btn, export_btn, archive_btn, open_btn]

    root.mainloop()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) == 1:
        run_gui()
        return

    parser = argparse.ArgumentParser(
        description="Export and sanitize code assistant sessions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s                                         Launch GUI (default)
  %(prog)s -o ~/backup/sessions                    Export all sessions (CLI)
  %(prog)s -o ~/backup/fable --model fable         Export only Fable sessions
  %(prog)s -o ~/backup/sessions --scan-only        Dry run — show PII without modifying
  %(prog)s -o ~/backup/sessions --archive           Also create .7z archive(s)
  %(prog)s -i ~/prev-export -o ~/clean             Re-sanitize existing exports
  %(prog)s -o ~/backup/raw --raw                   Export without sanitization
        """,
    )
    parser.add_argument("--gui", action="store_true", help="Launch GUI mode")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-i", "--input", help="Re-sanitize existing exports in this directory")
    parser.add_argument("--raw", action="store_true", help="Export without PII sanitization")
    parser.add_argument("--model", help="Filter by model (e.g. fable, opus, sonnet)")
    parser.add_argument("--claude-dir", help="Path to session config directory (default: home/.claude on Linux/macOS/Windows)")
    parser.add_argument("--scan-only", action="store_true", help="Scan and report PII without modifying")
    parser.add_argument("--salt", default="", help="Salt for deterministic hash replacements")
    parser.add_argument("--no-readable", action="store_true", help="Skip readable .json exports")
    parser.add_argument("--no-verify", action="store_true", help="Skip verification")
    parser.add_argument("--archive", action="store_true", help="Create .7z archive(s)")
    parser.add_argument("--jsonl-only", action="store_true", help="Archive only .jsonl files")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    if args.scan_only and args.raw:
        parser.error("--raw cannot be used with --scan-only")
    if args.scan_only and args.archive:
        parser.error("--archive cannot be used with --scan-only")
    if args.input and args.claude_dir:
        parser.error("--input cannot be used with --claude-dir")

    if args.gui:
        run_gui()
        return

    if not args.output and not args.input:
        run_gui()
        return

    def cli_scan(file_paths):
        if args.quiet:
            return scan_files(file_paths)
        printed = False
        finished = False

        def progress_cb(done, total):
            nonlocal printed, finished
            printed = True
            print(f"\r  scanning {done}/{total} files...", end="", file=sys.stderr, flush=True)
            if done >= total:
                finished = True
                print(file=sys.stderr, flush=True)

        findings = scan_files(file_paths, progress_cb=progress_cb)
        if printed and not finished:
            print(file=sys.stderr, flush=True)
        return findings

    # --input mode: re-sanitize existing exports
    if args.input:
        in_dir = Path(args.input)
        if not in_dir.exists():
            print(f"error: input directory not found: {in_dir}", file=sys.stderr)
            sys.exit(1)
        out_dir = Path(args.output) if args.output else in_dir
        if args.scan_only:
            out_dir = in_dir
        elif out_dir != in_dir:
            out_dir.mkdir(parents=True, exist_ok=True)
            for f in in_dir.iterdir():
                if f.is_file() and f.suffix in (".json", ".jsonl") and not f.name.startswith("_"):
                    shutil.copy2(f, out_dir / f.name)

        scan_paths = [f for f in out_dir.glob("*.json")] + [f for f in out_dir.glob("*.jsonl")] + [f for f in out_dir.glob("*.tmp")]
        scan_paths = [f for f in scan_paths if not f.name.startswith("_")]
        if not args.quiet:
            print(f"scanning {len(scan_paths)} files in {out_dir}...")
        findings = cli_scan(scan_paths)
        if args.scan_only:
            if not args.quiet:
                by_cat = defaultdict(list)
                for value, cat in sorted(findings, key=lambda x: x[1]):
                    by_cat[cat].append(value)
                for cat, values in sorted(by_cat.items()):
                    print(f"\n  [{cat}] ({len(values)} found)")
                    for v in sorted(values)[:10]:
                        print(f"    {v[:60] + '...' if len(v) > 60 else v}")
                    if len(values) > 10:
                        print(f"    ...and {len(values) - 10} more")
                print(f"\n{len(findings)} total findings.")
            sys.exit(0)

        rmap = build_replacement_map(findings, salt=args.salt)
        sanitize_files(out_dir, rmap, quiet=args.quiet)
        for _ in range(3):
            files = [f for f in (
                list(out_dir.glob("*.json"))
                + list(out_dir.glob("*.jsonl"))
                + list(out_dir.glob("*.tmp"))
            )
                     if not f.name.startswith("_")]
            residual = cli_scan(files)
            residual = {(v, c) for v, c in residual if not _is_own_replacement(v, c)}
            if not residual:
                break
            rmap2 = build_replacement_map(residual, salt=args.salt)
            rmap.update(rmap2)
            sanitize_files(out_dir, rmap2, quiet=args.quiet)

        map_path = out_dir / "_replacement_map.json"
        with open(map_path, "w") as f:
            json.dump(rmap, f, indent=2, ensure_ascii=False)

        if not args.no_verify:
            issues, residual = verify(out_dir)
            if issues:
                for i in issues:
                    print(i)
            if residual:
                print(f"\n  WARNING: {len(residual)} potential PII items remain:")
                for v, c in sorted(residual):
                    print(f"    [{c}] {v[:60]}")
            elif not args.quiet:
                print("  all JSON valid, no residual PII detected")

        if not args.quiet:
            print(f"\ndone: re-sanitized {len(scan_paths)} files in {out_dir}")
        sys.exit(0)

    if not args.output:
        run_gui()
        return

    claude_dir = Path(args.claude_dir) if args.claude_dir else find_claude_dir()
    if not claude_dir.exists():
        print(f"error: session directory not found at {claude_dir}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"scanning {claude_dir}/projects for sessions...")
    sessions = find_sessions(claude_dir, filter_model=args.model)
    if not sessions:
        print("no sessions found.")
        sys.exit(0)

    if args.scan_only:
        if not args.quiet:
            total_mb = sum(s["size"] for s in sessions) / 1024 / 1024
            print(f"found {len(sessions)} sessions ({total_mb:.1f} MB)")
            print("\nscanning for PII and secrets...")
        findings = cli_scan([s["path"] for s in sessions])
        if not args.quiet:
            by_cat = defaultdict(list)
            for value, cat in sorted(findings, key=lambda x: x[1]):
                by_cat[cat].append(value)
            for cat, values in sorted(by_cat.items()):
                print(f"\n  [{cat}] ({len(values)} found)")
                for v in sorted(values)[:10]:
                    print(f"    {v[:60] + '...' if len(v) > 60 else v}")
                if len(values) > 10:
                    print(f"    ...and {len(values) - 10} more")
            print(f"\n{len(findings)} total findings. Run without --scan-only to export and sanitize.")
        sys.exit(0)

    out_dir = Path(args.output)
    same_file_sources = [
        s["path"] for s in sessions
        if (out_dir / s["path"].name).resolve() == s["path"].resolve()
    ]
    if same_file_sources:
        print(f"error: output directory would overwrite source session: {same_file_sources[0]}", file=sys.stderr)
        sys.exit(1)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not args.quiet:
        total_mb = sum(s["size"] for s in sessions) / 1024 / 1024
        print(f"found {len(sessions)} sessions ({total_mb:.1f} MB)")
        print(f"\nexporting to {out_dir}...")

    for s in sessions:
        shutil.copy2(s["path"], out_dir / s["path"].name)
        if not args.no_readable:
            export_readable(s["path"], out_dir / f"{s['session_id']}.json")
        if not args.quiet:
            print(f"  {s['session_id']}: {s['msg_count']} msgs, {s['size'] / 1024:.0f} KB")

    if args.raw:
        if not args.quiet:
            print("\nraw export — no PII sanitization applied")
    else:
        if not args.quiet:
            print("\nscanning for PII and secrets...")
        scan_paths = list(out_dir.glob("*.json")) + list(out_dir.glob("*.jsonl")) + list(out_dir.glob("*.tmp"))
        findings = cli_scan(scan_paths)

        if not args.quiet or args.scan_only:
            by_cat = defaultdict(list)
            for value, cat in sorted(findings, key=lambda x: x[1]):
                by_cat[cat].append(value)
            for cat, values in sorted(by_cat.items()):
                print(f"\n  [{cat}] ({len(values)} found)")
                for v in sorted(values)[:10]:
                    print(f"    {v[:60] + '...' if len(v) > 60 else v}")
                if len(values) > 10:
                    print(f"    ...and {len(values) - 10} more")

        if not args.quiet:
            print(f"\nsanitizing {len(findings)} findings...")
        rmap = build_replacement_map(findings, salt=args.salt)
        sanitize_files(out_dir, rmap, quiet=args.quiet)

        for pass_num in range(2, 5):
            files = [f for f in (
                list(out_dir.glob("*.json"))
                + list(out_dir.glob("*.jsonl"))
                + list(out_dir.glob("*.tmp"))
            )
                     if not f.name.startswith("_")]
            residual = cli_scan(files)
            residual = {(v, c) for v, c in residual if not _is_own_replacement(v, c)}
            if not residual:
                break
            if not args.quiet:
                print(f"\npass {pass_num}: {len(residual)} residuals, fixing...")
            rmap2 = build_replacement_map(residual, salt=args.salt)
            rmap.update(rmap2)
            sanitize_files(out_dir, rmap2, quiet=args.quiet)

        if not args.no_verify:
            if not args.quiet:
                print("\nverifying...")
            issues, residual = verify(out_dir)
            if issues:
                for i in issues:
                    print(i)
            if residual:
                print(f"\n  WARNING: {len(residual)} potential PII items remain:")
                for v, c in sorted(residual):
                    print(f"    [{c}] {v[:60]}")
            elif not args.quiet:
                print("  all JSON valid, no residual PII detected")

        map_path = out_dir / "_replacement_map.json"
        with open(map_path, "w") as f:
            json.dump(rmap, f, indent=2, ensure_ascii=False)
        if not args.quiet:
            print(f"\nreplacement map saved to {map_path.name}")

    if args.archive:
        if not args.quiet:
            print("\ncreating .7z archive(s)...")
        try:
            archives = create_archive(out_dir, jsonl_only=args.jsonl_only)
            if not args.quiet:
                total = sum(a.stat().st_size for a in archives) / 1024 / 1024
                print(f"  created {len(archives)} archive(s), {total:.1f} MB")
        except FileNotFoundError as e:
            print(f"  error: {e}", file=sys.stderr)
            sys.exit(1)

    if not args.quiet:
        total_out = sum(f.stat().st_size for f in out_dir.iterdir() if f.is_file()) / 1024 / 1024
        print(f"\ndone: {len(sessions)} sessions exported to {out_dir} ({total_out:.1f} MB)")


if __name__ == "__main__":
    main()
