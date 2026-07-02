# code-session-export

Export your local code assistant sessions for backup or review. Optionally strip PII, secrets, API keys, paths, and other identifying information before sharing or archiving.

Works on **Linux, macOS, and Windows**. Zero dependencies (stdlib only). Single file.

## Install

**Standalone binary** (no Python needed):

Download from [Releases](../../releases) — one binary per platform, double-click to launch the GUI. On Windows, the plain `.exe` is built as a `--windowed` GUI app; use `windows-console.exe` for CLI/stdout output.

**From source** (Python 3.9+, 3.12 recommended):

```bash
# Run directly
python code_session_export.py

# Or install as a CLI tool
pip install .
code-session-export
```

> Python 3.14 has a regex bug that crashes on large files. The tool auto-detects this and re-execs with 3.12/3.13 if available. If you only have 3.14, install 3.12 alongside it.

## Quick start

**GUI** — launch with no args or double-click the binary:

```bash
code-session-export
```

1. Click **Scan Sessions** — finds all sessions in the default session directory: `~/.claude/projects/` on Linux/macOS, `%USERPROFILE%\.claude\projects\` on Windows
2. Select which sessions to export
3. Click **Analyze PII** — scans for secrets and identifying information
4. Click **Export & Sanitize** — copies, sanitizes, and verifies

To export **without sanitization**, uncheck **Sanitize PII** in the top bar. Steps 2-3 are skipped — sessions are exported as-is with full unredacted content.

**CLI** — pass `-o` for an output directory:

```bash
# Export all sessions with PII sanitization
code-session-export -o ~/backup/sessions

# Export raw (no sanitization)
code-session-export -o ~/backup/raw --raw

# Export only Fable sessions
code-session-export -o ~/backup/fable --model fable

# Dry run — show what PII would be found
code-session-export -o ~/backup/sessions --scan-only

# Re-sanitize existing exports (no default session directory needed)
code-session-export -i ~/prev-export -o ~/clean

# Export + compress
code-session-export -o ~/backup/sessions --archive
```

## GUI features

Dark Catppuccin theme, split-pane layout:

| Left pane (sessions)                          | Right pane (findings)                 |
| --------------------------------------------- | ------------------------------------- |
| Project name, message count, size, date       | Category, original value, replacement |

- **Sanitize PII** checkbox — toggle sanitization on/off
- **Model filter** — show only sessions matching a model name
- **Salt** — custom salt for deterministic replacement hashes
- **Selection buttons** — All / None / With Blocks
- **Cancel** — stop any running operation mid-progress
- **Open Folder** — jump to the export directory

## Output

For each session:

- **`{session-id}.jsonl`** — raw code assistant transcript (full fidelity)
- **`{session-id}.json`** — structured conversation export

When sanitized, also:

- **`_replacement_map.json`** — all substitutions made (keep private to reverse them)

Optional:

- **`_archives/*.7z`** — compressed archives, split at 500MB if large (requires `p7zip`)

## What it catches

79 regex patterns across these categories:

| Category            | Examples                                                                                             |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| **Home paths**      | `/home/user`, `/Users/user`, `C:\Users\user` (including accented usernames)                          |
| **Emails**          | `user@domain.com`, GCP service account emails                                                        |
| **API keys/tokens** | common provider tokens, cloud keys, package tokens, webhooks, and other service credentials |
| **Generic secrets** | `api_key=`, `*_SECRET=`, `*_TOKEN=` env vars, OAuth, cookies, Docker auth, .netrc                    |
| **Bearer/JWT**      | `Authorization: Bearer ...`, `eyJ...` tokens                                                         |
| **URL credentials** | `https://user:pass@host/`                                                                            |
| **Database**        | `postgres://`, `mysql://`, `mongodb://`, `redis://` connection strings                               |
| **SSH/SMB**         | `ssh user@host`, UNC paths, CIFS credentials, known_hosts, SSH config                                |
| **Shell prompts**   | `user@hostname $`, sudo prompts, /etc/passwd                                                         |
| **Network**         | Public IPs, Tailscale IPs, MAC addresses, `*.local` hostnames                                        |
| **GPS coordinates** | Decimal lat/lon pairs (range-validated, 4+ decimal places)                                           |
| **Crypto**          | Ethereum wallets, WireGuard keys, age secret keys                                                    |
| **Private keys**    | SSH/PGP key blocks replaced entirely                                                                 |
| **Git identity**    | Author name/email, remote usernames, .gitconfig                                                      |
| **Phone numbers**   | US (3-3-4 with separators) + international (20+ country codes)                                       |
| **Credit cards**    | Visa, MC, Amex (Luhn validated, requires separators)                                                 |
| **SSN**             | US Social Security Numbers (excludes known-invalid ranges)                                           |
| **Webhooks**        | Discord, Slack webhook URLs                                                                          |
| **Messaging**       | Telegram bot tokens                                                                                  |

Replacements are **deterministic** — same input always maps to same fake output. Uses RFC 5737 TEST-NET IPs, locally-administered MACs, `@example.com` emails, and realistic fake names. An optional `--salt` makes hashes unique to you.

## CLI reference

```
code-session-export [options]

Options:
  -o, --output DIR       Output directory
  -i, --input DIR        Re-sanitize existing exports in this directory
  --raw                  Export without PII sanitization
  --model FILTER         Filter sessions by model name
  --claude-dir DIR       Custom session config directory (default: ~/.claude on Linux/macOS, %USERPROFILE%\.claude on Windows)
  --scan-only            Show PII findings without modifying files
  --salt TEXT            Salt for deterministic replacement hashes
  --no-readable          Skip .json exports (keep only raw .jsonl)
  --no-verify            Skip post-sanitization verification
  --archive              Create .7z archive(s) after export
  --jsonl-only           Archive only .jsonl files (smaller)
  --gui                  Force GUI mode
  -q, --quiet            Suppress output
```

## Packaging

Zero dependencies — stdlib Python only (tkinter for GUI). Build standalone binaries with PyInstaller:

```bash
pip install pyinstaller
pyinstaller --onefile --name code-session-export code_session_export.py
```

The GitHub Actions workflow builds Linux/macOS/Windows binaries automatically on version tags.

## Testing

```bash
python3.12 -m unittest discover -s tests
```

## Limitations

- Pattern-based — won't catch names in prose (needs NER), base64-encoded secrets, or PII in non-Latin scripts beyond Latin-1
- Some unlabeled version numbers that look like public IPs may get replaced
- Review `_replacement_map.json` and spot-check output before publishing
- Archive creation requires `p7zip` (`sudo apt install p7zip-full` / `brew install p7zip`)
