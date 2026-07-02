import ast
import importlib.util
import json
import os
import signal
import subprocess
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "code_session_export.py"

spec = importlib.util.spec_from_file_location("code_session_export_under_test", SCRIPT)
cse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cse)


def write_jsonl(path, events):
    with open(path, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


class ScanTextTests(unittest.TestCase):
    def test_major_pii_categories_are_detected(self):
        text = "\n".join([
            "contact sample.user@privacy.test",
            "ssh sampleuser@198.51.100.42",
            "mac aa:bb:cc:dd:ee:ff",
            "open /home/sampleuser/project",
            "win C:/Users/sampleuser/project",
            "token sk-proj-" + "A" * 48,
            "github ghp_" + "B" * 36,
            "aws AKIA" + "C" * 16,
            "aws-temp ASIA" + "D" * 16,
            "jwt eyJ" + "a" * 24 + ".eyJ" + "b" * 24 + "." + "c" * 12,
        ])
        findings = cse.scan_text(text)

        self.assertIn(("sample.user@privacy.test", "email"), findings)
        self.assertIn(("198.51.100.42", "ip"), findings)
        self.assertIn(("aa:bb:cc:dd:ee:ff", "mac"), findings)
        self.assertIn(("sampleuser", "username"), findings)
        self.assertIn(("sk-proj-" + "A" * 48, "apikey"), findings)
        self.assertIn(("ghp_" + "B" * 36, "apikey"), findings)
        self.assertIn(("AKIA" + "C" * 16, "apikey"), findings)
        self.assertIn(("ASIA" + "D" * 16, "apikey"), findings)
        self.assertIn(("eyJ" + "a" * 24 + ".eyJ" + "b" * 24 + "." + "c" * 12, "apikey"), findings)

    def test_expanded_secret_patterns_are_detected_and_redacted(self):
        token_cases = [
            ("github_fine_grained", "github_pat_" + "A" * 22 + "_" + "B" * 59, "apikey"),
            ("gitlab", "glpat-" + "C" * 20, "apikey"),
            ("slack_bot", "xoxb-" + "D" * 12 + "-" + "E" * 12 + "-" + "F" * 24, "apikey"),
            ("slack_refresh", "xoxr-" + "G" * 32, "apikey"),
            ("openrouter", "sk-or-v1-" + "H" * 64, "apikey"),
            ("groq", "gsk_" + "I" * 52, "apikey"),
            ("gemini", "AIza" + "J" * 35, "apikey"),
            ("digitalocean", "dop_v1_" + "a" * 64, "apikey"),
            ("twilio_sid", "AC" + "b" * 32, "apikey"),
            ("mailgun", "key-" + "c" * 32, "apikey"),
            ("openai_project", "sk-proj-" + "K" * 48, "apikey"),
            ("sk_ant", "sk-ant-" + "L" * 48, "apikey"),
            ("databricks", "dapi" + "d" * 32, "apikey"),
            ("supabase", "sbp_" + "M" * 42, "apikey"),
            ("jwt", "eyJ" + "e" * 24 + ".eyJ" + "f" * 24 + "." + "g" * 24, "apikey"),
        ]
        assignment_cases = [
            ("mistral", "MISTRAL_API_KEY=" + "N" * 40, "N" * 40, "apikey"),
            ("vercel", "VERCEL_TOKEN=" + "O" * 32, "O" * 32, "apikey"),
            ("netlify", "NETLIFY_AUTH_TOKEN=" + "P" * 32, "P" * 32, "apikey"),
            ("cloudflare", "CLOUDFLARE_API_TOKEN=" + "Q" * 40, "Q" * 40, "apikey"),
            ("twilio_auth", "TWILIO_AUTH_TOKEN=" + "1" * 32, "1" * 32, "apikey"),
            ("mailgun_signing", "MAILGUN_SIGNING_KEY=" + "2" * 32, "2" * 32, "apikey"),
        ]

        text = "\n".join([f"{name}: {value}" for name, value, _cat in token_cases]
                         + [f"{name}: {line}" for name, line, _value, _cat in assignment_cases])
        findings = cse.scan_text(text)
        rmap = cse.build_replacement_map(findings, salt="fixed-salt")
        sanitized = cse._replace_in_str(text, sorted(rmap.items(), key=lambda x: -len(x[0])))

        for _name, value, category in token_cases:
            self.assertIn((value, category), findings)
            self.assertIn(value, rmap)
            self.assertTrue(rmap[value].startswith(f"REDACTED_{category.upper()}_"))
            self.assertNotIn(value, sanitized)
        for _name, _line, value, category in assignment_cases:
            self.assertIn((value, category), findings)
            self.assertIn(value, rmap)
            self.assertTrue(rmap[value].startswith(f"REDACTED_{category.upper()}_"))
            self.assertNotIn(value, sanitized)

    def test_benign_code_corpus_has_no_findings(self):
        text = "\n".join([
            'VERSION = "1.2.3.4"',
            'SEMVER = "2.10.3"',
            'UUID = "123e4567-e89b-12d3-a456-426614174000"',
            'GIT_SHA = "0123456789abcdef0123456789abcdef01234567"',
            'COLOR = "#aabbcc"',
            'LOCALHOST = "127.0.0.1"',
            'PRIVATE_A = "10.12.13.14"',
            'PRIVATE_B = "172.20.30.40"',
            'PRIVATE_C = "192.168.50.60"',
            'BLOB = "VGhpcyBpcyBhIGJlbmlnbiBiYXNlNjQgYmxvYiBmb3IgdGVzdHMu"',
            'HASH = "e3b0c44298fc1c149afbf4c8996fb924"',
            'LOREM = "lorem ipsum dolor sit amet consectetur adipiscing elit"',
        ])
        self.assertEqual(cse.scan_text(text), set())

    def test_deterministic_replacement_and_idempotency(self):
        text = json.dumps({
            "email": "sample.user@privacy.test",
            "path": "/home/sampleuser/project",
            "token": "ghp_" + "E" * 36,
        })
        findings = cse.scan_text(text)
        first = cse.build_replacement_map(findings, salt="fixed-salt")
        second = cse.build_replacement_map(findings, salt="fixed-salt")
        self.assertEqual(first, second)

        sorted_map = sorted(first.items(), key=lambda x: -len(x[0]))
        sanitized = cse._replace_in_str(text, sorted_map)
        self.assertEqual(sanitized, cse._replace_in_str(sanitized, sorted_map))

    def test_duplicate_value_category_tie_is_deterministic(self):
        findings = {("sharedvalue", "username"), ("sharedvalue", "ssh_user")}
        maps = {tuple(cse.build_replacement_map(findings, salt="fixed").items()) for _ in range(20)}
        self.assertEqual(len(maps), 1)

    def test_replacements_do_not_cascade_into_original_values(self):
        findings = {("zzuser100", "username"), ("quinn", "username")}
        rmap = cse.build_replacement_map(findings)
        originals = {value for value, _category in findings}
        self.assertTrue(all(original not in replacement for replacement in rmap.values() for original in originals))

        sorted_map = sorted(rmap.items(), key=lambda x: -len(x[0]))
        text = "users: zzuser100 and quinn"
        sanitized = cse._replace_in_str(text, sorted_map)
        self.assertEqual(sanitized, cse._replace_in_str(sanitized, sorted_map))

    @unittest.skipUnless(hasattr(signal, "SIGALRM"), "requires SIGALRM")
    def test_unfiltered_scan_handles_long_nonmatching_text_quickly(self):
        class Timeout(Exception):
            pass

        def handler(_signum, _frame):
            raise Timeout()

        old_handler = signal.signal(signal.SIGALRM, handler)
        old_env = os.environ.get(cse.DISABLE_SCAN_PREFILTER_ENV)
        try:
            os.environ[cse.DISABLE_SCAN_PREFILTER_ENV] = "1"
            signal.setitimer(signal.ITIMER_REAL, 1.0)
            self.assertEqual(cse.scan_text("A" * 100_000), set())
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)
            if old_env is None:
                os.environ.pop(cse.DISABLE_SCAN_PREFILTER_ENV, None)
            else:
                os.environ[cse.DISABLE_SCAN_PREFILTER_ENV] = old_env

    def test_chunked_scan_finds_token_across_50kb_boundary(self):
        token = "ghp_" + "F" * 36
        text = "x" * (cse.MAX_SCAN_CHARS - 10) + token + " " + "y" * 1000
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "session.jsonl"
            path.write_text(text, encoding="utf-8")
            findings = cse.scan_files([path])
        self.assertIn((token, "apikey"), findings)

    def test_scan_prefilter_matches_unfiltered_scan_on_large_corpus(self):
        examples = [
            "email sample.user@privacy.test",
            "gcp svc-account@sample-project.iam.gserviceaccount.com",
            "paths /home/sampleuser/project /Users/desktopuser/work C:/Users/winuser/repo C:\\Users\\shelluser\\repo",
            "ip 203.0.113.42 tailscale 100.64.12.34 mac aa:bb:cc:dd:ee:ff host buildbox.local",
            "smb smb://smbuser@smbhost/share/path //files.example.net/share username=mountuser credentials=/etc/cifs/secret",
            "ssh ssh shelluser@remote.example.net bareuser@198.51.100.23",
            "HostName hostconfig.example.net\nUser sshconfiguser",
            "known.example.net ssh-ed25519 " + "A" * 40,
            "[promptuser@prompthost ~]$ sudo ls\n[sudo] password for sudouser:",
            "passwduser:x:1001:1001:Sample User:/home/passwduser:/bin/bash",
            "db postgres://dbuser:dbsecretvalue123@dbhost.example.net:5432/app",
            "netrc machine netrc.example.net login netrcuser password netrcsecretvalue",
            "Author: Sample Author <author@privacy.test>\nurl = git@github.com:gitowner/repo.git\nname = Config Author\nemail = config@privacy.test",
            "hf hf_" + "A" * 24,
            "sk sk-" + "B" * 24,
            "aws AKIA" + "C" * 16 + " ASIA" + "D" * 16,
            "gh ghp_" + "E" * 36 + " github_pat_" + "F" * 22 + "_" + "G" * 24,
            "gitlab glpat-" + "H" * 24,
            "npm npm_" + "I" * 36 + "\n_authToken = " + "J" * 24,
            "pypi pypi-" + "K" * 36,
            "stripe sk_live_" + "L" * 24,
            "sendgrid SG." + "M" * 24 + "." + "N" * 24,
            "slack xoxb-" + "O" * 16,
            "google AIza" + "P" * 35,
            "twilio AC" + "a" * 32 + "\nTWILIO_AUTH_TOKEN=" + "b" * 32,
            "do dop_v1_" + "c" * 64,
            "mailgun key-" + "d" * 32 + "\nMAILGUN_SIGNING_KEY=" + "e" * 32,
            "vault hvs." + "Q" * 24,
            "telegram 123456789:" + "R" * 35,
            "sentry https://" + "f" * 32 + "@o123.ingest.sentry.io/456",
            "openrouter sk-or-v1-" + "S" * 40,
            "groq gsk_" + "T" * 40,
            "MISTRAL_API_KEY=" + "U" * 40,
            "VERCEL_TOKEN=" + "V" * 24,
            "NETLIFY_AUTH_TOKEN=" + "W" * 24,
            "CLOUDFLARE_API_TOKEN=" + "X" * 32,
            "databricks dapi" + "a" * 32,
            "supabase sbp_" + "Y" * 32,
            "bearer Bearer " + "Z" * 24,
            "jwt eyJ" + "a" * 24 + ".eyJ" + "b" * 24 + "." + "c" * 24,
            "generic api_key=" + "d" * 24,
            "oauth access_token=" + "e" * 32,
            "cookie Cookie: session_id=" + "f" * 24,
            'docker {"auth": "' + "QUJDREVGR0hJSktMTU5PUFFSU1Q=" + '"}',
            "wallet 0x" + "a" * 40,
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "PrivateKey = " + "A" * 43 + "=",
            "age AGE-SECRET-KEY-1" + "A" * 58,
            "discord https://discord.com/api/webhooks/123456/" + "abc_DEF-123",
            "slackhook https://hooks.slack.com/services/T00000000/B00000000/" + "C" * 24,
            "phone 212-555-0199 intl +44 20 7946 0958",
            "cc 4111-1111-1111-1111",
            "ssn 123-45-6789",
            "sk-ant " + "sk-ant-" + "G" * 32,
            "aws_secret_access_key=" + "H" * 40,
            "gocspx GOCSPX-" + "I" * 24,
            "client_secret=" + "J" * 36,
            "url https://urluser:urlsecret@example.net/path",
            "gps 37.7749, -122.4194",
            "ENV_TOKEN=" + "K" * 24,
        ]
        filler = "\n".join([
            '{"type":"assistant","message":{"content":"function example() { return 42; }"}}',
            "def benign(value):\n    return {'ok': True, 'value': value}",
            "This prose describes a synthetic session export with no private data.",
            "const config = { retries: 3, endpoint: '/v1/messages', enabled: true };",
        ] * 1500)
        corpus = filler + "\n" + "\n".join(examples) + "\n" + filler

        old_env = os.environ.get(cse.DISABLE_SCAN_PREFILTER_ENV)
        try:
            os.environ.pop(cse.DISABLE_SCAN_PREFILTER_ENV, None)
            filtered = sorted(cse.scan_text(corpus))
            os.environ[cse.DISABLE_SCAN_PREFILTER_ENV] = "1"
            unfiltered = sorted(cse.scan_text(corpus))
        finally:
            if old_env is None:
                os.environ.pop(cse.DISABLE_SCAN_PREFILTER_ENV, None)
            else:
                os.environ[cse.DISABLE_SCAN_PREFILTER_ENV] = old_env

        self.assertEqual(filtered, unfiltered)
        self.assertGreaterEqual(len(filtered), 70)


class FileOperationTests(unittest.TestCase):
    def test_sanitize_jsonl_streams_to_valid_json_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            path = out_dir / "session.jsonl"
            write_jsonl(path, [
                {"type": "user", "message": {"content": "email sample.user@privacy.test"}},
                {"type": "assistant", "message": {"content": "token ghp_" + "G" * 36}},
            ])
            findings = cse.scan_files([path])
            rmap = cse.build_replacement_map(findings, salt="fixed-salt")

            cse.sanitize_files(out_dir, rmap, quiet=True)
            once = path.read_text(encoding="utf-8")
            self.assertFalse((out_dir / "session.tmp").exists())
            for line in once.splitlines():
                json.loads(line)

            cse.sanitize_files(out_dir, rmap, quiet=True)
            self.assertEqual(once, path.read_text(encoding="utf-8"))

    def test_leftover_tmp_files_are_sanitized_and_verified(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            tmp = out_dir / "session.jsonl.tmp"
            tmp.write_text("email sample.user@privacy.test\n", encoding="utf-8")

            issues, residual = cse.verify(out_dir)
            self.assertEqual(issues, [])
            self.assertIn(("sample.user@privacy.test", "email"), residual)

            rmap = cse.build_replacement_map(cse.scan_files([tmp]), salt="fixed-salt")
            cse.sanitize_files(out_dir, rmap, quiet=True)

            self.assertNotIn("sample.user@privacy.test", tmp.read_text(encoding="utf-8"))
            self.assertEqual(cse.verify(out_dir), ([], set()))

    def test_verify_handles_non_utf8_jsonl_like_scan(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            path = out_dir / "session.jsonl"
            path.write_bytes(b'{"type":"user","message":{"content":"sample.user@privacy.test \xff"}}\n')

            issues, residual = cse.verify(out_dir)

        self.assertEqual(issues, [])
        self.assertIn(("sample.user@privacy.test", "email"), residual)

    def test_export_readable_writes_valid_json(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "sample-session.jsonl"
            dst = Path(td) / "sample-session.json"
            write_jsonl(src, [
                {
                    "type": "assistant",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "model": "code-test",
                    "message": {"content": [{"type": "thinking", "thinking": "reasoning"}]},
                },
                {"type": "user", "message": {"content": "hello"}},
            ])
            cse.export_readable(src, dst)
            data = json.loads(dst.read_text(encoding="utf-8"))
        self.assertEqual(data["session_id"], "sample-session")
        self.assertEqual(data["message_count"], 2)
        self.assertEqual(data["messages"][0]["content"][0]["type"], "thinking")


class DiscoveryTests(unittest.TestCase):
    def test_find_sessions_uses_fake_claude_tree_only(self):
        with tempfile.TemporaryDirectory() as td:
            claude = Path(td) / ".claude"
            project = claude / "projects" / "-tmp-sample"
            project.mkdir(parents=True)
            write_jsonl(project / "abc123.jsonl", [
                {"type": "user", "timestamp": "2026-01-01T00:00:00Z", "message": {"content": "hi"}},
                {
                    "type": "assistant",
                    "model": "code-fable-test",
                    "message": {"content": [{"type": "thinking", "thinking": "reasoning"}]},
                },
            ])
            write_jsonl(project / "history.jsonl", [{"type": "user"}])

            sessions = cse.find_sessions(claude, filter_model="fable")

        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["session_id"], "abc123")
        self.assertEqual(sessions[0]["msg_count"], 2)
        self.assertTrue(sessions[0]["has_thinking"])

    def test_find_sessions_model_filter_does_not_silently_skip_unreadable_files(self):
        with tempfile.TemporaryDirectory() as td:
            claude = Path(td) / ".claude"
            project = claude / "projects" / "-tmp-sample"
            project.mkdir(parents=True)
            write_jsonl(project / "ok.jsonl", [
                {"type": "user", "timestamp": "2026-01-01T00:00:00Z", "message": {"content": "code-fable-test"}},
            ])
            denied = project / "denied.jsonl"
            write_jsonl(denied, [
                {"type": "user", "timestamp": "2026-01-01T00:00:00Z", "message": {"content": "code-fable-test"}},
            ])
            denied.chmod(0)
            try:
                sessions = cse.find_sessions(claude, filter_model="fable")
            finally:
                denied.chmod(stat.S_IRUSR | stat.S_IWUSR)

        self.assertEqual({s["session_id"] for s in sessions}, {"ok", "denied"})


class CliTests(unittest.TestCase):
    def run_cli(self, *args, env=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_help_and_version(self):
        help_result = self.run_cli("--help")
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("--scan-only", help_result.stdout)

        version_result = self.run_cli("--version")
        self.assertEqual(version_result.returncode, 0)
        self.assertIn(cse.__version__, version_result.stdout)

    def test_scan_only_against_fixture_dir_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            claude = root / ".claude"
            project = claude / "projects" / "-tmp-sample"
            project.mkdir(parents=True)
            write_jsonl(project / "abc123.jsonl", [
                {"type": "user", "message": {"content": "sample.user@privacy.test"}},
            ])
            out_dir = root / "out"

            result = self.run_cli("-o", str(out_dir), "--claude-dir", str(claude), "--scan-only")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 total findings", result.stdout)
        self.assertFalse(out_dir.exists())

    def test_input_scan_only_does_not_copy_to_output(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "input"
            src.mkdir()
            write_jsonl(src / "abc123.jsonl", [
                {"type": "user", "message": {"content": "sample.user@privacy.test"}},
            ])
            out_dir = root / "out"

            result = self.run_cli("-i", str(src), "-o", str(out_dir), "--scan-only")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 total findings", result.stdout)
        self.assertFalse(out_dir.exists())

    def test_conflicting_cli_flags_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            claude = root / ".claude"
            project = claude / "projects" / "-tmp-sample"
            project.mkdir(parents=True)
            write_jsonl(project / "abc123.jsonl", [
                {"type": "user", "message": {"content": "sample.user@privacy.test"}},
            ])
            src = root / "input"
            src.mkdir()

            cases = [
                ("--raw", "--scan-only", "-o", str(root / "out"), "--claude-dir", str(claude)),
                ("--archive", "--scan-only", "-o", str(root / "out"), "--claude-dir", str(claude)),
                ("-i", str(src), "-o", str(root / "out"), "--claude-dir", str(claude)),
            ]
            for args in cases:
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("error:", result.stderr)

    def test_quiet_scan_only_suppresses_output(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            claude = root / ".claude"
            project = claude / "projects" / "-tmp-sample"
            project.mkdir(parents=True)
            write_jsonl(project / "abc123.jsonl", [
                {"type": "user", "message": {"content": "sample.user@privacy.test"}},
            ])

            result = self.run_cli("-o", str(root / "out"), "--claude-dir", str(claude), "--scan-only", "-q")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_output_dir_cannot_be_source_project_dir(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            claude = root / ".claude"
            project = claude / "projects" / "-tmp-sample"
            project.mkdir(parents=True)
            write_jsonl(project / "abc123.jsonl", [
                {"type": "user", "message": {"content": "sample.user@privacy.test"}},
            ])

            result = self.run_cli("-o", str(project), "--claude-dir", str(claude), "-q")

        self.assertEqual(result.returncode, 1)
        self.assertIn("would overwrite source session", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_archive_failure_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            claude = root / ".claude"
            project = claude / "projects" / "-tmp-sample"
            project.mkdir(parents=True)
            write_jsonl(project / "abc123.jsonl", [
                {"type": "user", "message": {"content": "hello"}},
            ])
            env = os.environ.copy()
            env["PATH"] = "/nonexistent"

            result = self.run_cli("-o", str(root / "out"), "--claude-dir", str(claude), "--archive", "-q", env=env)

        self.assertEqual(result.returncode, 1)
        self.assertIn("7z/7za not found", result.stderr)

    def test_subprocess_export_sanitizes_json_and_is_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            claude = root / ".claude"
            project = claude / "projects" / "-tmp-sample"
            project.mkdir(parents=True)
            out_dir = root / "out"
            session = project / "abc123.jsonl"
            pii_values = [
                "sample.user@privacy.test",
                "203.0.113.42",
                "aa:bb:cc:dd:ee:ff",
                "sampleuser",
                "ghp_" + "R" * 36,
                "github_pat_" + "S" * 22 + "_" + "T" * 59,
                "glpat-" + "U" * 20,
                "xoxr-" + "V" * 32,
                "sk-ant-" + "W" * 48,
                "eyJ" + "h" * 24 + ".eyJ" + "i" * 24 + "." + "j" * 24,
            ]
            write_jsonl(session, [
                {
                    "type": "user",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "message": {"content": "email sample.user@privacy.test ip 203.0.113.42 mac aa:bb:cc:dd:ee:ff path /home/sampleuser/project"},
                },
                {
                    "type": "assistant",
                    "model": "code-test",
                    "message": {"content": [{"type": "text", "text": "tokens ghp_" + "R" * 36 + " github_pat_" + "S" * 22 + "_" + "T" * 59 + " glpat-" + "U" * 20 + " xoxr-" + "V" * 32 + " sk-ant-" + "W" * 48 + " eyJ" + "h" * 24 + ".eyJ" + "i" * 24 + "." + "j" * 24}]},
                },
            ])
            env = os.environ.copy()
            env["HOME"] = str(root)

            cmd = ["python3.12", str(SCRIPT), "-o", str(out_dir), "--claude-dir", str(claude), "--salt", "fixed-salt"]
            first = subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            first_bytes = {
                "jsonl": (out_dir / "abc123.jsonl").read_bytes(),
                "json": (out_dir / "abc123.json").read_bytes(),
                "map": (out_dir / "_replacement_map.json").read_bytes(),
            }
            second = subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(first_bytes["jsonl"], (out_dir / "abc123.jsonl").read_bytes())
            self.assertEqual(first_bytes["json"], (out_dir / "abc123.json").read_bytes())
            self.assertEqual(first_bytes["map"], (out_dir / "_replacement_map.json").read_bytes())

            json.loads((out_dir / "abc123.json").read_text(encoding="utf-8"))
            for line in (out_dir / "abc123.jsonl").read_text(encoding="utf-8").splitlines():
                json.loads(line)
            exported = (out_dir / "abc123.jsonl").read_text(encoding="utf-8") + (out_dir / "abc123.json").read_text(encoding="utf-8")
            for value in pii_values:
                self.assertNotIn(value, exported)
            rmap = json.loads((out_dir / "_replacement_map.json").read_text(encoding="utf-8"))
            for value in pii_values:
                self.assertIn(value, rmap)
                self.assertNotEqual(value, rmap[value])


class DependencyTests(unittest.TestCase):
    def test_runtime_imports_are_stdlib_only(self):
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertLessEqual(imported, {
            "argparse", "hashlib", "json", "os", "re", "shutil", "subprocess",
            "sys", "threading", "collections", "pathlib", "tkinter",
        })


if __name__ == "__main__":
    unittest.main()
