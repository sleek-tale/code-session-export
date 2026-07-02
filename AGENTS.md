# AGENTS.md

## Project
`code-session-export` is a single-file, stdlib-only Python tool for exporting local code assistant sessions with optional PII/secret sanitization.

## Commands
```bash
# GUI
python3.12 code_session_export.py

# Sanitized export
python3.12 code_session_export.py -o ~/export/sessions

# Raw export
python3.12 code_session_export.py -o ~/export/raw --raw

# Re-sanitize existing exports
python3.12 code_session_export.py -i ~/prev-export -o ~/clean

# Scan only; writes nothing
python3.12 code_session_export.py -o ~/export --scan-only

# Tests
python3.12 -m unittest discover -s tests -v
```

## Constraints
- Keep it single-file and dependency-free except optional `tkinter` for GUI.
- Default session discovery must stay cross-platform: use `Path.home() / ".claude" / "projects"`, which maps to `~/.claude/projects` on Linux/macOS and `%USERPROFILE%\.claude\projects` on Windows. Keep `--claude-dir` override working.
- Prefer Python 3.12; Python 3.14 can crash on large regex scans.
- Stream large files; do not load full session exports into memory.
- Preserve full JSONL fidelity and structured message exports.
- Sanitization is multi-pass: scan, replace, re-scan residuals, fix up to 3 passes.
- Replacement values must be deterministic and safe: TEST-NET IPs, local MACs, `@example.com` emails.
- GUI work must keep tkinter widget access on the main thread; use `root.after()` from workers.

## Packaging
```bash
pip install pyinstaller
pyinstaller --onefile --name code-session-export code_session_export.py
```

GitHub Actions builds release binaries from `v*` tags.
