# Handoff — mcp-hayabusa

_Last updated: 2026-07-15_

## What this is

MCP server that wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa) EVTX
analysis CLI, exposing it as tools callable from MCP clients (Claude Code, Claude Desktop).
See `CLAUDE.md` for the full architecture — it's up to date as of commit `cf7ceff`.

## Current state

Two MCP tools are implemented and manually tested against a real sample EVTX:

- **`scan_evtx(path, min_severity=None, rule_filter=None, output_format="summary", max_results=None)`**
  Runs `hayabusa json-timeline` against a file/directory, returns structured JSON findings.
- **`get_hayabusa_rules(keyword=None, min_severity=None, max_results=None)`**
  Parses the ~4,958 rule YAMLs under `hayabusa/rules/` (Hayabusa + Sigma rule sets) and
  returns id/title/level/description/tags/etc., filterable by keyword/severity. Parsed rules
  are cached in-memory (`_rules_cache` module global) after first call.

Both live in **`server_lowlevel.py`** — this is the file actually wired up:
`.mcp.json` launches it (`python3 server_lowlevel.py`), and `test_scan_evtx.py` imports it
directly for manual testing.

**`server.py`** is a second, *unused* FastMCP-based skeleton. Both of its tools
(`scan_evtx`, `get_hayabusa_rules`) are stubs that `raise NotImplementedError` — kept only
for signature parity in case someone revives the FastMCP approach later. Pyright will flag
unused params in these stubs; that's expected and not a bug. **Decision (2026-07-15):
leaving it as-is for now** — don't finish or delete it without asking.

The project is under git (this was the top gap in the previous handoff — now resolved).
`.gitignore` excludes `hayabusa/` (73MB binary + rules clone, reproducible via
`scripts/download_hayabusa.py`), `samples/`, `logs/`, and `__pycache__/`.

## How to test

```
python3 test_scan_evtx.py
```

Downloads a sample EVTX (Mimikatz/Sysmon) into `samples/` on first run if not already
present, then exercises both tools end-to-end: normal scan, severity filter, rule filter,
missing-file error, invalid-arg errors, `output_format` summary/full, `max_results`,
keyword search over rules, `min_severity` over rules. All checks passing as of last run.

There is no pytest/unittest harness — this is a single manual script with hand-rolled
assertions and `sys.exit(1)` on failure.

## Known gaps / things to flag

- **Branch is `master`, not `main`.** If this ever gets a remote/PR workflow, consider
  `git branch -m master main` first.
- **Hayabusa binary/rules are unpinned.** `scripts/download_hayabusa.py` fetches
  "latest" — installed version at last check was `hayabusa-3.10.0-lin-x64-musl`. No
  lockfile ties a known-good rule/binary version to this codebase.
- **`requirements.txt`** lists `mcp[cli]>=1.2.0` and `pyyaml>=6.0`. Not yet verified
  against a clean venv install — the packages were already present in the environment
  when tested.
- **`_load_all_rules()` caches forever** — if `hayabusa update-rules` is run against a
  live server process, `get_hayabusa_rules` will keep serving stale cached rules until
  restart. Fine for now, worth knowing.
- **`hayabusa/rules/` is itself a git checkout** (has its own `.git/`). It's inside the
  gitignored `hayabusa/` directory, so it never touches this repo's history — just don't
  try to vendor it.

## Suggested next steps

1. If you want CI-style confidence beyond the manual script, convert
   `test_scan_evtx.py` into real `pytest` cases.
2. Consider pinning the Hayabusa release (and rules commit) that
   `scripts/download_hayabusa.py` installs, so scans are reproducible.
3. Verify `requirements.txt` in a clean venv.
