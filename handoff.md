# Handoff — mcp-hayabusa

_Last updated: 2026-07-11_

## What this is

MCP server that wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa) EVTX
analysis CLI, exposing it as tools callable from MCP clients (Claude Code, Claude Desktop).
See `CLAUDE.md` for the original design brief (note: that file is stale — it still says
"pre-implementation", but real code now exists).

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
unused params in these stubs; that's expected and not a bug.

## How to test

```
python3 test_scan_evtx.py
```

Downloads a sample EVTX (Mimikatz/Sysmon) into `samples/` on first run if not already
present, then exercises both tools end-to-end: normal scan, severity filter, rule filter,
missing-file error, invalid-arg errors, `output_format` summary/full, `max_results`,
keyword search over rules, `min_severity` over rules. All checks currently pass.

There is no pytest/unittest harness — this is a single manual script with hand-rolled
assertions and `sys.exit(1)` on failure.

## Known gaps / things to flag

- **No version control.** This directory is not a git repo (`git status` → "not a git
  repository"). Nothing here is committed anywhere — a disk failure or accidental
  `rm` loses all of it, including the code from this session.
- **`hayabusa/rules/` is itself a git checkout** (has its own `.git/`). If you `git init`
  at the project root, this will show up as an embedded/nested repo (git treats it as a
  gitlink boundary, not tracked file-by-file) — decide whether to `.gitignore` the whole
  `hayabusa/` directory (binary + rules, ~73MB) rather than trying to vendor it.
- **No `.gitignore` exists yet.** Candidates to exclude: `hayabusa/` (73MB binary +
  rules clone — reproducible via `scripts/download_hayabusa.py`), `samples/` (test fixture
  downloaded on demand), `logs/`, `__pycache__/`.
- **`requirements.txt`** now lists `mcp[cli]>=1.2.0` and `pyyaml>=6.0` (added this session
  for `get_hayabusa_rules`'s YAML parsing). Not yet verified against a clean venv install
  — it was already present in the environment when tested.
- **Hayabusa binary/rules are unpinned.** `scripts/download_hayabusa.py` fetches
  "latest" — current installed version is `hayabusa-3.10.0-lin-x64-musl`. No lockfile
  ties a known-good rule/binary version to this codebase.
- **`_load_all_rules()` caches forever** — if `hayabusa update-rules` is run against a
  live server process, `get_hayabusa_rules` will keep serving stale cached rules until
  restart. Fine for now, worth knowing.
- **`CLAUDE.md` is stale** — still describes the repo as empty/pre-implementation. Worth
  updating to reflect the real architecture (two server files, which one is live, test
  script, rules-caching behavior) so future sessions don't have to rediscover this from
  scratch.

## Suggested next steps before you step away

1. **`git init` and commit** — highest priority; there is currently zero durability for
   this work. Add a `.gitignore` first (see candidates above) so you don't accidentally
   commit the 73MB `hayabusa/` payload or its nested `.git`.
2. Update `CLAUDE.md` to match reality (drop "pre-implementation", document the two
   server files and which is live).
3. Decide whether `server.py` (the dead FastMCP stub) should be finished, deleted, or
   left as-is — right now it's dead code that could confuse a future reader.
4. If you want CI-style confidence beyond the manual script, consider converting
   `test_scan_evtx.py` into real `pytest` cases.
