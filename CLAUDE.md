# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Implemented. The server runs and both tools are manually tested against a real sample EVTX (see `test_scan_evtx.py`). Not yet under CI; there's no pytest harness, just a manual assertion script.

## Purpose

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) — a Windows event log (EVTX) analysis tool — to expose EVTX scanning as a tool callable by MCP clients (e.g. Claude Code, Claude Desktop).

## Tools

- **`scan_evtx(path, min_severity=None, rule_filter=None, output_format="summary", max_results=None)`**
  Runs `hayabusa json-timeline` against an EVTX file or directory and returns structured
  JSON findings. `min_severity` is passed through to Hayabusa's own `-m` flag (efficient
  server-side filtering); `rule_filter` is a client-side case-insensitive substring match
  on rule title. `output_format="summary"` returns condensed fields per finding;
  `"full"` includes the raw Hayabusa `Details`/`ExtraFieldInfo`.
- **`get_hayabusa_rules(keyword=None, min_severity=None, max_results=None)`**
  Lists Hayabusa's detection rules (title, id, level, status, description, tags, logsource,
  ruletype) by parsing the YAML rule files under `hayabusa/rules/` directly — Hayabusa's CLI
  has no built-in "list rules as JSON" command. Filterable by keyword (substring match over
  title/description/tags/id) and/or minimum severity. Parsed rules are cached in-memory
  after the first call (`_rules_cache` in `server_lowlevel.py`), so a `hayabusa update-rules`
  run against a live server process won't be picked up until restart. Meant to be called
  before `scan_evtx` so a client can discover what rules exist / pick a `rule_filter`.

## Architecture

- **`server_lowlevel.py`** — the live server, using the MCP low-level `Server` API
  (`list_tools`/`call_tool`). This is what `.mcp.json` actually launches
  (`python3 server_lowlevel.py`) and what `test_scan_evtx.py` imports directly. Both tools
  above are fully implemented here.
- **`server.py`** — a second, unused FastMCP-based skeleton with matching tool signatures.
  Both of its tools just `raise NotImplementedError`; it's not wired to anything and exists
  only for signature parity in case someone revives the FastMCP approach. Don't confuse it
  for the live server.
- **`hayabusa/`** — the external Hayabusa binary + its rules, installed by
  `scripts/download_hayabusa.py` (fetches the latest GitHub release for the current
  platform). Gitignored — not vendored, reproducible on demand. `hayabusa/rules/` is
  itself a git checkout (has its own `.git/`), which is part of why it's excluded rather
  than added as a submodule.
- **`samples/`** — test fixture EVTX file(s), auto-downloaded by `test_scan_evtx.py` on
  first run if missing. Gitignored.
- **`logs/`** — scratch error logs from manual CLI testing. Gitignored.
- **`test_scan_evtx.py`** — manual test script (not pytest). Imports `server_lowlevel`
  directly and exercises both tools end-to-end: normal scan, severity/keyword filtering,
  missing-file and invalid-argument errors, `output_format`, `max_results`. Run with
  `python3 test_scan_evtx.py`; it downloads the sample EVTX itself if needed and exits
  non-zero on any assertion failure.

## Stack

- **Language**: Python
- **MCP framework**: the `mcp` Python library (official MCP SDK), low-level `Server` API
- **YAML parsing**: `pyyaml`, used only by `get_hayabusa_rules` to read rule metadata
  (prefers `CSafeLoader`/libyaml when available for parse speed across ~5k rule files;
  falls back to `SafeLoader` otherwise)
- **Hayabusa**: invoked as an external CLI binary installed locally under `hayabusa/`
  (not bundled/committed) — the server shells out to it via `subprocess` rather than
  reimplementing EVTX parsing

## Architecture notes for implementation

- Hayabusa is invoked as a subprocess using its JSONL output mode (`json-timeline -L`),
  not human-readable table/CSV output.
- Severity filtering for `scan_evtx` uses Hayabusa's own `-m`/min-level flag server-side;
  `get_hayabusa_rules` filters severity client-side since it's reading rule files, not
  running a scan.
- Hayabusa's binary presence is checked on each `scan_evtx` call (`HAYABUSA_BIN.is_file()`)
  and raises a `FileNotFoundError` pointing at `scripts/download_hayabusa.py` if missing;
  same pattern for the rules directory in `get_hayabusa_rules`.
- EVTX paths from the MCP client are validated (existence check) before being passed to
  the subprocess call; the subprocess is invoked as an argument list (no shell=True), so
  there's no shell-injection surface.
