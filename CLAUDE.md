# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Hayabusa scanning: implemented. The server runs and both tools are manually tested against a real sample EVTX (see `test_scan_evtx.py`, a manual assertion script — not pytest). Not yet under CI.

Sigma rule resources: implemented and under pytest (`tests/`). This is the one part of the project with a real automated test suite; everything else is still manual-script-only.

Detection engineering knowledge base: **mostly implemented.** Sigma rules under `rules/`
are exposed as MCP resources, and ATT&CK technique lookups (name/description/coverage)
are exposed via `detection://attack/techniques/{technique_id}`, sourced live from the
MITRE ATT&CK STIX bundle rather than a checked-in `mappings/` directory — that directory
is no longer planned. A dedicated coverage-query tool (e.g. "list every technique with no
rule at all") is still **not implemented**; see "Planned expansion" below.

## Purpose

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) — a Windows event log (EVTX) analysis tool — to expose EVTX scanning as a tool callable by MCP clients (e.g. Claude Code, Claude Desktop).

The project's intended scope is broader than EVTX scanning alone: it's meant to become an MCP server providing a **detection engineering knowledge base** — Sigma rules and ATT&CK technique mappings browsable/queryable by Claude, combined with the Hayabusa scanning capability already in place.

## Resources

In addition to the two tools above, `server.py` exposes our own Sigma rules (distinct
from Hayabusa's bundled rules under `hayabusa/rules/`) as MCP resources, parsed from
`rules/` and cached in-memory (`_detection_rules_cache`) the same way `get_hayabusa_rules`
caches Hayabusa's rules. ATT&CK technique IDs are pulled out of each rule's `attack.tXXXX[.XXX]`
Sigma tags.

- **`detection://rules`** — JSON summary of every Sigma rule in `rules/` (rule_name, id,
  title, level, status, tags, techniques).
- **`detection://rules/{rule_name}`** — the raw YAML content of a single rule, looked up
  by filename stem (e.g. `detection://rules/proc_creation_win_lsass_dump_procdump`).
- **`detection://rules/by-technique/{technique_id}`** — JSON summary of rules tagged with
  a given ATT&CK technique ID, case-insensitive (e.g. `detection://rules/by-technique/T1003.001`).
- **`detection://attack/techniques/{technique_id}`** — a single ATT&CK technique's name,
  description, MITRE URL, tactics, and sub-technique/deprecated flags, plus which of our
  Sigma rules detect it and a `coverage` assessment (`"covered"` if at least one matching
  rule has Sigma `status: stable`, `"partial"` if matches exist but none are stable,
  `"gap"` if no rule matches at all), case-insensitive (e.g.
  `detection://attack/techniques/T1003.001`). Backed by `_load_attack_techniques()`,
  which parses the MITRE ATT&CK Enterprise STIX bundle downloaded to
  `attack/enterprise-attack.json` by `scripts/download_attack_data.py` (gitignored, same
  pattern as `hayabusa/`) and caches it in-memory (`_attack_techniques_cache`). Raises
  `FileNotFoundError` pointing at that script if the file is missing, and again if the
  requested technique ID isn't in the bundle.

All four concrete/templated URIs are registered via the low-level API's
`list_resources`/`list_resource_templates`/`read_resource` handlers — there's no FastMCP
`@mcp.resource` decorator involved, matching the rest of `server.py`'s low-level style.

## Planned expansion: detection engineering knowledge base

Still not implemented — documented here as the intended direction beyond the resources above.

**Goals:**
- A dedicated coverage-query tool (e.g. "list every technique with no rule at all" across
  the whole ATT&CK matrix, not just one technique at a time) — `detection://attack/techniques/{id}`
  only answers the question for a single technique you already know the ID of.
- Combine with Hayabusa scanning (the existing `scan_evtx`/`get_hayabusa_rules` tools)

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
  after the first call (`_rules_cache` in `server.py`), so a `hayabusa update-rules`
  run against a live server process won't be picked up until restart. Meant to be called
  before `scan_evtx` so a client can discover what rules exist / pick a `rule_filter`.

## Architecture

- **`server.py`** — the live server, using the MCP low-level `Server` API
  (`list_tools`/`call_tool`). This is what `.mcp.json` actually launches
  (`python3 server.py`) and what `test_scan_evtx.py` imports directly. Both tools
  above are fully implemented here. (This file used to be named `server_lowlevel.py`;
  it was renamed to `server.py` to remove the confusion of having two same-purpose
  files — there used to be a second, unused FastMCP-based skeleton also named
  `server.py` whose tools just raised `NotImplementedError`. That skeleton is gone;
  there is now exactly one server entry point.)
- **`hayabusa/`** — the external Hayabusa binary + its rules, installed by
  `scripts/download_hayabusa.py` (fetches the latest GitHub release for the current
  platform). Gitignored — not vendored, reproducible on demand. `hayabusa/rules/` is
  itself a git checkout (has its own `.git/`), which is part of why it's excluded rather
  than added as a submodule.
- **`attack/`** — the MITRE ATT&CK Enterprise STIX bundle (`enterprise-attack.json`, ~50MB),
  installed by `scripts/download_attack_data.py`. Gitignored — not vendored, reproducible
  on demand, same pattern as `hayabusa/`.
- **`samples/`** — test fixture EVTX file(s), auto-downloaded by `test_scan_evtx.py` on
  first run if missing. Gitignored.
- **`logs/`** — scratch error logs from manual CLI testing. Gitignored.
- **`test_scan_evtx.py`** — manual test script (not pytest). Imports `server`
  directly and exercises both tools end-to-end: normal scan, severity/keyword filtering,
  missing-file and invalid-argument errors, `output_format`, `max_results`. Run with
  `python3 test_scan_evtx.py`; it downloads the sample EVTX itself if needed and exits
  non-zero on any assertion failure.
- **`tests/`** — the one real pytest suite in this repo, covering the Sigma rules and the
  `detection://` resources (nothing about `scan_evtx`/`get_hayabusa_rules` is covered here;
  that's still `test_scan_evtx.py`'s job). Run with `python3 -m pytest`. `pytest.ini` sets
  `pythonpath = .` so `import server` resolves from the repo root without a src-layout or
  editable install.
  - `test_sigma_rules.py` — schema-validates every YAML file under `rules/` with `pysigma`
    (`SigmaRule.from_dict` + forcing each `condition` through the parser to catch dangling
    identifiers like a typo'd selection name), plus repo-specific sanity checks: required
    fields present, `level` is a real Sigma severity, no duplicate `id`/`title`, every rule
    has at least one `attack.tXXXX[.XXX]` tag, and the four ATT&CK techniques named in the
    original task (T1003.001, T1558.003, T1003.006, T1550.002) each have rule coverage.
  - `test_resources.py` — exercises `list_resources`, `list_resource_templates`, and
    `read_resource` directly (async functions run via `asyncio.run`, not through the MCP
    stdio transport), including the error paths (unknown rule name, empty technique_id,
    unrecognized URI scheme). The `detection://attack/techniques/{id}` tests are marked
    `requires_attack_data` and skip themselves if `attack/enterprise-attack.json` hasn't
    been downloaded, so the suite stays runnable without network access.
  - `conftest.py` — autouse fixtures that reset `server._detection_rules_cache` and
    `server._attack_techniques_cache` before/after each test so tests don't leak
    in-memory caches across each other.
  - Needs `pytest` and `pysigma`, tracked in `requirements-dev.txt` (not `requirements.txt`,
    since neither is needed at runtime by the live server).

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
