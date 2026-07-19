# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Hayabusa scanning: implemented. The server runs and both tools are manually tested against a real sample EVTX (see `test_scan_evtx.py`, a manual assertion script — not pytest). Not yet under CI.

Sigma rule resources: implemented and under pytest (`tests/`). This is the one part of the project with a real automated test suite; everything else is still manual-script-only.

Detection engineering knowledge base: **implemented.** Sigma rules under `rules/`
are exposed as MCP resources, and ATT&CK technique lookups (name/description/coverage)
are exposed via `detection://attack/techniques/{technique_id}`, sourced live from the
MITRE ATT&CK STIX bundle rather than a checked-in `mappings/` directory — that directory
is no longer planned. The coverage-query tool called out below as the remaining gap is
now implemented as `analyze_coverage`.

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
- **`suggest_rule(technique_id, create_file=False)`**
  The gap-filling counterpart to `analyze_coverage`: checks a single technique's
  coverage (via the same `_build_technique_report()` helper), and if it isn't
  `"covered"`, suggests a detection approach instead of just reporting the gap.
  The suggestion isn't guesswork from the technique name alone — `_load_attack_techniques()`
  also parses the STIX bundle's newer detection-strategy/analytic objects (`x-mitre-detection-strategy`,
  `x-mitre-analytic`, and their `detects` relationships to techniques) into a
  `detection_guidance` list of MITRE-authored analytic descriptions and log-source
  references per technique, when present. `_guess_logsource_category()` maps those
  log-source names to a Sigma logsource category via `_LOGSOURCE_CATEGORY_HINTS`
  (e.g. "Process: Process Creation" → `process_creation`), falling back to
  `_TACTIC_LOGSOURCE_FALLBACK` (by tactic) and then a hardcoded default if a
  technique has no detection-strategy data yet. If `create_file=true` and the
  technique needs a rule, `_generate_rule_template()` writes a starter Sigma YAML to
  `rules/<generated_name>.yml`: `status: experimental`, a placeholder
  `detection.selection` (deliberately not a real detection — guessing exact field/value
  matches without a log sample would be a false coverage claim), the MITRE guidance
  text as header comments, and `level: medium` as a generic starting point. Raises
  `FileExistsError` rather than overwriting if that filename is already taken, and
  resets `_detection_rules_cache` after writing so the new rule is immediately visible
  to `detection://` resources and `analyze_coverage` without a server restart. A
  covered technique makes `create_file` a no-op (`rule_created: false`) regardless of
  the flag. Coverage here is assessed against our own `rules/` Sigma rules only, same
  as `analyze_coverage` and `detection://attack/techniques/{id}`.
- **`analyze_coverage(technique_id=None, tactic=None)`**
  The dedicated coverage-query tool that the resource endpoints alone couldn't provide:
  `detection://attack/techniques/{id}` only answers the covered/partial/gap question for
  one technique you already know the ID of. Takes exactly one of `technique_id` (e.g.
  `"T1003.001"`) or `tactic` (e.g. `"credential-access"`, case/spacing-insensitive —
  normalized via `_normalize_tactic()`); raises `ValueError` if given both or neither.
  - `technique_id` mode returns the same payload as `detection://attack/techniques/{id}`
    (built from the shared `_build_technique_report()` helper both now call).
  - `tactic` mode aggregates across every non-deprecated technique in that tactic (per
    the MITRE ATT&CK STIX bundle's `kill_chain_phases`), applying the same per-technique
    `_coverage_assessment()` logic used elsewhere, and returns `covered_count`/
    `partial_count`/`gap_count` plus the technique lists themselves — `gap_techniques` is
    the "list every technique with no rule at all" answer for a whole tactic in one call.
    Raises `ValueError` listing valid tactic slugs if the tactic name doesn't match any
    technique's tactics.
  - Like the `detection://` resources, coverage here is assessed against our own
    `rules/` Sigma rules only, not Hayabusa's bundled rule pack — matching the semantics
    `detection://attack/techniques/{id}` already established.

## Architecture

- **`server.py`** — the live server, using the MCP low-level `Server` API
  (`list_tools`/`call_tool`). This is what `.mcp.json` actually launches
  (`python3 server.py`) and what `test_scan_evtx.py` imports directly. All four tools
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
  - `test_analyze_coverage.py` — exercises `analyze_coverage()` directly (calling the
    plain Python function, not through `call_tool`): both `technique_id` and `tactic`
    modes, the argument-validation errors (both/neither given, unknown tactic, unknown
    technique ID), case/spacing-insensitivity, and that deprecated techniques are excluded
    from tactic-wide reports. Also marked `requires_attack_data` where it needs the STIX
    bundle, same as `test_resources.py`.
  - `test_suggest_rule.py` — exercises `suggest_rule()` directly: the already-covered
    no-op path, the gap path's suggestion payload, case-insensitivity, unknown-technique
    and empty-`technique_id` errors, and `create_file=True`'s file write — validated with
    `pysigma` the same way `test_sigma_rules.py` validates real rules, plus the
    `_detection_rules_cache` invalidation and the `FileExistsError` on a repeat write.
    The file-writing tests use an `isolated_rules_dir` fixture (`monkeypatch.setattr(server,
    "DETECTION_RULES_DIR", tmp_path)`) so they never touch the real `rules/` — note that
    same redirect also changes what counts as "covered" for the duration of the test,
    since coverage is read from `DETECTION_RULES_DIR` too, so the already-covered no-op
    test deliberately does *not* use that fixture (it never reaches the write branch).
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
