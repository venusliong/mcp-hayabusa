# Handoff — mcp-hayabusa

_Last updated: 2026-07-18_

## What this is

MCP server that wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa) EVTX
analysis CLI, exposing it as tools callable from MCP clients (Claude Code, Claude Desktop),
combined with a detection-engineering knowledge base (Sigma rules + ATT&CK technique
lookups + coverage-gap tooling) exposed as MCP resources and tools. See `CLAUDE.md` for
the full architecture — it's up to date as of this handoff.

## Current state

Branch is `main`, everything below is committed (latest commit `73f6449`, "Add
analyze_coverage and suggest_rule tools for detection coverage gaps"). Nothing is
uncommitted except the local permissions allowlist noise described below.

Four MCP tools, all fully implemented in **`server.py`** (the file `.mcp.json` launches;
`server_lowlevel.py` and the unused FastMCP stub are both long gone):

- **`scan_evtx(path, min_severity=None, rule_filter=None, output_format="summary", max_results=None)`**
  Runs `hayabusa json-timeline` against a file/directory, returns structured JSON findings.
- **`get_hayabusa_rules(keyword=None, min_severity=None, max_results=None)`**
  Parses Hayabusa's bundled rule YAMLs under `hayabusa/rules/`, filterable by keyword/severity.
  Cached in-memory after first call (`_rules_cache`).
- **`analyze_coverage(technique_id=None, tactic=None)`** — **new this session.** Reports
  Sigma rule (`rules/`) coverage for a single technique (same payload as
  `detection://attack/techniques/{id}`) or aggregates covered/partial/gap counts across
  every non-deprecated technique in a whole tactic. `tactic` is normalized
  case/spacing-insensitively (`"Credential Access"` == `"credential-access"`). This is
  the coverage-query tool that was on the "Planned expansion" roadmap in the previous
  handoff — that roadmap section is now gone from `CLAUDE.md`.
- **`suggest_rule(technique_id, create_file=False)`** — **new this session.** Checks a
  technique's coverage and, if it's not `"covered"`, suggests a detection approach.
  The suggestion draws on real MITRE-authored content: `_load_attack_techniques()` now
  also parses the STIX bundle's `x-mitre-detection-strategy`/`x-mitre-analytic` objects
  (linked to techniques via `detects` relationships) into a `detection_guidance` field —
  analyst-written detection descriptions plus log-source hints — and maps those to a
  best-guess Sigma logsource category. Falls back to a tactic→category heuristic when a
  technique has no detection-strategy data yet. `create_file=true` writes a starter
  `status: experimental` Sigma rule template to `rules/` with a placeholder selection
  block (intentionally not a real detection — see `CLAUDE.md` for why) and the MITRE
  guidance as header comments; refuses to overwrite (`FileExistsError`) and invalidates
  `_detection_rules_cache` on write so the new rule is immediately visible elsewhere.
  A covered technique makes `create_file` a no-op.

Both new tools share a `_build_technique_report()` helper with the
`detection://attack/techniques/{id}` resource handler (refactored out of that handler
this session, so all three stay in sync automatically).

Four MCP resources, all under the `detection://` scheme, backed by our own Sigma rules in
`rules/` (distinct from Hayabusa's bundled rules) — unchanged this session:

- `detection://rules` — summary of every rule in `rules/`.
- `detection://rules/{rule_name}` — raw YAML of one rule.
- `detection://rules/by-technique/{technique_id}` — rules tagged with a given ATT&CK ID.
- `detection://attack/techniques/{technique_id}` — technique name/description/URL/tactics
  plus which of our rules detect it and a `covered`/`partial`/`gap` coverage verdict.

## Interesting thing found this session: ATT&CK's STIX bundle has changed shape

The downloaded `attack/enterprise-attack.json` (fetched "latest" by
`scripts/download_attack_data.py`) now contains MITRE's newer "detection strategy" model:
`x-mitre-detection-strategy` objects link to `x-mitre-analytic` objects (each with a
human-written `description` and `x_mitre_log_source_references`), connected to techniques
via `relationship_type: "detects"`. `x_mitre_data_sources` on `attack-pattern` objects
themselves is now always empty (0/858 populated) — this newer structure is where the real
data source/detection info actually lives. `suggest_rule`'s guidance quality depends on
this; if a future re-download of the bundle changes this shape again, `_load_attack_techniques()`
is where to look. Also noticed at least one technique (T1027) tagged with a
`kill_chain_phases` tactic name (`"stealth"`) that isn't one of the classic eight
enterprise tactics — `_TACTIC_LOGSOURCE_FALLBACK` and `analyze_coverage`'s tactic
validation both handle unrecognized tactic names gracefully (fallback / listed as a valid
option respectively), so this wasn't a bug, just worth knowing the taxonomy isn't fully
stable across bundle downloads.

## Untracked files not yet investigated

`credential_access_rules.json`, `credential_access_rules_critical.json`,
`credential_access_rules_high.json` still sit untracked in the repo root, unchanged since
the last handoff. Origin and purpose still unknown — still explicitly deferred by the
user. Don't delete or commit them without asking.

## Local-only noise

`.claude/settings.local.json` has an uncommitted diff (adds a `Bash(python3 *)` permission
entry) — that's the harness auto-recording a tool-permission grant from this session, not
a deliberate project change. Left uncommitted on purpose; ignore it unless the user asks
to commit permissions changes.

## How to test

```
python3 -m pytest              # Sigma rules + detection:// resources + analyze_coverage +
                                # suggest_rule (69 tests, fast, no network needed once
                                # attack/ is downloaded — ATT&CK-dependent tests self-skip
                                # otherwise via the requires_attack_data marker)
python3 test_scan_evtx.py      # manual script: scan_evtx + get_hayabusa_rules end-to-end
```

`test_scan_evtx.py` downloads a sample EVTX (Mimikatz/Sysmon) into `samples/` on first run
if not already present. It's hand-rolled assertions + `sys.exit(1)` on failure, not pytest.

To exercise the ATT&CK-dependent resources/tools, `attack/enterprise-attack.json` must
exist first: `python3 scripts/download_attack_data.py` (~50MB download).

`tests/test_suggest_rule.py`'s file-writing tests monkeypatch `server.DETECTION_RULES_DIR`
to a `tmp_path` so they never write into the real `rules/` — confirmed via `git status`
after the test run that `rules/` stayed clean.

## Known gaps / things to flag

- **Hayabusa binary/rules are unpinned.** `scripts/download_hayabusa.py` fetches
  "latest" — no lockfile ties a known-good rule/binary version to this codebase. Same is
  true of the ATT&CK STIX bundle (`scripts/download_attack_data.py` always fetches the
  current `master` snapshot) — see the STIX-shape note above for why that's a live risk,
  not just a hypothetical one.
- **`requirements.txt`/`requirements-dev.txt`** not yet verified against a clean venv
  install — packages were already present in the environment when tested.
- **`_load_all_rules()` / `_load_detection_rules()` / `_load_attack_techniques()` all
  cache forever** (module-level globals, reset only by the pytest fixtures in
  `tests/conftest.py`, or by `suggest_rule` itself for `_detection_rules_cache` after a
  file write). If `hayabusa update-rules` runs, or `rules/` or
  `attack/enterprise-attack.json` change some other way, against a live server process,
  it'll keep serving stale cached data until restart.
- **`hayabusa/rules/` is itself a git checkout** (has its own `.git/`). It's inside the
  gitignored `hayabusa/` directory, so it never touches this repo's history.
- **`suggest_rule`'s generated templates are intentionally not real detections** —
  placeholder `detection.selection` field/value, `status: experimental`. They exist to
  get an analyst started (title, tags, logsource guess, MITRE guidance as comments), not
  to auto-produce working coverage. Don't mistake `rule_created: true` for "gap closed."
- **`scan_evtx`/`get_hayabusa_rules` still have no pytest coverage** — only the Sigma
  rules, `detection://` resources, `analyze_coverage`, and `suggest_rule` are under
  `tests/`; the Hayabusa-facing tools are still `test_scan_evtx.py`-only.

## Suggested next steps

1. Figure out what the three untracked `credential_access_rules*.json` files are for.
2. If you want CI-style confidence for the Hayabusa tools too, convert
   `test_scan_evtx.py` into real `pytest` cases.
3. Consider pinning the Hayabusa release/rules commit and the ATT&CK STIX bundle version
   the two download scripts install, so scans and technique lookups are reproducible —
   especially now that the STIX bundle's own internal shape has changed once already.
4. Verify `requirements.txt`/`requirements-dev.txt` in a clean venv.
5. Consider whether `suggest_rule`'s tactic→logsource fallback table
   (`_TACTIC_LOGSOURCE_FALLBACK`) needs updating for tactic names ATT&CK has introduced
   outside the classic eight (e.g. `"stealth"`, seen on T1027 this session).
