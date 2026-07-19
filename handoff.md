# Handoff — mcp-hayabusa

_Last updated: 2026-07-18_

## What this is

MCP server that wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa) EVTX
analysis CLI, exposing it as tools callable from MCP clients (Claude Code, Claude Desktop),
combined with a growing detection-engineering knowledge base (Sigma rules + ATT&CK technique
lookups) exposed as MCP resources. See `CLAUDE.md` for the full architecture — it's up to
date as of this handoff (including the uncommitted changes described below).

## Current state

Branch is `main` (already resolved as of the previous handoff). Everything below is on
`main`, except the ATT&CK resource work, which is **uncommitted in the working tree** —
see "Uncommitted changes" below.

Two MCP tools, both fully implemented in **`server.py`** (this is the file `.mcp.json`
launches and what `test_scan_evtx.py` imports — the old `server_lowlevel.py` name and the
unused FastMCP stub file are both gone, folded into this one file as of commit `986ff9f`):

- **`scan_evtx(path, min_severity=None, rule_filter=None, output_format="summary", max_results=None)`**
  Runs `hayabusa json-timeline` against a file/directory, returns structured JSON findings.
- **`get_hayabusa_rules(keyword=None, min_severity=None, max_results=None)`**
  Parses Hayabusa's bundled rule YAMLs under `hayabusa/rules/`, filterable by keyword/severity.
  Cached in-memory after first call (`_rules_cache`).

Four MCP resources, all under the `detection://` scheme, backed by our own Sigma rules in
`rules/` (distinct from Hayabusa's bundled rules):

- `detection://rules` — summary of every rule in `rules/`.
- `detection://rules/{rule_name}` — raw YAML of one rule.
- `detection://rules/by-technique/{technique_id}` — rules tagged with a given ATT&CK ID.
- `detection://attack/techniques/{technique_id}` — **new this session, uncommitted.** An
  ATT&CK technique's name/description/URL/tactics plus which of our rules detect it and a
  `covered`/`partial`/`gap` coverage verdict. See below.

## Uncommitted changes: ATT&CK technique resource

Not yet committed — working tree has:

- `server.py` — `_load_attack_techniques()` (parses the MITRE ATT&CK Enterprise STIX
  bundle, cached in `_attack_techniques_cache`), `_coverage_assessment()`, and the new
  `detection://attack/techniques/{technique_id}` resource handler/template.
- `scripts/download_attack_data.py` — new script, downloads the STIX bundle to
  `attack/enterprise-attack.json` (gitignored, same reproducible-on-demand pattern as
  `hayabusa/`). Already run locally, so `attack/` exists on this machine.
- `.gitignore` — added `attack/`.
- `tests/conftest.py`, `tests/test_resources.py` — 8 new tests for the resource
  (covered/gap cases, case-insensitivity, error paths, coverage-assessment unit tests).
  The tests that need the STIX file are marked `requires_attack_data` and skip themselves
  if `attack/enterprise-attack.json` is missing, so `pytest` stays runnable without network.
- `CLAUDE.md` — updated to document the new resource and retire the previously-planned
  `mappings/` directory (this resource replaces that plan).

Coverage semantics: `covered` if at least one matching rule has Sigma `status: stable`,
`partial` if matches exist but none are stable, `gap` if no rule matches the technique ID
at all. Verified manually against `T1003.001` (covered), `T1550.002` (covered, mix of
stable+experimental rules), and `T1027` (gap, no rule coverage).

All 51 tests pass (`python3 -m pytest`); `pyright server.py` is clean.

**Next step for this thread of work: review the diff and commit it** (nothing has been
committed yet this session).

## Untracked files not yet investigated

`credential_access_rules.json`, `credential_access_rules_critical.json`,
`credential_access_rules_high.json` sit untracked in the repo root. Origin and purpose
unknown — explicitly deferred by the user ("leave the three untracked files for now").
Don't delete or commit them without asking; look into what they are before doing anything
else with them.

## How to test

```
python3 -m pytest              # Sigma rules + detection:// resources (51 tests, fast, no network needed
                                # once attack/ is downloaded — ATT&CK-resource tests self-skip otherwise)
python3 test_scan_evtx.py      # manual script: scan_evtx + get_hayabusa_rules end-to-end
```

`test_scan_evtx.py` downloads a sample EVTX (Mimikatz/Sysmon) into `samples/` on first run
if not already present. It's hand-rolled assertions + `sys.exit(1)` on failure, not pytest.

To exercise the new ATT&CK resource, `attack/enterprise-attack.json` must exist first:
`python3 scripts/download_attack_data.py` (~50MB download).

## Known gaps / things to flag

- **Hayabusa binary/rules are unpinned.** `scripts/download_hayabusa.py` fetches
  "latest" — no lockfile ties a known-good rule/binary version to this codebase. Same is
  now true of the ATT&CK STIX bundle (`scripts/download_attack_data.py` always fetches
  the current `master` snapshot).
- **`requirements.txt`/`requirements-dev.txt`** not yet verified against a clean venv
  install — packages were already present in the environment when tested.
- **`_load_all_rules()` / `_load_detection_rules()` / `_load_attack_techniques()` all
  cache forever** (module-level globals, reset only by the pytest fixtures in
  `tests/conftest.py`). If `hayabusa update-rules` runs, or `rules/` or
  `attack/enterprise-attack.json` change, against a live server process, it'll keep
  serving stale cached data until restart. Fine for now, worth knowing.
- **`hayabusa/rules/` is itself a git checkout** (has its own `.git/`). It's inside the
  gitignored `hayabusa/` directory, so it never touches this repo's history.
- **No coverage-query tool yet** — `detection://attack/techniques/{id}` only answers
  "what's the coverage for this one technique I already know the ID of," not "list every
  technique with no rule at all" across the whole ATT&CK matrix. Still on the roadmap
  (see CLAUDE.md "Planned expansion").
- **`scan_evtx`/`get_hayabusa_rules` still have no pytest coverage** — only the Sigma
  rules and `detection://` resources are under `tests/`; the Hayabusa-facing tools are
  still `test_scan_evtx.py`-only.

## Suggested next steps

1. Review and commit the uncommitted ATT&CK resource work (see above).
2. Figure out what the three untracked `credential_access_rules*.json` files are for.
3. If you want CI-style confidence for the Hayabusa tools too, convert
   `test_scan_evtx.py` into real `pytest` cases.
4. Consider pinning the Hayabusa release/rules commit and the ATT&CK STIX bundle version
   the two download scripts install, so scans and technique lookups are reproducible.
5. Verify `requirements.txt`/`requirements-dev.txt` in a clean venv.
6. Build the coverage-query tool (list all techniques with no/partial rule coverage)
   described in CLAUDE.md's "Planned expansion" section.
