---
name: detection-engineering
description: Use this skill when writing or creating Sigma detection rules, reviewing detection rules, discussing detection coverage, or working with YAML detection files under rules/ (or any Sigma-format *.yml). Enforces this repo's detection rule standards — ATT&CK technique mapping, justified severity, documented false positives, at least one test case, and lowercase_underscore naming — before a rule is considered done.
---

# Detection engineering standards

This repo's Sigma rules live in `rules/` (distinct from Hayabusa's bundled rules under
`hayabusa/rules/`) and are schema-validated by `pysigma` in `tests/test_sigma_rules.py`.
That test suite already enforces required fields, a valid `level`, unique `id`/`title`,
and at least one `attack.tXXXX` tag. It does **not** enforce severity justification,
false-positive quality, or test cases — those are judgment calls this skill exists to
apply consistently. Run `python3 -m pytest tests/test_sigma_rules.py` after any rule
change regardless.

Apply all five standards below to every rule you write or review.

## 1. ATT&CK technique mapping

Every rule must carry at least one `attack.tXXXX` or `attack.tXXXX.XXX` tag in
`tags:`, matching a real technique ID in the MITRE ATT&CK Enterprise matrix.

```yaml
tags:
    - attack.credential-access   # tactic tag, optional but preferred alongside the technique
    - attack.t1003.001           # required: technique (or sub-technique) tag
```

- Use the most specific applicable ID (prefer `t1003.001` over the parent `t1003` if the
  rule targets LSASS dumping specifically, not credential access generically).
- If you're unsure a technique ID is current, check it against
  `detection://attack/techniques/{technique_id}` (this project's own MCP resource) or
  `attack/enterprise-attack.json` rather than guessing — deprecated/renamed IDs happen.
- A rule with zero `attack.t*` tags fails `test_rule_has_at_least_one_attack_technique_tag`
  and should be rejected in review.

## 2. Severity with justification

`level:` must be one of Sigma's four values this repo uses: `low`, `medium`, `high`,
`critical`. `informational` is not an accepted level here even though Sigma allows it.

The level alone isn't sufficient — the rule (or the PR/review discussion introducing it)
must state **why** that level was chosen: impact if the technique succeeds, how
actionable/urgent a hit is, and how noisy the detection is expected to be. Put this in the
`description:` field or as a trailing sentence in `falsepositives:` context, e.g.:

```yaml
description: |
    Detects direct LSASS memory access with a handle mask associated with credential
    dumping tools. High severity: successful execution yields cleartext/hashed
    credentials enabling lateral movement, and the mask pattern is rare in legitimate
    activity, so hits are high-confidence.
level: high
```

When reviewing a rule with no justification, ask for one rather than assuming the
severity is correct. Calibration guide used elsewhere in this repo's rules:
- `critical` — direct path to domain compromise (e.g. DCSync, golden ticket use) with low
  false-positive rate.
- `high` — credential theft / privilege escalation primitives (e.g. LSASS dump,
  Kerberoasting, pass-the-hash) — see `rules/proc_creation_win_lsass_dump_procdump.yml`
  for the pattern.
- `medium` — suspicious but commonly benign-explainable behavior needing triage.
- `low` — weak signal, useful mainly as corroboration alongside other hits.

## 3. Documented false positives

`falsepositives:` must be present and non-empty — a list of concrete, specific scenarios,
not a placeholder. Reject/flag rules with vague entries.

```yaml
falsepositives:
    - Legitimate use by administrators or support engineers troubleshooting LSASS
      issues under a documented change ticket.
```

Bad (too vague to act on): `falsepositives: ["Unknown"]` or `["Legitimate admin activity"]`
with no specifics about *which* activity or *how* to distinguish it from the malicious
case.

If a rule genuinely has no known false-positive path (rare), say so explicitly and state
why: `- None known: this command-line pattern has no legitimate administrative use.`

## 4. At least one test case

Every rule must include at least one worked example showing a log event it should match
(true positive), documented as a YAML comment block at the bottom of the rule file since
Sigma has no native test-case field and this repo has no separate fixtures directory yet:

```yaml
# Test case (true positive):
#   Image: C:\Tools\procdump64.exe
#   OriginalFileName: procdump
#   CommandLine: procdump64.exe -ma -mp lsass.exe lsass.dmp
#
# Test case (should NOT match):
#   CommandLine: procdump64.exe -ma -mp winlogon.exe winlogon.dmp
```

Include a true-negative example too whenever the selection logic is non-obvious (e.g. it
disambiguates on a specific flag or target, not just the binary name) — that's the case
most likely to regress silently.

If you have a real or synthetic EVTX sample that exercises the rule, note where it lives
(e.g. under `samples/`) instead of/alongside the inline example.

## 5. Rule naming

Filenames (and thus `rule_name` as exposed by `detection://rules/{rule_name}`) must be
lowercase with underscores, following the existing convention:

```
<logsource-prefix>_win_<short-description>.yml
```

Examples already in `rules/`: `proc_creation_win_lsass_dump_procdump.yml`,
`win_security_dcsync_replication_rights_abuse.yml`,
`win_security_kerberoasting_rc4_tgs_request.yml`. Prefixes in use: `proc_creation_win_`,
`proc_access_win_`, `win_security_`, chosen to reflect `logsource.category`/`product`, not
freeform. No spaces, no CamelCase, no hyphens.

## Review checklist

When reviewing a rule (new or existing), check in order and stop at the first failure to
report back to the author:

1. `attack.tXXXX[.XXX]` tag present and valid.
2. `level` is one of `low`/`medium`/`high`/`critical`, and the severity choice is
   justified in prose somewhere in the rule.
3. `falsepositives:` present, non-placeholder, specific.
4. At least one test case (true positive, plus true negative if selection logic is
   non-trivial) documented in the rule or pointed at a sample file.
5. Filename is `lowercase_with_underscores.yml`.
6. `python3 -m pytest tests/test_sigma_rules.py` passes (schema, uniqueness, required
   fields — this is the automated floor, not a substitute for 1–4 above).

When writing a new rule from scratch (including via `suggest_rule`'s generated
templates), treat its `status: experimental` placeholder output as a starting skeleton
only — it deliberately omits a real detection and a test case, so standards 3 and 4 above
still need to be filled in by hand before the rule is considered reviewable, let alone
`status: stable`.

## Validation

After creating or modifying a rule, validate it:

```
python .claude/skills/detection-engineering/scripts/validate-rule.py path/to/rule.yml
```

This checks standards 1–4 above (ATT&CK tag present, valid `level`, non-placeholder
`falsepositives`, at least one `# Test case` comment) and prints a JSON report, exiting
non-zero if anything fails. It's a fast standards check, not a schema validator — still
run `python3 -m pytest tests/test_sigma_rules.py` too, since that's what actually
confirms the rule parses as valid Sigma.

## References

- `references/example-rules/lsass_memory_access.yml` — a fully annotated example
  rule showing all five standards satisfied in one file; copy the structure when
  starting a new rule from scratch.
- `references/severity-guide.md` — worked criteria and examples for choosing
  between `low`/`medium`/`high`/`critical`, to keep severity calibrated the same
  way across rules instead of re-deriving it each time.
- `references/false-positive-patterns.md` — recurring categories of legitimate
  activity (security tooling, admin/support workflows, legacy-protocol niches, CI
  systems, migration windows) to draw concrete `falsepositives:` entries from
  instead of writing a vague one.
