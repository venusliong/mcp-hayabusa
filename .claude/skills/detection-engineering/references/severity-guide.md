# Severity guide

This repo uses four Sigma `level:` values: `low`, `medium`, `high`, `critical`.
`informational` is valid Sigma but is **not** an accepted level here — pick the
nearest of the four instead.

Per SKILL.md standard 2, the level alone is never sufficient — every rule must state
*why* that level was chosen, in the `description:` field (impact if the technique
succeeds, how actionable/urgent a hit is, how noisy the rule is expected to be).
This doc exists to keep those choices consistent across rules; it doesn't replace
writing the justification in the rule itself.

## `critical`

Direct path to domain or tenant compromise, with a low false-positive rate — a hit
means immediate, high-confidence action, not triage.

- DCSync (`win_security_dcsync_replication_rights_abuse.yml`) — replication rights
  abuse yields every credential in the domain.
- Golden/silver ticket use.
- Full admin-scope OAuth consent grants on a tenant.

Ask: *if this fires and is a true positive, is the domain/tenant already
compromised?* If yes, `critical`.

## `high`

Credential theft or privilege-escalation primitives — the attacker doesn't have the
keys yet, but this step gets them there directly.

- LSASS memory access/dumping (`proc_access_win_lsass_access_susp_mask.yml`,
  `proc_creation_win_lsass_dump_procdump.yml`,
  `proc_creation_win_lsass_dump_comsvcs_minidump.yml`).
- Kerberoasting (`win_security_kerberoasting_rc4_tgs_request.yml`).
- Pass-the-hash (`win_security_pass_the_hash_logon_type9.yml`).

Ask: *if this fires and is a true positive, does the attacker now have (or is about
to have) credentials usable for lateral movement?* If yes, `high`.

## `medium`

Suspicious but commonly benign-explainable behavior that needs a human to triage
before deciding whether it's an incident.

- Legacy/risky authentication flows that expose credentials to an application but
  aren't themselves evidence of compromise (`azure_app_ropc_authentication.yml`) —
  a precondition for misuse, not proof of it.
- Unusual but not-inherently-malicious process relationships (e.g. an uncommon
  parent/child process pairing that has known legitimate uses).

Ask: *could a reasonable admin/user action produce this exact event, such that a
human needs to look at context before acting?* If yes, `medium`.

## `low`

Weak signal, mainly useful as corroboration alongside other hits rather than as a
standalone alert.

- Broad reconnaissance commands that are individually near-ubiquitous
  (`whoami`, `net user`) and only meaningful in combination with other signals.
- Access-mask or logon-type patterns that are *slightly* atypical but have many
  legitimate explanations.

Ask: *would I want to page someone on this alone, or only as one data point in a
larger correlation?* If only the latter, `low`.

## Choosing between two adjacent levels

When a technique could plausibly sit at either of two levels, let the
false-positive rate be the tiebreaker, not just the technique's theoretical impact:
a `critical`-impact technique detected via a noisy, low-precision selector should
usually be graded down one level (to `high`) rather than kept at `critical`, since
`critical` is meant to signal "act now," not just "this technique is scary."
Tighten the detection logic if you can instead of just lowering the level — but if
the noise is inherent to the log source, downgrade and say so in the description.
