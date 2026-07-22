# False-positive patterns

Per SKILL.md standard 3, `falsepositives:` must be present, non-empty, and specific
enough to act on — not a placeholder. This doc collects recurring categories of
legitimate activity that trigger detection rules in this repo's domains (LSASS/
credential access, Kerberos, cloud sign-in), so a new rule's false-positive entries
can be concrete instead of guessed from scratch.

Bad vs. good, restated from SKILL.md:

```yaml
# Bad — too vague to act on
falsepositives:
    - Unknown
    - Legitimate admin activity

# Good — names the actor, the action, and (where possible) how to tell it apart
falsepositives:
    - Legitimate use by administrators or support engineers troubleshooting LSASS
      issues under a documented change ticket.
```

## Pattern: security/EDR tooling doing the same thing as the attacker

Endpoint security agents, crash-reporting utilities, and backup/monitoring tools
often perform the exact API calls or process access patterns a detection is looking
for, because they need broad visibility to do their job.

- Example: `proc_access_win_lsass_access_susp_mask.yml` excludes
  `werfault.exe`/`wermgr.exe`/`MsMpEng.exe` via a filter list *and* documents them
  in `falsepositives:` — the two aren't redundant, since the filter list handles
  the common/known cases mechanically while the prose covers cases the filter list
  doesn't (a different EDR vendor, an unlisted crash handler).
- How to distinguish: known-vendor binary paths/hashes, expected parent process,
  consistent timing (e.g. runs on every crash, not just once).

## Pattern: legitimate admin/support workflows using the "attacker" tool

The same tool attackers use for credential theft is often a real Sysinternals/
Microsoft-signed utility with a legitimate support use case.

- Example: `proc_creation_win_lsass_dump_procdump.yml` — ProcDump against lsass.exe
  is exactly what Microsoft support sometimes asks a customer to run to diagnose an
  LSASS crash or hang.
- How to distinguish: presence of a change ticket/ticket number in the environment
  (not visible to Sigma, but worth noting so the SOC knows to check), whether it
  runs interactively from an admin's own session vs. unattended/remote, whether the
  output is exfiltrated afterward.

## Pattern: legacy protocols/flows with a narrow legitimate niche

Some flows (ROPC auth, NTLM fallback, RC4 Kerberos encryption) are deprecated or
discouraged but still required by specific legacy applications that can't be
upgraded.

- Example: `azure_app_ropc_authentication.yml` — ROPC is inherently risky but still
  used by CI/test automation and legacy line-of-business apps that can't do modern
  auth.
- Example: `win_security_kerberoasting_rc4_tgs_request.yml` — RC4-encrypted TGS
  requests happen legitimately when a service account's msDS-SupportedEncryptionTypes
  hasn't been updated to require AES, independent of any Kerberoasting attempt.
- How to distinguish: a fixed, known set of service/application accounts (an
  allowlist you can name explicitly) vs. an unexpected account requesting the same
  flow for the first time.

## Pattern: automated testing / CI systems

Test suites and CI pipelines legitimately exercise authentication flows, admin
tools, or process-access patterns at a much higher frequency than a human would,
and often from a small number of known service accounts or hosts.

- How to distinguish: source host/account is in a known CI/test allowlist,
  frequency and regularity (CI runs on a schedule; an attacker doesn't), absence of
  the other steps in a normal attack chain (no follow-on lateral movement).

## Pattern: authentication method transition periods

During a migration (e.g. rolling out AES-only Kerberos, deprecating ROPC,
onboarding new EDR), the volume of "false positives" from the old-but-still-valid
pattern spikes temporarily and predictably.

- How to distinguish: this isn't a per-rule filter so much as an operational note —
  document the expected migration window in the false-positive entry itself so
  triage analysts (and future you) know a spike during that window is expected,
  e.g. "Elevated volume expected during the AES enforcement rollout,
  tracked in [ticket]; investigate spikes outside that window."

## When there's genuinely no known false-positive path

Rare, but real — say so explicitly rather than leaving the field empty or vague:

```yaml
falsepositives:
    - None known. This command-line pattern has no legitimate administrative use.
```

Note the period after "known" rather than a colon — `None known:` gets parsed by
PyYAML as a mapping key inside the list item and breaks the file. Use `.` or `—`
instead if you need punctuation there.
