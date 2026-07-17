#!/usr/bin/env python3
"""Simple manual test: download a sample EVTX and call scan_evtx directly."""

import json
import sys
import urllib.request
from pathlib import Path

import server

SAMPLE_URL = (
    "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/"
    "Credential%20Access/CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx"
)
SAMPLE_DIR = Path(__file__).resolve().parent / "samples"
SAMPLE_PATH = SAMPLE_DIR / "CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx"


def ensure_sample() -> Path:
    if SAMPLE_PATH.exists():
        return SAMPLE_PATH
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Downloading sample EVTX from {SAMPLE_URL} ...")
    req = urllib.request.Request(SAMPLE_URL, headers={"User-Agent": "mcp-hayabusa-test"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        SAMPLE_PATH.write_bytes(resp.read())
    print(f"Saved to {SAMPLE_PATH}")
    return SAMPLE_PATH


def main() -> int:
    sample = ensure_sample()

    print("\n=== scan_evtx: no severity filter ===")
    result = server.scan_evtx(str(sample))
    print(f"path: {result['path']}")
    print(f"min_severity: {result['min_severity']}")
    print(f"total_findings: {result['total_findings']}")
    if not result["findings"]:
        print("ERROR: expected at least one finding from this sample", file=sys.stderr)
        return 1
    print("first finding:")
    print(json.dumps(result["findings"][0], indent=2))

    print("\n=== scan_evtx: min_severity=critical ===")
    filtered = server.scan_evtx(str(sample), min_severity="critical")
    print(f"total_findings: {filtered['total_findings']}")
    levels = sorted({f["Level"] for f in filtered["findings"]})
    print(f"levels present: {levels}")
    if any(level != "critical" for level in levels):
        print("ERROR: min_severity=critical returned a non-critical finding", file=sys.stderr)
        return 1
    if filtered["total_findings"] >= result["total_findings"]:
        print("ERROR: filtered scan did not narrow down results", file=sys.stderr)
        return 1

    print("\n=== scan_evtx: missing file ===")
    try:
        server.scan_evtx("/tmp/does-not-exist.evtx")
    except FileNotFoundError as e:
        print(f"correctly raised FileNotFoundError: {e}")
    else:
        print("ERROR: expected FileNotFoundError, none was raised", file=sys.stderr)
        return 1

    print("\n=== scan_evtx: invalid min_severity ===")
    try:
        server.scan_evtx(str(sample), min_severity="not-a-level")
    except ValueError as e:
        print(f"correctly raised ValueError: {e}")
    else:
        print("ERROR: expected ValueError, none was raised", file=sys.stderr)
        return 1

    print("\n=== scan_evtx: rule_filter='mimikatz' ===")
    filtered = server.scan_evtx(str(sample), rule_filter="mimikatz")
    print(f"total_findings: {filtered['total_findings']}")
    if not filtered["findings"]:
        print("ERROR: expected at least one finding matching 'mimikatz'", file=sys.stderr)
        return 1
    if any("mimikatz" not in f["RuleTitle"].lower() for f in filtered["findings"]):
        print("ERROR: rule_filter returned a finding without 'mimikatz' in its title", file=sys.stderr)
        return 1

    print("\n=== scan_evtx: output_format='summary' (default) ===")
    summary = server.scan_evtx(str(sample))
    expected_keys = {
        "Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID", "RuleID",
    }
    if any(set(f.keys()) != expected_keys for f in summary["findings"]):
        print("ERROR: summary findings did not have the expected condensed fields", file=sys.stderr)
        return 1

    print("\n=== scan_evtx: output_format='full' ===")
    full = server.scan_evtx(str(sample), output_format="full")
    if any("Details" not in f for f in full["findings"]):
        print("ERROR: full findings should include the raw 'Details' field", file=sys.stderr)
        return 1

    print("\n=== scan_evtx: invalid output_format ===")
    try:
        server.scan_evtx(str(sample), output_format="bogus")
    except ValueError as e:
        print(f"correctly raised ValueError: {e}")
    else:
        print("ERROR: expected ValueError, none was raised", file=sys.stderr)
        return 1

    print("\n=== scan_evtx: max_results=1 ===")
    limited = server.scan_evtx(str(sample), max_results=1)
    print(f"total_findings: {limited['total_findings']}, returned_findings: {limited['returned_findings']}")
    if limited["returned_findings"] != 1 or len(limited["findings"]) != 1:
        print("ERROR: max_results=1 did not limit the returned findings to 1", file=sys.stderr)
        return 1
    if limited["total_findings"] < 1:
        print("ERROR: total_findings should still reflect the unlimited match count", file=sys.stderr)
        return 1

    print("\n=== scan_evtx: invalid max_results ===")
    try:
        server.scan_evtx(str(sample), max_results=0)
    except ValueError as e:
        print(f"correctly raised ValueError: {e}")
    else:
        print("ERROR: expected ValueError, none was raised", file=sys.stderr)
        return 1

    print("\n=== get_hayabusa_rules: no filter ===")
    all_rules = server.get_hayabusa_rules()
    print(f"total_rules: {all_rules['total_rules']}")
    if all_rules["total_rules"] < 1:
        print("ERROR: expected at least one rule to be loaded", file=sys.stderr)
        return 1
    expected_keys = {
        "id", "title", "level", "status", "description", "tags",
        "ruletype", "logsource_product", "logsource_service", "logsource_category",
    }
    if any(set(r.keys()) != expected_keys for r in all_rules["rules"]):
        print("ERROR: rule entries did not have the expected fields", file=sys.stderr)
        return 1

    print("\n=== get_hayabusa_rules: keyword='mimikatz' ===")
    kw = server.get_hayabusa_rules(keyword="mimikatz")
    print(f"total_rules: {kw['total_rules']}")
    if not kw["rules"]:
        print("ERROR: expected at least one rule matching 'mimikatz'", file=sys.stderr)
        return 1

    def _rule_matches_keyword(rule: dict, needle: str) -> bool:
        haystacks = [rule.get("title"), rule.get("description"), rule.get("id"), *rule.get("tags", [])]
        return any(needle in str(h).lower() for h in haystacks)

    if any(not _rule_matches_keyword(r, "mimikatz") for r in kw["rules"]):
        print("ERROR: keyword filter returned a rule not matching 'mimikatz'", file=sys.stderr)
        return 1

    print("\n=== get_hayabusa_rules: min_severity='critical' ===")
    critical = server.get_hayabusa_rules(min_severity="critical")
    print(f"total_rules: {critical['total_rules']}")
    if not critical["rules"]:
        print("ERROR: expected at least one critical rule", file=sys.stderr)
        return 1
    if any(r["level"] != "critical" for r in critical["rules"]):
        print("ERROR: min_severity=critical returned a non-critical rule", file=sys.stderr)
        return 1
    if critical["total_rules"] >= all_rules["total_rules"]:
        print("ERROR: filtered rule list did not narrow down results", file=sys.stderr)
        return 1

    print("\n=== get_hayabusa_rules: max_results=3 ===")
    limited = server.get_hayabusa_rules(max_results=3)
    print(f"total_rules: {limited['total_rules']}, returned_rules: {limited['returned_rules']}")
    if limited["returned_rules"] != 3 or len(limited["rules"]) != 3:
        print("ERROR: max_results=3 did not limit the returned rules to 3", file=sys.stderr)
        return 1
    if limited["total_rules"] != all_rules["total_rules"]:
        print("ERROR: total_rules should still reflect the unlimited match count", file=sys.stderr)
        return 1

    print("\n=== get_hayabusa_rules: invalid min_severity ===")
    try:
        server.get_hayabusa_rules(min_severity="not-a-level")
    except ValueError as e:
        print(f"correctly raised ValueError: {e}")
    else:
        print("ERROR: expected ValueError, none was raised", file=sys.stderr)
        return 1

    print("\n=== get_hayabusa_rules: invalid max_results ===")
    try:
        server.get_hayabusa_rules(max_results=0)
    except ValueError as e:
        print(f"correctly raised ValueError: {e}")
    else:
        print("ERROR: expected ValueError, none was raised", file=sys.stderr)
        return 1

    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
