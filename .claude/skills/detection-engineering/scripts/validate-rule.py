#!/usr/bin/env python3
"""Validate a Sigma rule against this repo's detection-engineering standards.

Standards enforced (see .claude/skills/detection-engineering/SKILL.md):
  1. At least one attack.tXXXX[.XXX] tag in 'tags'.
  2. 'level' is one of low/medium/high/critical (Sigma's 'informational' is not
     accepted in this repo).
  3. 'falsepositives' is present, non-empty, and not just a placeholder entry
     (e.g. "Unknown", "N/A").
  4. At least one '# Test case' comment block documented in the file.

This is a lightweight standards check, not a schema validator — it does not
replace `python3 -m pytest tests/test_sigma_rules.py`, which uses pysigma to
validate the rule actually parses (required fields, condition references,
etc). Run both.

Usage:
    python3 .claude/skills/detection-engineering/scripts/validate-rule.py <path-to-rule.yml>

Prints a JSON report to stdout. Exits 0 if all checks pass, 1 if any check
fails, 2 on usage/file errors.
"""

import json
import re
import sys
from pathlib import Path

import yaml

ATTACK_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
VALID_LEVELS = {"low", "medium", "high", "critical"}
PLACEHOLDER_FALSEPOSITIVES = {"unknown", "none", "n/a", "na", "tbd", "todo"}
TEST_CASE_RE = re.compile(r"#\s*Test case", re.IGNORECASE)


def _technique_ids_from_tags(tags) -> set:
    ids = set()
    for tag in tags or []:
        match = ATTACK_TECHNIQUE_TAG_RE.match(str(tag))
        if match:
            ids.add(match.group(1).upper())
    return ids


def _falsepositives_documented(falsepositives) -> bool:
    if not isinstance(falsepositives, list) or not falsepositives:
        return False
    for fp in falsepositives:
        if not isinstance(fp, str):
            continue
        normalized = fp.strip().lower().rstrip(".:")
        if normalized and normalized not in PLACEHOLDER_FALSEPOSITIVES:
            return True
    return False


def validate(path: Path) -> dict:
    raw_text = path.read_text()

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        return {
            "file": str(path),
            "valid": False,
            "checks": {},
            "issues": [f"YAML parse error: {exc}"],
        }

    if not isinstance(data, dict):
        return {
            "file": str(path),
            "valid": False,
            "checks": {},
            "issues": ["rule content is not a YAML mapping"],
        }

    issues = []
    checks = {}

    techniques = _technique_ids_from_tags(data.get("tags"))
    checks["attack_tags_present"] = bool(techniques)
    if not techniques:
        issues.append("no attack.tXXXX[.XXX] tag found in 'tags'")

    level = data.get("level")
    level_valid = isinstance(level, str) and level.lower() in VALID_LEVELS
    checks["valid_severity_level"] = level_valid
    if not level_valid:
        issues.append(f"'level' is {level!r}, expected one of {sorted(VALID_LEVELS)}")

    fp_ok = _falsepositives_documented(data.get("falsepositives"))
    checks["falsepositives_documented"] = fp_ok
    if not fp_ok:
        issues.append(
            "'falsepositives' is missing, empty, or only placeholder entries "
            "(e.g. 'Unknown', 'N/A')"
        )

    has_test_case = bool(TEST_CASE_RE.search(raw_text))
    checks["test_case_present"] = has_test_case
    if not has_test_case:
        issues.append("no '# Test case' comment block found in the file")

    return {
        "file": str(path),
        "valid": not issues,
        "checks": checks,
        "issues": issues,
        "techniques": sorted(techniques),
        "level": level,
    }


def main() -> None:
    if len(sys.argv) != 2:
        print(
            json.dumps({"error": "usage: validate-rule.py <path-to-rule.yml>"}),
            file=sys.stderr,
        )
        sys.exit(2)

    path = Path(sys.argv[1])
    if not path.is_file():
        print(json.dumps({"error": f"file not found: {path}"}), file=sys.stderr)
        sys.exit(2)

    result = validate(path)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
