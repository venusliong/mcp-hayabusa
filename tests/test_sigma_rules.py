"""Schema/consistency tests for the Sigma rules under rules/."""

from pathlib import Path

import pytest
import yaml
from sigma.rule import SigmaRule

import server

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
RULE_PATHS = sorted(RULES_DIR.glob("*.yml"))
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
REQUIRED_FIELDS = {
    "title", "id", "status", "description", "references",
    "author", "date", "tags", "logsource", "detection", "level",
}


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def test_rules_directory_is_not_empty():
    assert RULE_PATHS, f"expected at least one *.yml rule under {RULES_DIR}"


@pytest.mark.parametrize("rule_path", RULE_PATHS, ids=lambda p: p.stem)
def test_rule_has_required_fields(rule_path: Path):
    data = _load(rule_path)
    missing = REQUIRED_FIELDS - data.keys()
    assert not missing, f"{rule_path.name} is missing fields: {missing}"


@pytest.mark.parametrize("rule_path", RULE_PATHS, ids=lambda p: p.stem)
def test_rule_level_is_valid(rule_path: Path):
    data = _load(rule_path)
    assert data["level"] in VALID_LEVELS, (
        f"{rule_path.name} has level {data['level']!r}, expected one of {VALID_LEVELS}"
    )


@pytest.mark.parametrize("rule_path", RULE_PATHS, ids=lambda p: p.stem)
def test_rule_parses_as_valid_sigma(rule_path: Path):
    data = _load(rule_path)
    rule = SigmaRule.from_dict(data)

    # from_dict() alone doesn't resolve condition identifiers against the
    # detection block; force the parse to catch e.g. "condition: selection and typo".
    for cond in rule.detection.parsed_condition:
        cond.parsed


@pytest.mark.parametrize("rule_path", RULE_PATHS, ids=lambda p: p.stem)
def test_rule_has_at_least_one_attack_technique_tag(rule_path: Path):
    data = _load(rule_path)
    techniques = server._technique_ids_from_tags(data.get("tags") or [])
    assert techniques, f"{rule_path.name} has no attack.tXXXX[.XXX] tag in {data.get('tags')}"


def test_rule_ids_are_unique():
    ids = [_load(p)["id"] for p in RULE_PATHS]
    duplicates = {i for i in ids if ids.count(i) > 1}
    assert not duplicates, f"duplicate Sigma rule IDs found: {duplicates}"


def test_rule_titles_are_unique():
    titles = [_load(p)["title"] for p in RULE_PATHS]
    duplicates = {t for t in titles if titles.count(t) > 1}
    assert not duplicates, f"duplicate rule titles found: {duplicates}"


@pytest.mark.parametrize(
    "technique_id,expected_min_rules",
    [
        ("T1003.001", 2),  # LSASS memory access
        ("T1558.003", 1),  # Kerberoasting
        ("T1003.006", 1),  # DCSync
        ("T1550.002", 2),  # Pass-the-hash
    ],
)
def test_required_techniques_have_coverage(technique_id: str, expected_min_rules: int):
    matches = [
        p for p in RULE_PATHS
        if technique_id in server._technique_ids_from_tags(_load(p).get("tags") or [])
    ]
    assert len(matches) >= expected_min_rules, (
        f"expected at least {expected_min_rules} rule(s) tagged {technique_id}, "
        f"found {len(matches)}: {[p.name for p in matches]}"
    )
