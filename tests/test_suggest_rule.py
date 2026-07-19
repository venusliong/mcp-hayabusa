"""Tests for the suggest_rule tool in server.py."""

import pytest
import yaml
from sigma.rule import SigmaRule

import server

requires_attack_data = pytest.mark.skipif(
    not server.ATTACK_DATA_PATH.is_file(),
    reason="ATT&CK data not downloaded; run scripts/download_attack_data.py",
)


@pytest.fixture
def isolated_rules_dir(tmp_path, monkeypatch):
    """Redirect create_file writes to a throwaway directory instead of the real rules/."""
    monkeypatch.setattr(server, "DETECTION_RULES_DIR", tmp_path)
    return tmp_path


@requires_attack_data
def test_suggest_rule_already_covered_needs_no_suggestion():
    result = server.suggest_rule("T1003.001")
    assert result["coverage"] == "covered"
    assert result["needs_rule"] is False
    assert result["suggestion"] is None
    assert result["rule_created"] is False


@requires_attack_data
def test_suggest_rule_gap_returns_suggestion_without_writing_a_file():
    # T1027 (Obfuscated Files or Information) has no rule anywhere in rules/.
    result = server.suggest_rule("T1027")
    assert result["coverage"] == "gap"
    assert result["needs_rule"] is True
    assert result["rule_created"] is False
    assert result["rule_path"] is None

    suggestion = result["suggestion"]
    assert suggestion is not None
    assert suggestion["suggested_logsource"]["product"] == "windows"
    assert suggestion["logsource_basis"] in {"attack-analytics", "tactic-fallback", "default-fallback"}


@requires_attack_data
def test_suggest_rule_is_case_insensitive():
    lower = server.suggest_rule("t1027")
    upper = server.suggest_rule("T1027")
    assert lower == upper


@requires_attack_data
def test_suggest_rule_unknown_technique_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        server.suggest_rule("T9999.999")


def test_suggest_rule_requires_technique_id():
    with pytest.raises(ValueError):
        server.suggest_rule("")


@requires_attack_data
def test_suggest_rule_create_file_writes_valid_sigma_rule(isolated_rules_dir):
    result = server.suggest_rule("T1027", create_file=True)

    assert result["rule_created"] is True
    written = list(isolated_rules_dir.glob("*.yml"))
    assert len(written) == 1
    assert written[0].name == f"{result['rule_name']}.yml"

    data = yaml.safe_load(written[0].read_text())
    rule = SigmaRule.from_dict(data)
    for cond in rule.detection.parsed_condition:
        cond.parsed  # forces identifier resolution, same as test_sigma_rules.py

    assert str(rule.status) == "experimental"
    assert "T1027" in server._technique_ids_from_tags(data["tags"])
    assert data["logsource"]["category"] == result["suggestion"]["suggested_logsource"]["category"]


@requires_attack_data
def test_suggest_rule_create_file_updates_detection_rules_cache(isolated_rules_dir):
    # Prime the cache with the (empty) isolated directory, then confirm the newly
    # written file is picked up without a manual cache reset.
    assert server._load_detection_rules() == []
    result = server.suggest_rule("T1027", create_file=True)
    rule_names = [r["rule_name"] for r in server._load_detection_rules()]
    assert result["rule_name"] in rule_names


@requires_attack_data
def test_suggest_rule_create_file_is_a_noop_when_already_covered():
    # Deliberately runs against the real rules/ (read-only path): a covered technique
    # never reaches the file-write branch, so nothing here touches the filesystem.
    result = server.suggest_rule("T1003.001", create_file=True)
    assert result["rule_created"] is False
    assert result["rule_path"] is None


@requires_attack_data
def test_suggest_rule_create_file_raises_if_already_generated(isolated_rules_dir):
    server.suggest_rule("T1027", create_file=True)
    server._detection_rules_cache = None
    with pytest.raises(FileExistsError):
        server.suggest_rule("T1027", create_file=True)
