"""Tests for the detection:// MCP resource endpoints in server.py."""

import asyncio
import json

import pytest
from pydantic import AnyUrl

import server


def _run(coro):
    return asyncio.run(coro)


def _read(uri: str):
    return _run(server.read_resource(AnyUrl(uri)))


requires_attack_data = pytest.mark.skipif(
    not server.ATTACK_DATA_PATH.is_file(),
    reason="ATT&CK data not downloaded; run scripts/download_attack_data.py",
)


def test_list_resources_includes_summary_and_one_per_rule():
    resources = _run(server.list_resources())
    uris = [str(r.uri) for r in resources]

    assert "detection://rules" in uris

    rule_files = sorted(server.DETECTION_RULES_DIR.glob("*.yml"))
    assert len(resources) == len(rule_files) + 1

    for rule_path in rule_files:
        assert f"detection://rules/{rule_path.stem}" in uris


def test_list_resource_templates_exposes_all_templates():
    templates = _run(server.list_resource_templates())
    uri_templates = {t.uriTemplate for t in templates}
    assert uri_templates == {
        "detection://rules/{rule_name}",
        "detection://rules/by-technique/{technique_id}",
        "detection://attack/techniques/{technique_id}",
    }


def test_read_all_rules_summary():
    contents = _read("detection://rules")
    assert len(contents) == 1
    payload = json.loads(contents[0].content)

    rule_files = list(server.DETECTION_RULES_DIR.glob("*.yml"))
    assert payload["total_rules"] == len(rule_files)
    assert len(payload["rules"]) == len(rule_files)

    for rule in payload["rules"]:
        assert {"rule_name", "id", "title", "level", "status", "tags", "techniques"} <= rule.keys()


def test_read_single_rule_returns_raw_yaml_verbatim():
    rule_path = next(server.DETECTION_RULES_DIR.glob("proc_creation_win_lsass_dump_procdump.yml"))
    contents = _read(f"detection://rules/{rule_path.stem}")
    assert len(contents) == 1
    assert contents[0].content == rule_path.read_text()
    assert contents[0].mime_type == "application/yaml"


def test_read_unknown_rule_name_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        _read("detection://rules/does-not-exist")


def test_read_by_technique_returns_matching_rules():
    contents = _read("detection://rules/by-technique/T1003.001")
    payload = json.loads(contents[0].content)

    assert payload["technique_id"] == "T1003.001"
    assert payload["total_rules"] >= 2
    for rule in payload["rules"]:
        assert "T1003.001" in rule["techniques"]


def test_read_by_technique_is_case_insensitive():
    lower = json.loads(_read("detection://rules/by-technique/t1003.001")[0].content)
    upper = json.loads(_read("detection://rules/by-technique/T1003.001")[0].content)
    assert lower == upper


def test_read_by_technique_with_no_matches_returns_empty_list():
    contents = _read("detection://rules/by-technique/T9999.999")
    payload = json.loads(contents[0].content)
    assert payload["total_rules"] == 0
    assert payload["rules"] == []


def test_read_by_technique_with_empty_id_raises_value_error():
    with pytest.raises(ValueError):
        _read("detection://rules/by-technique/")


def test_read_unknown_uri_scheme_raises_value_error():
    with pytest.raises(ValueError):
        _read("foo://bar")


def test_technique_ids_from_tags_filters_non_technique_tags():
    tags = ["attack.credential-access", "attack.t1003.001", "attack.s0029"]
    assert server._technique_ids_from_tags(tags) == {"T1003.001"}


def test_technique_ids_from_tags_handles_no_technique_tags():
    assert server._technique_ids_from_tags(["attack.credential-access"]) == set()


@requires_attack_data
def test_read_attack_technique_covered_by_stable_rules():
    contents = _read("detection://attack/techniques/T1003.001")
    payload = json.loads(contents[0].content)

    assert payload["technique_id"] == "T1003.001"
    assert payload["name"] == "LSASS Memory"
    assert payload["description"]
    assert payload["url"].startswith("https://attack.mitre.org/techniques/T1003/001")
    assert payload["is_subtechnique"] is True
    assert "credential-access" in payload["tactics"]
    assert payload["coverage"] == "covered"
    assert len(payload["detecting_rules"]) >= 2
    for rule in payload["detecting_rules"]:
        assert "T1003.001" in rule["techniques"]


@requires_attack_data
def test_read_attack_technique_is_case_insensitive():
    lower = json.loads(_read("detection://attack/techniques/t1003.001")[0].content)
    upper = json.loads(_read("detection://attack/techniques/T1003.001")[0].content)
    assert lower == upper


@requires_attack_data
def test_read_attack_technique_with_no_rules_is_a_gap():
    # T1027 (Obfuscated Files or Information) is a real technique with no rule
    # coverage anywhere in rules/.
    contents = _read("detection://attack/techniques/T1027")
    payload = json.loads(contents[0].content)
    assert payload["coverage"] == "gap"
    assert payload["detecting_rules"] == []


@requires_attack_data
def test_read_attack_technique_unknown_id_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        _read("detection://attack/techniques/T9999.999")


def test_read_attack_technique_with_empty_id_raises_value_error():
    with pytest.raises(ValueError):
        _read("detection://attack/techniques/")


def test_coverage_assessment_gap_when_no_rules():
    assert server._coverage_assessment([]) == "gap"


def test_coverage_assessment_covered_when_any_rule_stable():
    rules = [{"status": "experimental"}, {"status": "stable"}]
    assert server._coverage_assessment(rules) == "covered"


def test_coverage_assessment_partial_when_no_rule_stable():
    rules = [{"status": "experimental"}]
    assert server._coverage_assessment(rules) == "partial"
