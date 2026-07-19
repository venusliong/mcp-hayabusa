"""Tests for the analyze_coverage tool in server.py."""

import pytest

import server

requires_attack_data = pytest.mark.skipif(
    not server.ATTACK_DATA_PATH.is_file(),
    reason="ATT&CK data not downloaded; run scripts/download_attack_data.py",
)


@requires_attack_data
def test_analyze_coverage_by_technique_matches_resource_payload():
    tool_result = server.analyze_coverage(technique_id="T1003.001")
    assert tool_result["technique_id"] == "T1003.001"
    assert tool_result["coverage"] == "covered"
    assert len(tool_result["detecting_rules"]) >= 2


@requires_attack_data
def test_analyze_coverage_by_technique_is_case_insensitive():
    lower = server.analyze_coverage(technique_id="t1003.001")
    upper = server.analyze_coverage(technique_id="T1003.001")
    assert lower == upper


@requires_attack_data
def test_analyze_coverage_by_technique_unknown_id_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        server.analyze_coverage(technique_id="T9999.999")


@requires_attack_data
def test_analyze_coverage_by_tactic_reports_gaps_and_coverage_counts():
    report = server.analyze_coverage(tactic="credential-access")
    assert report["tactic"] == "credential-access"
    assert report["total_techniques"] == (
        report["covered_count"] + report["partial_count"] + report["gap_count"]
    )
    assert report["total_techniques"] > 0

    covered_ids = {t["technique_id"] for t in report["covered_techniques"]}
    # The four techniques with known custom-rule coverage should all show up as covered.
    assert {"T1003.001", "T1003.006", "T1558.003"} <= covered_ids

    gap_ids = {t["technique_id"] for t in report["gap_techniques"]}
    # T1552 (Unsecured Credentials) has no rule anywhere in rules/.
    assert "T1552" in gap_ids


@requires_attack_data
def test_analyze_coverage_by_tactic_is_case_and_spacing_insensitive():
    hyphenated = server.analyze_coverage(tactic="credential-access")
    spaced = server.analyze_coverage(tactic="Credential Access")
    assert hyphenated == spaced


@requires_attack_data
def test_analyze_coverage_by_tactic_excludes_deprecated_techniques():
    report = server.analyze_coverage(tactic="credential-access")
    all_ids = (
        {t["technique_id"] for t in report["covered_techniques"]}
        | {t["technique_id"] for t in report["partial_techniques"]}
        | {t["technique_id"] for t in report["gap_techniques"]}
    )
    techniques = server._load_attack_techniques()
    for technique_id in all_ids:
        assert not techniques[technique_id]["deprecated"]


@requires_attack_data
def test_analyze_coverage_unknown_tactic_raises_value_error():
    with pytest.raises(ValueError):
        server.analyze_coverage(tactic="not-a-real-tactic")


def test_analyze_coverage_requires_one_argument():
    with pytest.raises(ValueError):
        server.analyze_coverage()


def test_analyze_coverage_rejects_both_arguments():
    with pytest.raises(ValueError):
        server.analyze_coverage(technique_id="T1003.001", tactic="credential-access")
