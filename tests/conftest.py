import pytest

import server


@pytest.fixture(autouse=True)
def reset_detection_rules_cache():
    """Force _load_detection_rules() to re-read rules/ from disk on every test."""
    server._detection_rules_cache = None
    yield
    server._detection_rules_cache = None


@pytest.fixture(autouse=True)
def reset_attack_techniques_cache():
    """Force _load_attack_techniques() to re-read attack/ from disk on every test."""
    server._attack_techniques_cache = None
    yield
    server._attack_techniques_cache = None
