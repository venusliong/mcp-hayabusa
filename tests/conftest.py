import pytest

import server


@pytest.fixture(autouse=True)
def reset_detection_rules_cache():
    """Force _load_detection_rules() to re-read rules/ from disk on every test."""
    server._detection_rules_cache = None
    yield
    server._detection_rules_cache = None
