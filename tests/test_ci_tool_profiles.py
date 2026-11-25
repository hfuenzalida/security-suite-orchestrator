"""CI install profiles for check_security_tools / install-matrix alignment."""
from secscan.ci_tool_profiles import (
    PROFILE_CI_EXTENDED,
    PROFILE_CI_MINIMAL,
    PROFILE_FULL,
    tool_specs_for_profile,
)


def test_ci_minimal_is_subset_of_extended():
    m = {t.key for t in tool_specs_for_profile(PROFILE_CI_MINIMAL)}
    e = {t.key for t in tool_specs_for_profile(PROFILE_CI_EXTENDED)}
    assert m <= e


def test_ci_extended_is_subset_of_full():
    e = {t.key for t in tool_specs_for_profile(PROFILE_CI_EXTENDED)}
    f = {t.key for t in tool_specs_for_profile(PROFILE_FULL)}
    assert e <= f


def test_ci_minimal_expected_keys():
    keys = {t.key for t in tool_specs_for_profile(PROFILE_CI_MINIMAL)}
    assert keys == {"semgrep", "bandit", "pip-audit", "detect-secrets"}
