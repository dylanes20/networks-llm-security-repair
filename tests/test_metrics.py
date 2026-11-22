import pytest

from metrics import calculate_metrics


def observation(claim, verified, false_assurance):
    return dict(llm_claimed_success=claim, verified_repair=verified,
                false_assurance=false_assurance)


def test_professor_example():
    rows = [
        observation(True, True, False),
        observation(True, False, True),
        observation(True, False, True),
        observation(False, False, False),
        observation(True, True, False),
    ]
    assert calculate_metrics(rows) == {
        "total_cases": 5, "verified_repairs": 2, "positive_claims": 4,
        "false_assurances": 2, "VRR": 0.4, "FAR": 0.5,
    }


@pytest.mark.parametrize("rows, expected_vrr", [([], None), ([observation(False, True, False)], 1)])
def test_far_undefined_without_positive_claims(rows, expected_vrr):
    result = calculate_metrics(rows)
    assert result["VRR"] == expected_vrr
    assert result["FAR"] is None


def test_indeterminate_attempts_keep_original_denominators():
    result = calculate_metrics([
        observation(True, False, True),
        observation(True, None, None),
        observation(None, None, None),
    ])
    assert result["total_cases"] == 3
    assert result["VRR"] == 0
    assert result["FAR"] == 0.5
