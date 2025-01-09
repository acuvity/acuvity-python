from unittest.mock import ANY, MagicMock, patch

import pytest

from acuvity.models.principal import PrincipalType
from acuvity.models.scanresponse import Extraction, Principal, Scanresponse
from acuvity.models.scanresponsewrapper import ScanResponseWrapper


@pytest.fixture
def mock_scanresponse():
    """
    Create a mock Scanresponse object for testing.
    """
    extraction = Extraction(
        exploits={"prompt_injection": 0.7},
        detections=None
    )
    return Scanresponse(
        principal=Principal(type=PrincipalType.APP),
        extractions=[extraction],
    )

def test_scan_api_with_mocked_internal_logic(mock_scanresponse):
    """
    Test the scan API by mocking the internal function that returns the Scanresponse.
    Verify the ScanResponseWrapper functionality and GuardCheck.
    """
    # Mock the internal scan_request function to return the mock Scanresponse
    with patch("acuvity.apex.Apex.scan_request", return_value=mock_scanresponse):
        # Mock the API's scan method
        def mock_scan(*args, **kwargs):
            raw_response = mock_scanresponse
            return ScanResponseWrapper(raw_response)

        # Call the mock scan function
        response = mock_scan(messages="Test prompt injection detection.")

        # Verify the response is wrapped correctly
        assert isinstance(response, ScanResponseWrapper)
        assert isinstance(response._scan_response, Scanresponse)


        # Test GuardCheck functionality
        guard_check = response.check("prompt_injection")

        # Mock the evaluator's evaluate method
        guard_check._evaluator.evaluate = MagicMock(return_value=MagicMock(verdict="FAIL"))

        # Perform a threshold check
        result = guard_check.threshold_greater_than(0.6)
        guard_check._evaluator.evaluate.assert_called_once_with(
            response._scan_response,
            "prompt_injection",
            ANY,
            None
        )
        print(result)
        assert result.verdict == "FAIL"

        # Test another guard attribute
        assert response._scan_response.extractions[0].exploits["prompt_injection"] == 0.7
