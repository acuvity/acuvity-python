from typing import Dict, List
from unittest.mock import MagicMock

import pytest

from acuvity.verdict_processing.core.guard_processor import GuardProcessor


@pytest.fixture
def guard_processor_exploit():
    """Fixture for GuardProcessor configured for EXPLOIT guards."""
    guard_config = {
        "guardrails": [
            {
                "name": "prompt_injection",
                "threshold": ">= 0.7"
            },
            {
                "name": "jail_break",
                "threshold": ">= 0.7"
            },
            {
                "name": "malicious_url",
                "threshold": ">= 0.7"
            }
        ]
    }
    return GuardProcessor(guard_config)

@pytest.fixture
def mock_response_exploit_pass():
    """Simulates a Scanresponse with an exploit value below the threshold."""
    extraction = MagicMock()
    extraction.exploits = {"prompt_injection": 0.5}  # Below the threshold of 0.7
    response = MagicMock()
    response.extractions = [extraction]
    return response

@pytest.fixture
def mock_response_exploit_fail():
    """Simulates a Scanresponse with an exploit value above the threshold."""
    extraction = MagicMock()
    extraction.exploits = {"prompt_injection": 0.9}  # Above the threshold of 0.7
    response = MagicMock()
    response.extractions = [extraction]
    return response

def test_guard_processor_exploit_pass(guard_processor_exploit, mock_response_exploit_pass):
    """Tests GuardProcessor for an EXPLOIT guard where the threshold is not crossed."""
    verdict = guard_processor_exploit.get_verdict(mock_response_exploit_pass).verdict
    assert verdict == "PASS", "The verdict should be PASS when the guard value does not exceed the threshold."

def test_guard_processor_exploit_fail(guard_processor_exploit, mock_response_exploit_fail):
    """Tests GuardProcessor for an EXPLOIT guard where the threshold is crossed."""
    verdict = guard_processor_exploit.get_verdict(mock_response_exploit_fail).verdict
    assert verdict == "FAIL", "The verdict should be FAIL when the guard value exceeds the threshold."


@pytest.fixture
def mock_response_malicious_url_pass():
    """Simulates a Scanresponse with a malicious URL value below the threshold."""
    extraction = MagicMock()
    extraction.exploits = {"malicious_url": 0.3}  # Below the threshold of 0.7
    response = MagicMock()
    response.extractions = [extraction]
    return response

@pytest.fixture
def mock_response_malicious_url_fail():
    """Simulates a Scanresponse with a malicious URL value above the threshold."""
    extraction = MagicMock()
    extraction.exploits = {"malicious_url": 0.9}  # Above the threshold of 0.7
    response = MagicMock()
    response.extractions = [extraction]
    return response

def test_guard_processor_prompt_injection_pass(guard_processor_exploit, mock_response_exploit_pass):
    """Tests GuardProcessor for a prompt_injection EXPLOIT guard where the threshold is not crossed."""
    verdict = guard_processor_exploit.get_verdict(mock_response_exploit_pass).verdict
    assert verdict == "PASS", "The verdict should be PASS when the guard value does not exceed the threshold."

def test_guard_processor_prompt_injection_fail(guard_processor_exploit, mock_response_exploit_fail):
    """Tests GuardProcessor for a prompt_injection EXPLOIT guard where the threshold is crossed."""
    verdict = guard_processor_exploit.get_verdict(mock_response_exploit_fail).verdict
    assert verdict == "FAIL", "The verdict should be FAIL when the guard value exceeds the threshold."

def test_guard_processor_jail_break_pass(guard_processor_exploit, mock_response_jailbreak_pass):
    """Tests GuardProcessor for a jail_break EXPLOIT guard where the threshold is not crossed."""
    verdict = guard_processor_exploit.get_verdict(mock_response_jailbreak_pass).verdict
    assert verdict == "PASS", "The verdict should be PASS when the guard value does not exceed the threshold."

def test_guard_processor_jail_break_fail(guard_processor_exploit, mock_response_jailbreak_fail):
    """Tests GuardProcessor for a jail_break EXPLOIT guard where the threshold is crossed."""
    verdict = guard_processor_exploit.get_verdict(mock_response_jailbreak_fail).verdict
    assert verdict == "FAIL", "The verdict should be FAIL when the guard value exceeds the threshold."

def test_guard_processor_malicious_url_pass(guard_processor_exploit, mock_response_malicious_url_pass):
    """Tests GuardProcessor for a malicious_url EXPLOIT guard where the threshold is not crossed."""
    verdict = guard_processor_exploit.get_verdict(mock_response_malicious_url_pass).verdict
    assert verdict == "PASS", "The verdict should be PASS when the guard value does not exceed the threshold."

def test_guard_processor_malicious_url_fail(guard_processor_exploit, mock_response_malicious_url_fail):
    """Tests GuardProcessor for a malicious_url EXPLOIT guard where the threshold is crossed."""
    verdict = guard_processor_exploit.get_verdict(mock_response_malicious_url_fail).verdict
    assert verdict == "FAIL", "The verdict should be FAIL when the guard value exceeds the threshold."
