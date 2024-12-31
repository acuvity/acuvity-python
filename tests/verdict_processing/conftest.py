# tests/verdict_processing/conftest.py
from typing import Any, Dict

import pytest


@pytest.fixture
def sample_response() -> Dict[str, Any]:
    """Sample response data for testing."""
    return {
        "exploits": {
            "prompt_injection": 0.95,
            "toxicity": 0.8,
            "gibberish": 0.85,
            "jail_break": 1.0,
            "bias": 0.85,
            "harmful_content": 0.9
        },
        "modalities": [
            {"group": "image", "type": "document"},
            {"group": "text", "type": "plain"}
        ],
        "languages": {
            "gibberish": 0.7,
            "english": 0.94,
            "french": 0.7,
            "spanish": 0.6,
            "german": 0.6,
            "russian": 0.6,
            "chinese": 0.6,
            "japanese": 0.65
        },
        "topics": {
            "category/enterprise": 0.85,
            "department/information_technology": 1.0,
            "image/document": 0.9,
            "image/printed": 0.85,
            "category/sales_and_marketing": 0.7
        },
        "intent": {
            "write": 1.0,
            "explain": 0.8,
            "summarize": 0.9,
            "suggest": 0.7
        },
        "piis": {
            "email": 0.95,
            "person": 1.0,
            "ssn": 0.9
        },
        "detections": [
            {
                "name": "email_address",
                "type": "Pattern",
                "score": 0.9,
                "start": 10,
                "end": 25,
                "redacted": True
            },
            {
                "name": "credit_card",
                "type": "Pattern",
                "score": 0.8,
                "start": 30,
                "end": 44,
                "redacted": False
            }
        ]
    }

@pytest.fixture
def basic_guard_config() -> Dict[str, Any]:
    """Simple guard config for basic tests."""
    return {
        "guardrails": [
            {
                "guard_name": "prompt_injection",
                "threshold": ">= 0.7",
                "action": "deny"
            },
            {
                "guard_name": "toxicity",
                "threshold": "0.7",
                "action": "deny"
            },
            {
                "guard_name": "gibberish",
                "threshold": ">= 0.8",
                "action": "deny"
            }
        ]
    }

@pytest.fixture
def full_guard_config() -> Dict[str, Any]:
    """Complete guard configuration for comprehensive tests."""
    return {
        "guardrails": [
            # Basic guards
            {
                "guard_name": "prompt_injection",
                "threshold": ">= 0.7",
                "action": "deny"
            },
            {
                "guard_name": "toxicity",
                "threshold": "0.7",
                "action": "deny"
            },
            {
                "guard_name": "gibberish",
                "threshold": ">= 0.8",
                "action": "deny"
            },
            {
                "guard_name": "jail_break",
                "threshold": ">= 1.0",
                "action": "deny"
            },
            {
                "guard_name": "bias",
                "threshold": "0.8",
                "action": "deny"
            },
            {
                "guard": "harmful_content",
                "threshold": ">= 0.9",
                "action": "deny"
            },
            # Complex guards with matches
            {
                "guard_name": "modality",
                "matches": {
                    "unknown": {"threshold": "0.7"},
                    "document": {"threshold": "0.7"},
                    "executable": {"threshold": "0.7"},
                    "application": {"threshold": "0.7"},
                    "code": {"threshold": "0.7"},
                    "image": {"threshold": "0.7"},
                    "archive": {"threshold": "0.7"},
                    "text": {"threshold": "0.7"},
                    "audio": {"threshold": "0.7"},
                    "video": {"threshold": "0.7"}
                },
                "action": "allow"
            },
            {
                "guard": "language",
                "matches": {
                    "english": {"threshold": "0.7"},
                    "french": {"threshold": "0.5"},
                    "spanish": {"threshold": "0.6"},
                    "german": {"threshold": "0.6"},
                    "russian": {"threshold": "0.6"},
                    "chinese": {"threshold": "0.6"},
                    "japanese": {"threshold": "0.6"}
                },
                "action": "deny"
            },
            {
                "guard": "image_classifier",
                "matches": {
                    "printed": {"threshold": "0.9"},
                    "blank": {"threshold": "0.9"},
                    "handwritten": {"threshold": "0.9"},
                    "cheque": {"threshold": "0.9"},
                    "code": {"threshold": "0.9"},
                    "whiteboard": {"threshold": "0.9"},
                    "document": {"threshold": "0.9"},
                    "unclassified": {"threshold": "0.9"}
                },
                "action": "deny"
            },
            # Special guards
            {
                "guard": "malicious_url",
                "threshold": "0.9",
                "action": "deny"
            },
            {
                "guard": "pii_detector",
                "matches": {
                    "email": {"redact": True},
                    "ssn": {"redact": True},
                    "person": {"redact": True}
                },
                "action": "allow"
            }
        ]
    }

@pytest.fixture
def classifier_guard_config() -> Dict[str, Any]:
    """Guard config specifically for testing classifiers."""
    return {
        "guardrails": [
            {
                "guard_name": "corporate_classifier",
                "matches": {
                    "customer_service": {"threshold": "0.7"},
                    "cybersecurity": {"threshold": "0.7"},
                    "finance": {"threshold": "0.7"},
                    "information_technology": {"threshold": "0.7"},
                    "legal": {"threshold": "0.7"}
                },
                "action": "allow"
            },
            {
                "guard_name": "generic_classifier",
                "matches": {
                    "explain": {"threshold": "0.7"},
                    "summarize": {"threshold": "0.7"},
                    "write": {"threshold": "0.7"},
                    "suggest": {"threshold": "0.7"}
                },
                "action": "allow"
            }
        ]
    }

@pytest.fixture
def pattern_detector_config() -> Dict[str, Any]:
    """Guard config for testing pattern detection."""
    return {
        "guardrails": [
            {
                "guard_name": "pattern_detector",
                "matches": {
                    "email_address": {"threshold": ">0.7"},
                    "credit_card": {"threshold": "0.7"},
                    "bank_account": {"threshold": "0.7"},
                    "phone_number": {"threshold": "0.7"}
                },
                "action": "allow"
            }
        ]
    }
