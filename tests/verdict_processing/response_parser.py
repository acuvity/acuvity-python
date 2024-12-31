# tests/verdict_processing/utils/test_response_parser.py
import pytest

from acuvity.verdict_processing.models.errors import ValidationError
from acuvity.verdict_processing.util.response_parser import ResponseParser


class TestResponseParser:
    """Test suite for ResponseParser."""

    @pytest.fixture
    def complete_response(self):
        """Fixture with a complete response including all fields."""
        return {
            "modalities": [
                {"group": "image", "type": "document"},
                {"group": "text", "type": "plain"}
            ],
            "exploits": {
                "prompt_injection": 0.95,
                "toxicity": 0.8,
                "jail_break": 1.0,
                "bias": 0.85,
                "harmful_content": 0.9
            },
            "intent": {
                "write": 1.0,
                "explain": 0.8,
                "summarize": 0.9
            },
            "languages": {
                "english": 0.94,
                "french": 0.7
            },
            "topics": {
                "category/enterprise": 0.85,
                "image/document": 0.9
            },
            "piis": {
                "email": 0.95,
                "person": 1.0
            },
            "detections": [
                {
                    "name": "email_address",
                    "type": "PII",
                    "score": 0.9,
                    "start": 10,
                    "end": 25,
                    "redacted": True
                }
            ]
        }

    @pytest.fixture
    def minimal_response(self):
        """Fixture with only required fields."""
        return {
            "exploits": {
                "prompt_injection": 0.95,
            },
            "languages": {
                "english": 0.94,
            },
            "modalities": []
        }

    def test_get_value_exploits(self, complete_response):
        """Test getting values from exploits section."""
        parser = ResponseParser()

        assert parser.get_value(complete_response, "exploits.prompt_injection") == 0.95
        assert parser.get_value(complete_response, "exploits.toxicity") == 0.8
        assert parser.get_value(complete_response, "exploits.jail_break") == 1.0

    def test_get_value_nested_paths(self, complete_response):
        """Test getting values using nested paths."""
        parser = ResponseParser()

        # Test different path patterns
        assert parser.get_value(complete_response, "topics.category/enterprise") == 0.85
        assert parser.get_value(complete_response, "topics.image/document") == 0.9
        assert parser.get_value(complete_response, "piis.email") == 0.95

    def test_get_value_missing_path(self, complete_response):
        """Test getting values with non-existent paths."""
        parser = ResponseParser()

        with pytest.raises(ValidationError) as exc:
            parser.get_value(complete_response, "exploits.non_existent")
        assert "Path" in str(exc.value)
        assert "not found" in str(exc.value)

    def test_validate_response_minimal(self, minimal_response):
        """Test validating a minimal valid response."""
        parser = ResponseParser()
        parser.validate_response(minimal_response)  # Should not raise

    def test_validate_response_complete(self, complete_response):
        """Test validating a complete response."""
        parser = ResponseParser()
        parser.validate_response(complete_response)  # Should not raise

    @pytest.mark.parametrize("invalid_response,expected_error", [
        ({}, "missing required sections"),
        ({"exploits": {}}, "missing required sections"),
        ({"exploits": {}, "languages": {}}, "missing required sections"),
        (None, "Response must be a dictionary"),
        ([], "Response must be a dictionary"),
        ("invalid", "Response must be a dictionary"),
    ])
    def test_validate_response_invalid(self, invalid_response, expected_error):
        """Test validating invalid responses."""
        parser = ResponseParser()

        with pytest.raises(ValidationError) as exc:
            parser.validate_response(invalid_response)
        assert expected_error in str(exc.value)

    def test_get_value_from_detections(self, complete_response):
        """Test getting values from detections array."""
        parser = ResponseParser()

        # Test accessing detection score
        value = parser.get_value(complete_response, "detections.0.score")
        assert value == 0.9

    @pytest.mark.parametrize("path,expected_type", [
        ("exploits.prompt_injection", float),
        ("languages.english", float),
        ("topics.category/enterprise", float),
        ("piis.email", float),
        ("detections.0.score", float),
    ])
    def test_get_value_return_types(self, complete_response, path, expected_type):
        """Test return type of get_value for different paths."""
        parser = ResponseParser()
        value = parser.get_value(complete_response, path)
        assert isinstance(value, expected_type)

    def test_validate_response_with_optional_sections(self):
        """Test validation with different combinations of optional sections."""
        parser = ResponseParser()

        # Response with some optional sections
        response = {
            "exploits": {"prompt_injection": 0.95},
            "languages": {"english": 0.94},
            "modalities": [],
            "intent": {"write": 1.0},  # Optional
            "topics": {"category/enterprise": 0.85}  # Optional
        }
        parser.validate_response(response)  # Should not raise

        # Response without optional sections
        minimal = {
            "exploits": {"prompt_injection": 0.95},
            "languages": {"english": 0.94},
            "modalities": []
        }
        parser.validate_response(minimal)  # Should not raise

    def test_get_value_empty_or_invalid_paths(self, complete_response):
        """Test get_value with empty or invalid path strings."""
        parser = ResponseParser()

        invalid_paths = ["", " ", None, ".", "/", "invalid/path"]
        for path in invalid_paths:
            with pytest.raises(ValidationError) as exc:
                parser.get_value(complete_response, path)
            assert "Invalid path" in str(exc.value) or "Path not found" in str(exc.value)
