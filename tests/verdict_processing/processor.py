import pytest

from acuvity.verdict_processing.constants import Verdict
from acuvity.verdict_processing.core.processor import VerdictProcessor
from acuvity.verdict_processing.models.errors import ConfigurationError, ValidationError


class TestVerdictProcessor:
    """Comprehensive test suite for VerdictProcessor and its components."""

    @pytest.fixture
    def simple_response(self):
        """Simple response with basic fields."""
        return {
            "exploits": {
                "prompt_injection": 0.95,
                "jail_break": 1.0,
                "malicious_url": 0.8
            },
            "topics": {
                "content/toxic": 0.7,
                "content/bias": 0.65,
                "content/harmful": 0.85,
                "image/document": 0.9,
                "image/code": 0.8
            },
            "languages": {
                "gibberish": 0.79,
                "english": 0.94
            },
            "modalities": [],
            "intent": {
                "write": 0.9
            },
            "piis": {
                "email": 0.95
            },
            "detections": []
        }

    def test_direct_check_threshold_greater(self, simple_response):
        """Test direct threshold check with greater than."""
        processor = VerdictProcessor(simple_response)

        # Test prompt_injection (in exploits section)
        result = processor.check("prompt_injection").threshold_greater_than(0.7)
        assert result.verdict == Verdict.PASS  # 0.95 > 0.7 is True
        assert result.actual_value == 0.95
        assert result.threshold == 0.7

        # Test toxicity (in topics.content/toxic)
        result = processor.check("toxicity").threshold_greater_than(0.9)
        assert result.verdict == Verdict.FAIL  # 0.7 > 0.9 is False
        assert result.actual_value == 0.7
        assert result.threshold == 0.9

    def test_direct_check_threshold_less(self, simple_response):
        """Test direct threshold check with less than."""
        processor = VerdictProcessor(simple_response)

        # Test gibberish (in languages section)
        result = processor.check("gibberish").threshold_less_than(0.9)
        assert result.verdict == Verdict.PASS  # 0.79 < 0.9 is True
        assert result.actual_value == 0.79
        assert result.threshold == 0.9

        # Test prompt_injection
        result = processor.check("prompt_injection").threshold_less_than(0.9)
        assert result.verdict == Verdict.FAIL  # 0.95 < 0.9 is False
        assert result.actual_value == 0.95

    def test_direct_check_equals(self, simple_response):
        """Test direct threshold check with equals."""
        processor = VerdictProcessor(simple_response)

        # Test jail_break
        result = processor.check("jail_break").equals(1.0)
        assert result.verdict == Verdict.PASS  # 1.0 == 1.0 is True
        assert result.actual_value == 1.0

        # Test malicious_url
        result = processor.check("malicious_url").equals(0.9)
        assert result.verdict == Verdict.FAIL  # 0.8 != 0.9 is False
        assert result.actual_value == 0.8

    def test_match_based_checks(self, simple_response):
        """Test checks that use matches."""
        processor = VerdictProcessor(simple_response)

        # Test language match
        result = processor.check("language").for_match("english").threshold_greater_than(0.7)
        assert result.verdict == Verdict.PASS  # 0.94 > 0.7 is True
        assert result.actual_value == 0.94

        # Test image_classifier match
        result = processor.check("image_classifier").for_match("document").threshold_greater_than(0.7)
        assert result.verdict == Verdict.PASS  # 0.9 > 0.7 is True
        assert result.actual_value == 0.9

    def test_topic_based_checks(self, simple_response):
        """Test checks that use topic prefixes."""
        processor = VerdictProcessor(simple_response)

        # Test content/toxic
        result = processor.check("toxicity").threshold_greater_than(0.6)
        assert result.verdict == Verdict.PASS  # 0.7 > 0.6 is True
        assert result.actual_value == 0.7

        # Test content/harmful
        result = processor.check("harmful_content").threshold_greater_than(0.9)
        assert result.verdict == Verdict.FAIL  # 0.85 > 0.9 is False
        assert result.actual_value == 0.85



    @pytest.fixture
    def sample_response(self):
        """Sample response with all required sections."""
        return {
            "exploits": {
                "prompt_injection": 0.95,
                "jail_break": 1.0,
                "malicious_url": 0.8
            },
            "topics": {
                "content/toxic": 0.7,
                "content/bias": 0.65,
                "content/harmful": 0.85,
                "image/document": 0.9,
                "image/code": 0.8,
                "department/cybersecurity": 0.75,
                "category/enterprise": 0.8
            },
            "languages": {
                "gibberish": 0.79,
                "english": 0.94,
                "french": 0.7,
                "spanish": 0.6
            },
            "modalities": [
                {"group": "document", "type": "pdf", "score": 0.8},
                {"group": "image", "type": "png", "score": 0.7}
            ],
            "intent": {
                "write": 0.9,
                "explain": 0.8
            },
            "piis": {
                "email": 0.95,
                "person": 1.0
            },
            "detections": [
                {
                    "name": "email_address",
                    "type": "Pattern",
                    "score": 0.9
                }
            ]
        }

    # def test_simple_guards(self, sample_response):
    #     """Test processing of simple guards (no matches)."""
    #     config = {
    #         "guardrails": [
    #             {
    #                 "guard_name": "prompt_injection",
    #                 "threshold": ">= 0.7",
    #                 "action": "deny"
    #             },
    #             {
    #                 "guard_name": "toxicity",  # Uses topics.content/toxic
    #                 "threshold": ">= 0.8",
    #                 "action": "deny"
    #             },
    #             {
    #                 "guard_name": "gibberish",  # Direct in languages
    #                 "threshold": ">= 0.8",
    #                 "action": "deny"
    #             }
    #         ]
    #     }

    #     processor = VerdictProcessor(sample_response)
    #     result = processor.process_config(config)

    #     # Should fail for prompt_injection (0.95 >= 0.7)
    #     # Should pass for toxicity (0.7 < 0.8)
    #     # Should pass for gibberish (0.79 < 0.8)
    #     assert result.verdict == Verdict.FAIL
    #     assert len(result.failed_checks) == 1
    #     assert result.failed_checks[0].check_name == "exploits.prompt_injection"
    #     assert result.total_checks == 3

    def test_match_guards(self, sample_response):
        """Test processing of guards with matches."""
        config = {
            "guardrails": [
                {
                    "guard_name": "language",
                    "matches": {
                        "english": {"threshold": ">= 0.7"},
                        "french": {"threshold": "0.5"},
                        "spanish": {"threshold": ">= 0.8"}
                    },
                    "action": "deny"
                },
                {
                    "guard_name": "image_classifier",
                    "matches": {
                        "document": {"threshold": "0.7"},
                        "code": {"threshold": "0.7"}
                    },
                    "action": "allow"
                }
            ]
        }

        processor = VerdictProcessor(sample_response)
        result = processor.get_verdict_from_guardconfig(config)

        # For language (deny action):
        # - english: should fail (0.94 >= 0.7)
        # - french: should fail (0.7 > 0.5)
        # - spanish: should pass (0.6 < 0.8)

        # For image_classifier (allow action):
        # - document: should pass (0.9 >= 0.7)
        # - code: should pass (0.8 >= 0.7)

        assert result.verdict == Verdict.FAIL
        assert len(result.failed_checks) == 2  # english and french
        assert result.total_checks == 5  # 3 language matches + 2 image matches

        # Verify specific checks
        failed_paths = [check.check_name for check in result.failed_checks]
        assert "languages.english" in failed_paths
        assert "languages.french" in failed_paths

    def test_invalid_response(self):
        """Test handling of invalid response (missing sections)."""
        invalid_response = {
            "exploits": {},
            "languages": {}
            # Missing other required sections
        }

        with pytest.raises(ValidationError) as exc:
            VerdictProcessor(invalid_response)
        assert "missing required sections" in str(exc.value)

    def test_mixed_guards_config(self, sample_response):
        """Test processing of both simple and match guards together."""
        config = {
            "guardrails": [
                {
                    "guard_name": "prompt_injection",
                    "threshold": ">= 0.9",
                    "action": "deny"
                },
                {
                    "guard_name": "language",
                    "matches": {
                        "english": {"threshold": ">= 0.9"},
                        "french": {"threshold": ">= 0.8"}
                    },
                    "action": "deny"
                }
            ]
        }

        processor = VerdictProcessor(sample_response)
        result = processor.get_verdict_from_guardconfig(config)

        # prompt_injection: should fail (0.95 >= 0.9)
        # language.english: should fail (0.94 >= 0.9)
        # language.french: should pass (0.7 < 0.8)

        assert result.verdict == Verdict.FAIL
        assert len(result.failed_checks) == 2
        assert result.total_checks == 3

        # Verify the details
        check_names = [check.check_name for check in result.failed_checks]
        assert "exploits.prompt_injection" in check_names
        assert "languages.english" in check_names
