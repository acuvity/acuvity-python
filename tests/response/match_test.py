from typing import List

import pytest

from acuvity.guard.config import Guard, GuardConfig, Match
from acuvity.guard.constants import GuardName
from acuvity.guard.threshold import Threshold
from acuvity.models.extraction import Extraction
from acuvity.models.principal import PrincipalType
from acuvity.models.scanresponse import Principal, Scanresponse
from acuvity.models.textualdetection import Textualdetection, TextualdetectionType
from acuvity.response.match import ScanResponseMatch

class TestResponseProcessingE2E:
    @pytest.fixture
    def create_pii_extraction(self) -> Extraction:
        """Create an extraction with PII detections"""
        def _create_pii_extraction(
            email_detections: List[float] ,
            person_detections: List[float] ,
            ssn_detections: List[float]
        ) -> Extraction:
            detections = []
            pii_dict = {}

            # Add email detections
            if email_detections:
                for confidence in email_detections:
                    detections.append(
                        Textualdetection(
                            type=TextualdetectionType.PII,
                            name="email",
                            score=confidence,
                        )
                    )
                pii_dict["email"] = max(email_detections)

            # Add person detections
            if person_detections:
                for confidence in person_detections:
                    detections.append(
                        Textualdetection(
                            type=TextualdetectionType.PII,
                            name="person",
                            score=confidence,
                        )
                    )
                pii_dict["person"] = max(person_detections)

            # Add SSN detections
            if ssn_detections:
                for confidence in ssn_detections:
                    detections.append(
                        Textualdetection(
                            type=TextualdetectionType.PII,
                            name="ssn",
                            score=confidence,
                        )
                    )
                pii_dict["ssn"] = max(ssn_detections)

            return Extraction(detections=detections, pi_is=pii_dict, data="hello")

        return _create_pii_extraction

    @pytest.fixture
    def create_exploit_extraction(self) -> Extraction:
        """Create an extraction with exploit detection"""
        def _create_exploit_extraction(
            prompt_injection_score: float = 0.0
        ) -> Extraction:
            exploits = {}
            if prompt_injection_score is not None:
                exploits["prompt_injection"] = prompt_injection_score
            return Extraction(exploits=exploits, data="test")

        return _create_exploit_extraction

    def test_pii_positive_case(self, create_pii_extraction):
        """
        Test PII detection with all thresholds met:
        - 2 emails (>=0.8)
        - 1 person (1.0)
        - 1 SSN (>=0.9)
        """
        # Create extraction with required detections
        extraction = create_pii_extraction(
            email_detections=[0.85, 0.82],  # 2 emails above threshold
            person_detections=[1.0],        # 1 person at max confidence
            ssn_detections=[0.95]           # 1 SSN above threshold
        )

        # Create guard configuration
        guard_config = GuardConfig(
            [
                Guard(
                    name=GuardName.PII_DETECTOR,
                    threshold=Threshold(">= 0.8"),
                    count_threshold=3,  # Need 3 different types
                    matches={
                        "email": Match(threshold=Threshold(">= 0.8"), count_threshold=2),
                        "person": Match(threshold=Threshold(">= 1.0"), count_threshold=1),
                        "ssn": Match(threshold=Threshold(">= 0.9"), count_threshold=1)
                    }
                )
            ]
        )

        # Process
        response = Scanresponse(principal=Principal(type=PrincipalType.APP), extractions=[extraction])
        srm = ScanResponseMatch(response, guard_config, 1)
        result = srm.matches()

        # Verify
        assert result[0].response_match
        assert len(result[0].matched_checks) == 1
        assert result[0].matched_checks[0].guard_name == GuardName.PII_DETECTOR

    def test_pii_negative_count_threshold(self, create_pii_extraction):
        """
        Test PII detection with count threshold not met:
        - 1 email (>=0.8) - fails count threshold of 2
        - 1 person (1.0)
        - 1 SSN (>=0.9)
        """
        # Create extraction with insufficient email count
        extraction = create_pii_extraction(
            email_detections=[0.85],        # Only 1 email
            person_detections=[1.0],        # 1 person at max confidence
            ssn_detections=[0.95]           # 1 SSN above threshold
        )

        # Create guard configuration (same as positive case)
        guard_config = GuardConfig(
            [
                Guard(
                    name=GuardName.PII_DETECTOR,
                    threshold=Threshold(">= 0.8"),
                    count_threshold=3,
                    matches={
                        "email": Match(threshold=Threshold(">= 0.8"), count_threshold=2),
                        "person": Match(threshold=Threshold(">= 1.0"), count_threshold=1),
                        "ssn": Match(threshold=Threshold(">= 0.9"), count_threshold=1)
                    }
                )
            ]
        )

        # Process
        response = Scanresponse(principal=Principal(type=PrincipalType.APP), extractions=[extraction])
        srm = ScanResponseMatch(response, guard_config, 1)
        result = srm.matches()

        # Verify
        assert not result[0].response_match
        assert len(result[0].matched_checks) == 0

    def test_prompt_injection_positive(self, create_exploit_extraction):
        """Test prompt injection detection above threshold"""
        # Create extraction with high confidence prompt injection
        extraction = create_exploit_extraction(prompt_injection_score=0.85)

        # Create guard configuration
        guard_config = GuardConfig(
            [
                Guard(
                    name=GuardName.PROMPT_INJECTION,
                    threshold=Threshold(">= 0.8"),
                    matches={}
                )
            ]
        )

        # Process
        response = Scanresponse(principal=Principal(type=PrincipalType.APP), extractions=[extraction])
        srm = ScanResponseMatch(response, guard_config, 1)
        result = srm.matches()

        # Verify
        assert result[0].response_match
        assert len(result[0].matched_checks) == 1
        assert result[0].matched_checks[0].guard_name == GuardName.PROMPT_INJECTION

    def test_prompt_injection_negative(self, create_exploit_extraction):
        """Test prompt injection detection below threshold"""
        # Create extraction with low confidence prompt injection
        extraction = create_exploit_extraction(prompt_injection_score=0.75)

        # Create guard configuration
        guard_config = GuardConfig(
            [
                Guard(
                    name=GuardName.PROMPT_INJECTION,
                    threshold=Threshold(">= 0.8"),
                    matches = {}
                )
            ]
        )

        # Process
        response = Scanresponse(principal=Principal(type=PrincipalType.APP), extractions=[extraction])
        srm = ScanResponseMatch(response, guard_config, 1)
        result = srm.matches()

        # Verify
        assert len(result) == 1
        assert not result[0].response_match
        assert len(result[0].matched_checks) == 0

    def test_combined_pii_and_prompt_injection(self, create_pii_extraction, create_exploit_extraction):
        """Test both PII and prompt injection detection together"""
        # Create PII extraction
        pii_extraction = create_pii_extraction(
            email_detections=[0.85, 0.82],
            person_detections=[1.0],
            ssn_detections=[0.95]
        )

        # Create exploit extraction with prompt injection
        exploit_extraction = create_exploit_extraction(prompt_injection_score=0.85)

        # Combine extractions
        combined_extraction = Extraction(
            detections=pii_extraction.detections,
            pi_is=pii_extraction.pi_is,
            exploits=exploit_extraction.exploits,
            data="test"
        )

        # Create combined guard configuration
        guard_config = GuardConfig(
            [
                Guard(
                    name=GuardName.PROMPT_INJECTION,
                    threshold=Threshold(">= 0.8"),
                    matches={}
                ),
                Guard(
                    name=GuardName.PII_DETECTOR,
                    threshold=Threshold(">= 0.8"),
                    count_threshold=3,
                    matches={
                        "email": Match(threshold=Threshold(">= 0.8"), count_threshold=2),
                        "person": Match(threshold=Threshold(">= 1.0"), count_threshold=1),
                        "ssn": Match(threshold=Threshold(">= 0.9"), count_threshold=1)
                    }
                )
            ]
        )

        # Process
        response = Scanresponse(principal=Principal(type=PrincipalType.APP), extractions=[combined_extraction])
        srm = ScanResponseMatch(response, guard_config, 1)
        result = srm.matches()

        # Verify both were detected
        assert result[0].response_match
        assert len(result[0].matched_checks) == 2
        guard_names = {check.guard_name for check in result[0].matched_checks}
        assert guard_names == {GuardName.PII_DETECTOR, GuardName.PROMPT_INJECTION}

    def test_mixed_thresholds_with_partial_matches(
    self,
        create_pii_extraction,
        create_exploit_extraction
    ):
        """
        Complex scenario 1: Mixed threshold matches where some pass and some fail
        - PII: Only 2 types qualify (email and SSN, person fails)
        - Prompt injection: Passes
        - Multiple high-confidence but insufficient count emails
        Expected: Only prompt injection should match
        """
        # Create PII extraction with:
        # - 3 high confidence emails (above threshold but won't matter as person fails)
        # - 1 person with too low confidence
        # - 1 SSN above threshold
        pii_extraction = create_pii_extraction(
            email_detections=[0.95, 0.2, 0.10],  # 3 high confidence emails
            person_detections=[0.95],              # Person below required 1.0
            ssn_detections=[0.95]                  # SSN above threshold
        )

        # Create exploit extraction with high confidence
        exploit_extraction = create_exploit_extraction(prompt_injection_score=0.85)

        # Combine extractions
        combined_extraction = Extraction(
            detections=pii_extraction.detections,
            pi_is=pii_extraction.pi_is,
            exploits=exploit_extraction.exploits,
            data="test"
        )

        # Create guard configuration
        guard_config = GuardConfig(
            [
                Guard(
                    name=GuardName.PROMPT_INJECTION,
                    threshold=Threshold(">= 0.8"),
                    matches={}
                ),
                Guard(
                    name=GuardName.PII_DETECTOR,
                    threshold=Threshold(">= 0.8"),
                    count_threshold=3,  # Needs all 3 types to qualify
                    matches={
                        "email": Match(threshold=Threshold(">= 0.8"), count_threshold=2),
                        "person": Match(threshold=Threshold(">= 1.0"), count_threshold=1),  # Must be exactly 1.0
                        "ssn": Match(threshold=Threshold(">= 0.9"), count_threshold=1)
                    }
                )
            ]
        )

        # Process
        response = Scanresponse(principal=Principal(type=PrincipalType.APP),extractions=[combined_extraction])
        srm = ScanResponseMatch(response, guard_config, 1)
        result = srm.matches()

        # Verify
        assert not result[0].response_match  # Overall no because only prompt injection met the match
        assert len(result[0].matched_checks) == 1
        assert result[0].matched_checks[0].guard_name == GuardName.PROMPT_INJECTION

        # Verify all checks contains both results
        assert len(result[0].all_checks) == 2
        pii_check = next(check for check in result[0].all_checks if check.guard_name == GuardName.PII_DETECTOR)
        assert not pii_check.response_match

    def test_multiple_guards_edge_cases(
        self,
        create_pii_extraction,
        create_exploit_extraction
    ):
        """
        Complex scenario 2: Multiple guards with edge cases
        - PII: Exactly meets minimum thresholds
        - Prompt injection: Just below threshold
        - Add toxic check: Just above threshold
        Expected: PII and toxic should match, prompt injection should fail
        """
        # Create PII extraction with exactly meeting thresholds
        pii_extraction = create_pii_extraction(
            email_detections=[0.80, 0.80],  # Exactly meets email threshold
            person_detections=[1.0],        # Exactly meets person threshold
            ssn_detections=[0.90]           # Exactly meets SSN threshold
        )

        # Create exploit extraction with borderline cases
        exploit_extraction = create_exploit_extraction(prompt_injection_score=0.79)  # Just below threshold

        # Combine extractions and add toxic
        combined_extraction = Extraction(
            detections=pii_extraction.detections,
            pi_is=pii_extraction.pi_is,
            exploits=exploit_extraction.exploits,
            topics={
                "content/toxic": 0.81  # Just above threshold
            },
            data="test"
        )

        # Create guard configuration with three different types
        guard_config = GuardConfig(
            [
                Guard(
                    name=GuardName.PROMPT_INJECTION,
                    threshold=Threshold(">= 0.8"),
                    matches={}
                ),
                Guard(
                    name=GuardName.TOXIC,
                    threshold=Threshold(">= 0.8"),
                    matches={}
                ),
                Guard(
                    name=GuardName.PII_DETECTOR,
                    threshold=Threshold(">= 0.8"),
                    count_threshold=3,
                    matches={
                        "email": Match(threshold=Threshold(">= 0.8"), count_threshold=2),
                        "person": Match(threshold=Threshold(">= 1.0"), count_threshold=1),
                        "ssn": Match(threshold=Threshold(">= 0.9"), count_threshold=1)
                    }
                )
            ]
        )

        # Process
        response = Scanresponse(principal=Principal(type=PrincipalType.APP), extractions=[combined_extraction])
        srm = ScanResponseMatch(response, guard_config, 1)
        result = srm.matches()

        # Verify
        assert not result[0].response_match
        assert len(result[0].matched_checks) == 2

        # Verify specific guards
        guard_names = {check.guard_name for check in result[0].matched_checks}
        assert guard_names == {GuardName.PII_DETECTOR, GuardName.TOXIC}

        # Verify all checks contains all three results
        assert len(result[0].all_checks) == 3

        # Verify individual check results
        for check in result[0].all_checks:
            if check.guard_name == GuardName.PROMPT_INJECTION:
                assert not check.response_match
                assert check.score == 0.79
            elif check.guard_name == GuardName.TOXIC:
                assert check.response_match
                assert check.score == 0.81
            elif check.guard_name == GuardName.PII_DETECTOR:
                assert check.response_match
