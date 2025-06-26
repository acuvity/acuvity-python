from typing import Dict, List, Optional, Union

from acuvity.guard.config import Guard
from acuvity.guard.constants import GuardName
from acuvity.models.extraction import Extraction
from acuvity.models.textualdetection import Textualdetection, TextualdetectionType
from acuvity.response.result import GuardMatch, ResponseMatch
from acuvity.utils.logger import get_default_logger

logger = get_default_logger()

class ResponseHelper:
    """
    Parser for evaluating content against different types of guards/filters.
    Handles various detection types (exploits, PII, keywords, etc.) with configurable thresholds.
    """

    @staticmethod
    def evaluate(
        extraction: Extraction,
        guard: Guard,
        match_name: Optional[str] = None
    ) -> GuardMatch:
        """
        Evaluates extracted content against a specific guard configuration.

        Args:
            extraction: Contains all detected content from the detection engine
            guard: Configuration defining what to check for and threshold values
            match_name: Optional specific pattern/entity name to check for

        Returns:
            GuardMatch object indicating whether the check passed/failed and related metadata
        """
        exists = False
        value = 0.0
        match_count = 0
        match_list: List[str] = []

        # Dispatch to appropriate handler based on guard type
        if guard.name in (GuardName.PROMPT_INJECTION, GuardName.JAILBREAK, GuardName.MALICIOUS_URL):
            # Security-related checks
            exists, value = ResponseHelper._get_guard_value(extraction.exploits, str(guard.name))
        elif guard.name in (GuardName.TOXIC, GuardName.BIASED, GuardName.HARMFUL):
            # Content quality/safety checks
            exists, value = ResponseHelper._get_guard_value(extraction.malcontents, str(guard.name))
        elif guard.name == GuardName.LANGUAGE:
            # Language detection - check specific language or any language
            if match_name:
                exists, value = ResponseHelper._get_guard_value(extraction.languages, match_name)
            elif extraction.languages:
                exists, value = len(extraction.languages) > 0 , 1.0
        elif guard.name == GuardName.MODALITY:
            # Check for specific content modalities (text, image, etc.)
            exists = ResponseHelper._get_modality_value(extraction, guard, match_name)
        elif guard.name == GuardName.PII_DETECTOR:
            # Personal Identifiable Information detection
            exists, value, match_count, match_list = ResponseHelper._get_text_detections(
                extraction.pi_is, guard, TextualdetectionType.PII, extraction.detections, match_name
            )
        elif guard.name == GuardName.SECRETS_DETECTOR:
            # Secrets detection (API keys, passwords, etc.)
            exists, value, match_count, match_list = ResponseHelper._get_text_detections(
                extraction.secrets, guard, TextualdetectionType.SECRET, extraction.detections, match_name
            )
        elif guard.name == GuardName.KEYWORD_DETECTOR:
            # Custom keyword matching
            exists, value, match_count, match_list = ResponseHelper._get_text_detections(
                extraction.keywords, guard, TextualdetectionType.KEYWORD, extraction.detections, match_name
            )

        # Determine if the check passed based on threshold configuration
        response_match = ResponseMatch.NO
        if exists and guard.threshold.compare(value):
            response_match = ResponseMatch.YES

        # Only return positive values for matches
        if response_match is ResponseMatch.NO:
            value = -1

        if response_match is ResponseMatch.NO:
            value = -1

        return GuardMatch(
            response_match=response_match,
            guard_name=guard.name,
            threshold=str(guard.threshold),
            actual_value=value,
            match_count=match_count,
            match_values=match_list
        )

    @staticmethod
    def _get_guard_value(
        lookup: Union[Dict[str, float], None],
        prefix: str,
    ) -> tuple[bool, float]:
        """
        Extract a specific guard value from a dictionary of scores.

        Returns:
            Tuple of (exists, score) where exists is True if match found
        """
        if not lookup:
            return False, 0
        value = lookup.get(prefix)
        if value is not None:
            return True, float(value)
        return False, 0.0

    @staticmethod
    def _get_text_detections(
        lookup: Union[Dict[str, float], None],
        guard: Guard,
        detection_type: TextualdetectionType,
        detections: Union[List[Textualdetection], None],
        match_name: Optional[str]
    ) -> tuple[bool, float, int, List[str]]:
        """
        Process text-based detections (PII, secrets, keywords).

        Handles both specific pattern matching (when match_name provided)
        and general detection reporting.

        Returns:
            Tuple of (exists, score, count, match_list)
        """
        if match_name:
            # Looking for a specific pattern/entity
            if not detections:
                return False, 0, 0, []

            # Find all matching detections that exceed the threshold
            text_matches = [
                d.score for d in detections
                if d.type == detection_type and d.name == match_name and d.score is not None and guard.threshold.compare(d.score)
            ]

            count = len(text_matches)

            # If no textual detections found, check lookup dictionary as fallback
            if count == 0 and lookup and match_name in lookup:
                return True, lookup[match_name], 1, [match_name]

            if count == 0:
                return False, 0, 0, []

            # Return highest confidence score if multiple matches
            score = max(text_matches)
            return True, score, count, [match_name]

        # No specific match requested - return all matches for this detection type
        exists = bool(lookup)
        count = len(lookup) if lookup else 0
        return exists, 1.0 if exists else 0.0, count, list(lookup.keys()) if lookup else []

    @staticmethod
    def _get_modality_value(
        extraction: Extraction,
        _: Guard,
        match_name: Optional[str] = None
    ) -> bool:
        """
        Check if specific or any content modality exists in the extraction.

        Returns:
            Boolean indicating if the modality check passed
        """
        if not extraction.modalities:
            return False  # No modalities at all

        if match_name:
            # Check for specific modality
            return any(m.group == match_name for m in extraction.modalities)

        # Check if any modality exists
        return len(extraction.modalities) > 0
