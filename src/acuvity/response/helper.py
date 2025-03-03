from typing import Dict, List, Optional, Union

from acuvity.guard.config import Guard
from acuvity.guard.constants import GuardName
from acuvity.models.extraction import Extraction
from acuvity.models.textualdetection import Textualdetection, TextualdetectionType
from acuvity.response.result import GuardMatch, ResponseMatch
from acuvity.utils.logger import get_default_logger

logger = get_default_logger()

class ResponseHelper:
    """Parser for accessing values in Extraction response based on guard types."""

    @staticmethod
    def evaluate(
        extraction: Extraction,
        guard: Guard,
        match_name: Optional[str] = None
    ) -> GuardMatch:
        """
        Evaluates a check condition using a Guard object.

        Args:
            extraction: A type which provides all the extractions based on the detection engine.
            guard: A guard configuration
            match_name: The match match for the guard

        Returns:
            GuardMatch with MATCH.YES if condition met, MATCH>NO if not met
        """
        exists = False
        value = -1
        match_count = 0
        match_list: List[str] = []
        if guard.name in (GuardName.PROMPT_INJECTION, GuardName.JAILBREAK, GuardName.MALICIOUS_URL):
            exists, value = ResponseHelper._get_guard_value(extraction.exploits, str(guard.name))
        elif guard.name in (GuardName.TOXIC, GuardName.BIASED, GuardName.HARMFUL):
            exists, value = ResponseHelper._get_guard_value(extraction.malcontents, str(guard.name))
        elif guard.name == GuardName.LANGUAGE:
            # Language guard
            if match_name:
                exists, value = ResponseHelper._get_guard_value(extraction.languages, match_name)
            elif extraction.languages:
                exists, value = len(extraction.languages) > 0 , 1.0
        elif guard.name == GuardName.MODALITY:
            exists = ResponseHelper._get_modality_value(extraction, guard, match_name)
        elif guard.name == GuardName.PII_DETECTOR:
            exists, value, match_count, match_list = ResponseHelper._get_text_detections(extraction.pi_is, guard, TextualdetectionType.PII, extraction.detections, match_name)
        elif guard.name == GuardName.SECRETS_DETECTOR:
            exists, value, match_count, match_list = ResponseHelper._get_text_detections(extraction.secrets, guard, TextualdetectionType.SECRET, extraction.detections, match_name)
        elif guard.name == GuardName.KEYWORD_DETECTOR:
            exists, value, match_count, match_list = ResponseHelper._get_text_detections(extraction.keywords, guard, TextualdetectionType.KEYWORD, extraction.detections, match_name)

        # A match is found if the the detection exists value is greater than the threshold
        response_match=ResponseMatch.NO
        if exists and guard.threshold.compare(value):
            response_match=ResponseMatch.YES

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
        lookup: Union[Dict[str, float] , None],
        prefix: str,
    ) -> tuple[bool, float]:
        if not lookup:
            return False, 0
        value = lookup.get(prefix)
        if value is not None:
            return True, float(value)
        return False, 0.0

    @staticmethod
    def _get_text_detections(
        lookup: Union[Dict[str, float] , None],
        guard: Guard,
        detection_type: TextualdetectionType,
        detections: Union[List[Textualdetection], None],
        match_name: Optional[str]
    )-> tuple[bool, float, int, List[str]]:

        if match_name:
            # Count occurrences in textual detections
            if not detections:
                return False, 0, 0, []
            text_matches = []
            text_matches = [
                d.score for d in detections
                if d.type == detection_type and d.name == match_name and d.score is not None  and guard.threshold.compare(d.score)
            ]

            count = len(text_matches)
            # If no textual detections, check `lookup` for the match
            if count == 0 and lookup and match_name in lookup:
                return True, lookup[match_name], 1, [match_name]

            if count == 0:
                return False, 0, 0, []

            score = max(text_matches)
            return True, score, count, [match_name]

        # Return all text match values if no match_name is provided
        exists = bool(lookup)
        count = len(lookup) if lookup else 0
        return exists, 1.0 if exists else 0.0, count, list(lookup.keys()) if lookup else []

    @staticmethod
    def _get_modality_value(
        extraction: Extraction,
        _: Guard,
        match_name: Optional[str] = None
    ) -> bool:
        if not extraction.modalities:
            return False  # No modalities at all

        if match_name:
            # Check for specific modality
            return any(m.group == match_name for m in extraction.modalities)

        # Check if any modality exists
        return len(extraction.modalities) > 0
