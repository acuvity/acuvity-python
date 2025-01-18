from typing import Callable, Dict, List, Optional, Tuple, TypeAlias, Union

from acuvity.guard.config import Guard
from acuvity.guard.constants import GuardName
from acuvity.models.extraction import Extraction
from acuvity.models.textualdetection import Textualdetection, TextualdetectionType
from acuvity.response.errors import ResponseValidationError
from acuvity.response.result import GuardMatch, ResponseMatch
from acuvity.utils.logger import get_default_logger

logger = get_default_logger()

# Define the type alias at the class or module level
value_getter_type: TypeAlias = Callable[
    [Extraction, Guard, Optional[str]],
    Union[bool, Tuple[bool, float], Tuple[bool, float, int]]
]

class ResponseHelper:
    """Parser for accessing values in Extraction response based on guard types."""

    def evaluate(
        self,
        response_extraction: Extraction,
        guard: Guard,
        match_name: Optional[str] = None
    ) -> GuardMatch:
        """
        Evaluates a check condition using a Guard object.

        Args:
            response_extraction: The scan response extraction
            guard: The guard to eval with the response
            match_name: The match match for the guard

        Returns:
            GuardMatch with MATCH.YES if condition met, MATCH>NO if not met
        """
        try:
            result = self._get_value(response_extraction, guard, match_name)
            # Handle different return types
            # PII and keyword
            match_count = None
            if isinstance(result, tuple) and len(result) == 3:  # (bool, float, int)
                exists, value, match_count = result
            # exploit, topic, classification, language
            elif isinstance(result, tuple) and len(result) == 2:  # (bool, float)
                exists, value = result
            # secrets and modality
            elif isinstance(result, bool):  # bool only
                exists, value = result, 1.0
            else:
                raise ValueError("Unexpected return type from _get_value")

            if not exists:
                return GuardMatch(
                    response_match=ResponseMatch.NO,
                    guard_name=guard.name,
                    threshold=str(guard.threshold),
                    actual_value=value
                )
            # Use ThresholdHelper for comparison
            comparison_result = guard.threshold.compare(value)

            return GuardMatch(
                response_match=ResponseMatch.YES if comparison_result else ResponseMatch.NO,
                guard_name=guard.name,
                threshold=str(guard.threshold),
                actual_value=value,
                match_count=match_count if match_count else 0
            )
        except Exception as e:
            logger.debug("Error in check evaluation: %s", str(e))
            raise

    def _get_value(
        self,
        extraction: Extraction,
        guard: Guard,
        match_name: Optional[str] = None
    ) -> Union[bool, Tuple[bool, float], Tuple[bool, float, int]]:
        """Get value from extraction based on guard type."""

        value_getters : Dict[GuardName, value_getter_type] =  {
            GuardName.PROMPT_INJECTION: self._get_guard_value,
            GuardName.JAILBREAK: self._get_guard_value,
            GuardName.MALICIOUS_URL: self._get_guard_value,

            # Topic guards with prefixes
            GuardName.TOXIC: self._get_guard_value,
            GuardName.BIASED: self._get_guard_value,
            GuardName.HARMFUL: self._get_guard_value,

            # Other guards
            GuardName.LANGUAGE: self._get_language_value,
            GuardName.PII_DETECTOR: self._get_text_detections,
            GuardName.SECRETS_DETECTOR: self._get_text_detections,
            GuardName.KEYWORD_DETECTOR: self._get_text_detections,
            GuardName.MODALITY: self._get_modality_value,
        }

        getter = value_getters.get(guard.name)
        if not getter:
            raise ResponseValidationError(f"No handler for guard name: {guard.name}")

        try:
            return getter(extraction, guard, match_name)
        except Exception as e:
            raise ResponseValidationError(f"Error getting value for {guard.name}: {str(e)}") from e

    def _get_guard_value(
        self,
        extraction: Extraction,
        guard: Guard,
        _: Optional[str]
    ) -> tuple[bool, float]:
        """Get value from topics section with prefix handling."""

        if guard.name in (GuardName.TOXIC, GuardName.HARMFUL, GuardName.BIASED):
            prefix = "content/" + str(guard.name)
            if not extraction.topics:
                return False, 0
            value = extraction.topics.get(prefix)
            if value is not None:
                return True, float(value)
            return False, 0.0

        if not extraction.exploits:
            return False , 0.0
        value = extraction.exploits.get(str(guard.name))
        if value is None:
            return False, 0
        return True, float(value)

    def _get_language_value(
        self,
        extraction: Extraction,
        _: Guard,
        match_name: Optional[str]
    ) -> tuple[bool, float]:
        """Get value from languages section."""
        if not extraction.languages:
            return False, 0

        if match_name:
            value = extraction.languages.get(match_name)
        else:
            return len(extraction.languages) > 0 , 1.0

        if value is None:
            return False, 0
        return True, float(value)

    def _get_text_detections(
        self,
        extraction: Extraction,
        guard: Guard,
        match_name: Optional[str]
    )-> tuple[bool, float, int]:

        if guard.name == GuardName.KEYWORD_DETECTOR:
            return self._get_text_detections_type(extraction.keywords, guard, TextualdetectionType.KEYWORD, extraction.detections, match_name)
        if guard.name == GuardName.SECRETS_DETECTOR:
            return self._get_text_detections_type(extraction.secrets, guard, TextualdetectionType.SECRET, extraction.detections, match_name)
        if guard.name == GuardName.PII_DETECTOR:
            return self._get_text_detections_type(extraction.pi_is, guard, TextualdetectionType.PII, extraction.detections, match_name)
        return False, 0, 0

    def _get_text_detections_type(
        self,
        lookup: Union[Dict[str, float] , None],
        guard: Guard,
        detection_type: TextualdetectionType,
        detections: Union[List[Textualdetection], None],
        match_name: Optional[str]
    )-> tuple[bool, float, int]:

        if match_name:
            # Count occurrences in textual detections
            if not detections:
                return False, 0, 0
            text_matches = []
            text_matches = [
                d.score for d in detections
                if d.type == detection_type and d.name == match_name and d.score is not None  and guard.threshold.compare(d.score)
            ]

            count = len(text_matches)
            # If no textual detections, check `lookup` for the match
            if count == 0 and lookup and match_name in lookup:
                return True, lookup[match_name], 1

            if count == 0:
                return False, 0, 0

            score = max(text_matches)
            return True, score, count

        # Return all text match values if no match_name is provided
        exists = bool(lookup)
        count = len(lookup) if lookup else 0
        return exists, 1.0 if exists else 0.0, count

    def _get_modality_value(
        self,
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
