from typing import Optional, Tuple, Union, Dict, List

from acuvity.guard.config import Guard
from acuvity.guard.constants import GuardName
from acuvity.models.extraction import Extraction
from acuvity.models.textualdetection import Textualdetection, TextualdetectionType

from acuvity.response.errors import ResponseValidationError


class ResponseParser:
    """Parser for accessing values in Extraction response based on guard types."""

    def get_value(
        self,
        extraction: Extraction,
        guard: Guard,
        match_name: Optional[str] = None
    ) -> Union[bool, Tuple[bool, float], Tuple[bool, float, int]]:
        """Get value from extraction based on guard type."""

        value_getters = {
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

        if guard.name == GuardName.TOXIC or guard.name == GuardName.HARMFUL or guard.name == GuardName.BIASED:
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
        elif guard.name == GuardName.SECRETS_DETECTOR:
            return self._get_text_detections_type(extraction.secrets, guard, TextualdetectionType.SECRET, extraction.detections, match_name)
        elif guard.name == GuardName.PII_DETECTOR:
            return self._get_text_detections_type(extraction.pi_is, guard, TextualdetectionType.PII, extraction.detections, match_name)
        return False, 0, 0

    def _get_text_detections_type(
        self,
        lookup: Dict[str, float] | None,
        guard: Guard,
        detection_type: TextualdetectionType,
        detections: List[Textualdetection] | None,
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
        _: GuardName,
        match_name: Optional[str] = None
    ) -> bool:
        if not extraction.modalities:
            return False  # No modalities at all

        if match_name:
            # Check for specific modality
            return any(m.group == match_name for m in extraction.modalities)

        # Check if any modality exists
        return len(extraction.modalities) > 0
