from typing import Optional, Tuple, Union

from acuvity.guard.config import Guard
from acuvity.guard.constants import GuardName
from acuvity.models.extraction import Extraction
from acuvity.response.constants import (
    DETECTIONTYPE_MAP,
    GUARD_TYPES,
    GUARDNAME_TO_DETECTIONTYPE,
    TOPIC_PREFIXES,
    GuardType,
)
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
        guard_type = GUARD_TYPES.get(guard.name)
        if not guard_type:
            raise ResponseValidationError(f"Unknown guard type: {guard.name}")

        value_getters = {
            GuardType.EXPLOIT: self._get_guard_value,
            GuardType.TOPIC: self._get_guard_value,
            GuardType.LANGUAGE: self._get_language_value,
            GuardType.MODALITY: self._get_modality_value,
            GuardType.PII: self.get_text_detections,
            GuardType.SECRETS: self.get_text_detections,
            GuardType.KEYWORD: self.get_text_detections,
        }

        getter = value_getters.get(guard_type)
        if not getter:
            raise ResponseValidationError(f"No handler for guard type: {guard_type}")

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

        prefix = TOPIC_PREFIXES.get(guard.name)
        if not prefix:
            if not extraction.exploits:
                return False , 0.0
            value = extraction.exploits.get(str(guard.name))
            if value is None:
                return False, 0
            return True, float(value)
        else:
            if not extraction.topics:
                return False, 0
            value = extraction.topics.get(prefix)
            if value is not None:
                return True, float(value)
            return False, 0.0


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


    def get_text_detections(
            self,
            extraction: Extraction,
            guard: Guard,
            match_name: Optional[str]
    )-> tuple[bool, float, int]:

        detection_type = GUARDNAME_TO_DETECTIONTYPE.get(guard.name)
        if not detection_type:
            raise ResponseValidationError(f"No matching detection type for guard: {guard.name}")

        # Get the field name for this detection type
        field_name = DETECTIONTYPE_MAP.get(detection_type)
        if not field_name:
            raise ResponseValidationError(f"No matching field for detection type: {detection_type}")

        # Get the relevant match_keys dictionary using getattr
        match_keys = getattr(extraction, field_name, {}) or {}
        detections = extraction.detections or []

        if not match_keys and not detections:
            return False, 0, 0

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
            # If no textual detections, check `match_keys` for the match
            if count == 0 and match_keys and match_name in match_keys:
                return True, match_keys[match_name], 1

            if count == 0:
                return False, 0, 0

            score = max(text_matches)
            return True, score, count

        # Return all text match values if no match_name is provided
        exists = bool(match_keys)
        count = len(match_keys) if match_keys else 0
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
