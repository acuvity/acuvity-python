from enum import Enum, auto
from typing import Optional, Tuple, Union

from ...models.extraction import Extraction
from ..models.errors import ValidationError


class GuardType(Enum):
    """Types of guards and their corresponding sections in Extraction."""
    EXPLOIT = auto()         # Direct access in exploits
    TOPIC = auto()           # Needs prefix in topics
    LANGUAGE = auto()        # Can be direct or match-based
    INTENT = auto()          # Match-based in intent
    PII = auto()            # Both direct values and textual detection counts
    SECRETS = auto()         # In secrets section
    KEYWORD = auto()         # In textual detections with count
    MODALITY = auto()        # Special handling for modalities list

# Define mappings
GUARD_TYPES = {
    # Exploit guards
    'prompt_injection': GuardType.EXPLOIT,
    'jail_break': GuardType.EXPLOIT,
    'malicious_url': GuardType.EXPLOIT,

    # Topic guards with prefixes
    'toxicity': GuardType.TOPIC,
    'bias': GuardType.TOPIC,
    'harmful_content': GuardType.TOPIC,
    'image_classifier': GuardType.TOPIC,
    'corporate_classifier': GuardType.TOPIC,
    'content_classifier': GuardType.TOPIC,

    # Other guards
    'language': GuardType.LANGUAGE,
    'gibberish': GuardType.LANGUAGE,
    'generic_classifier': GuardType.INTENT,
    'pii_detector': GuardType.PII,
    'secrets_detector': GuardType.SECRETS,
    'keyword_detector': GuardType.KEYWORD,
    'modality': GuardType.MODALITY
}

# Topic prefixes mapping
TOPIC_PREFIXES = {
    'toxicity': 'content/toxic',
    'bias': 'content/bias',
    'harmful_content': 'content/harmful',
    'image_classifier': 'image',
    'corporate_classifier': 'department',
    'content_classifier': 'category'
}

class ResponseParser:
    """Parser for accessing values in Extraction response based on guard types."""

    def get_value(
        self,
        extraction: Extraction,
        guard_name: str,
        match_name: Optional[str] = None
    ) -> Union[bool, Tuple[bool, float], Tuple[bool, float, int]]:
        """Get value from extraction based on guard type."""
        guard_type = GUARD_TYPES.get(guard_name)
        if not guard_type:
            raise ValidationError(f"Unknown guard type: {guard_name}")

        value_getters = {
            GuardType.EXPLOIT: self._get_exploit_value,
            GuardType.TOPIC: self._get_topic_value,
            GuardType.LANGUAGE: self._get_language_value,
            GuardType.INTENT: self._get_intent_value,
            GuardType.PII: self._get_pii_value,
            GuardType.SECRETS: self._get_secrets_value,
            GuardType.KEYWORD: self._get_keyword_value,
            GuardType.MODALITY: self._get_modality_value
        }

        getter = value_getters.get(guard_type)
        if not getter:
            raise ValidationError(f"No handler for guard type: {guard_type}")

        try:
            return getter(extraction, guard_name, match_name)
        except Exception as e:
            raise ValidationError(f"Error getting value for {guard_name}: {str(e)}") from e

    def _get_exploit_value(
        self,
        extraction: Extraction,
        guard_name: str,
        _: Optional[str] = None
    ) -> tuple[bool, float]:
        """Get value from exploits section."""
        if not extraction.exploits:
            return False, 0

        value = extraction.exploits.get(guard_name)
        if value is None:
            return False, 0

        return True, float(value)

    def _get_topic_value(
        self,
        extraction: Extraction,
        guard_name: str,
        match_name: Optional[str]
    ) -> tuple[bool, float]:
        """Get value from topics section with prefix handling."""
        if not extraction.topics:
            return False, 0

        prefix = TOPIC_PREFIXES.get(guard_name)
        if not prefix:
            raise ValidationError(f"No topic prefix for {guard_name}")

        if match_name:
            # Exact match with match_name
            key = f"{prefix}/{match_name}"
            value = extraction.topics.get(key)
            if value is not None:
                return True, float(value)
            return False, 0.0
        # Look for any key starting with prefix
        for key, value in extraction.topics.items():
            if key.startswith(prefix):
                return True, float(value)
        return False, 0.0

    def _get_language_value(
        self,
        extraction: Extraction,
        guard_name: str,
        match_name: Optional[str]
    ) -> tuple[bool, float]:
        """Get value from languages section."""
        if not extraction.languages:
            return False, 0

        if guard_name == 'gibberish':
            value = extraction.languages.get('gibberish')
            if value:
                return True, value
            else:
                return False, 0.0

        if match_name:
            value = extraction.languages.get(match_name)
        else:
            return len(extraction.languages) > 0, 1.0

        if value is None:
            return False, 0
        return True, float(value)

    def _get_pii_value(
        self,
        extraction: Extraction,
        _: str,
        match_name: Optional[str]
    ) -> tuple[bool, float, int]:
        """
        Get PII values. If match_name is provided, returns count from textual detections.
        Otherwise, returns all PII values.
        """
        if not extraction.pi_is and not extraction.detections:
            return False, 0, 0

        if match_name:
            # Count occurrences in textual detections
            if not extraction.detections:
                return False, 0, 0
            pii_matches = []
            pii_matches = [
                d.score for d in extraction.detections
                if d.type == "PII" and d.name == match_name and d.score is not None
            ]

            count = len(pii_matches)
            # If no textual detections, check `pi_is` for the match
            if count == 0 and extraction.pi_is and match_name in extraction.pi_is:
                return True, extraction.pi_is[match_name], 1

            if count == 0:
                return False, 0, 0
            score = max(pii_matches)
            return True, score, count

        # Return all PII values
        # Return all PII values if no match_name is provided
        exists = bool(extraction.pi_is)
        count = len(extraction.pi_is) if extraction.pi_is else 0
        return exists, 1.0 if exists else 0.0, count

    def _get_secrets_value(
        self,
        extraction: Extraction,
        _: str,
        match_name: Optional[str]
    ) -> bool:
        """Get value from secrets section."""
        if not extraction.secrets:
            return False
        if match_name:
            value = extraction.secrets.get(match_name)
        else:
            return len(extraction.secrets) > 0

        if value is None:
            return False
        return True

    def _get_keyword_value(
        self,
        extraction: Extraction,
        _: str,
        match_name: Optional[str]
    ) -> tuple[bool, float, int]:
        """
        Get keyword detector values. Returns both the keyword confidence
        and count of occurrences.
        """
        if not extraction.detections:
            return False, 0, 0
        if not match_name:
            raise ValidationError("Match name required for keyword detector")

        # Find all detections for this keyword
        keyword_detections = [
            d.score for d in extraction.detections
            if d.type == "Keyword" and d.name == match_name and d.score is not None
        ]

        if not keyword_detections:
            return False, 0, 0
        max_score = max(keyword_detections)
        # Return count of detections
        return True, max_score, len(keyword_detections)

    def _get_intent_value(
        self,
        extraction: Extraction,
        _: str,
        match_name: Optional[str]
    ) -> tuple[bool, float]:
        """Get value from intent section."""
        if not extraction.intent:
            return False, 0
        if not match_name:
            return True, 1

        value = extraction.intent.get(match_name, 1)
        return True, float(value)

    def _get_modality_value(
        self,
        extraction: Extraction,
        _: str,
        match_name: Optional[str] = None
    ) -> bool:
        """
        Check if modality exists in the extraction.

        Args:
            extraction: The Extraction instance
            _: Unused guard name
            match_name: Optional specific modality to check for

        Returns:
            bool: True if modality exists, False if not
        """
        if not extraction.modalities:
            return False  # No modalities at all

        if match_name:
            # Check for specific modality
            return any(m.group == match_name for m in extraction.modalities)

        # Check if any modality exists
        return len(extraction.modalities) > 0
