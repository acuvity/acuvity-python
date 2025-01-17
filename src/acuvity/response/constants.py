from enum import Enum, auto
from typing import Dict

from acuvity.guard.constants import GuardName
from acuvity.models.textualdetection import TextualdetectionType

# Default action for guards
DEFAULT_ACTION = "deny"

class GuardType(Enum):
    """Types of guards and their corresponding sections in Extraction."""
    EXPLOIT = auto()         # Direct access in exploits
    TOPIC = auto()           # Needs prefix in topics
    LANGUAGE = auto()        # Can be direct or match-based
    PII = auto()             # Both direct values and textual detection counts
    SECRETS = auto()         # In secrets section
    KEYWORD = auto()         # In textual detections with count
    MODALITY = auto()        # Special handling for modalities list

# Define mappings
GUARD_TYPES = {
    # Exploit guards
    GuardName.PROMPT_INJECTION: GuardType.EXPLOIT,
    GuardName.JAIL_BREAK: GuardType.EXPLOIT,
    GuardName.MALICIOUS_URL: GuardType.EXPLOIT,

    # Topic guards with prefixes
    GuardName.TOXICITY: GuardType.TOPIC,
    GuardName.BIAS: GuardType.TOPIC,
    GuardName.HARMFUL_CONTENT: GuardType.TOPIC,

    # Other guards
    GuardName.LANGUAGE: GuardType.LANGUAGE,
    GuardName.PII_DETECTOR: GuardType.PII,
    GuardName.SECRETS_DETECTOR: GuardType.SECRETS,
    GuardName.KEYWORD_DETECTOR: GuardType.KEYWORD,
    GuardName.MODALITY: GuardType.MODALITY
}

# Topic prefixes mapping
TOPIC_PREFIXES = {
    GuardName.TOXICITY: 'content/toxic',
    GuardName.BIAS: 'content/bias',
    GuardName.HARMFUL_CONTENT: 'content/harmful',
}

DETECTIONTYPE_MAP = {
    TextualdetectionType.KEYWORD : "keywords",
    TextualdetectionType.PII: "pi_is",
    TextualdetectionType.SECRET : "secrets"
}

GUARDNAME_TO_DETECTIONTYPE = {
    GuardName.KEYWORD_DETECTOR : TextualdetectionType.KEYWORD,
    GuardName.SECRETS_DETECTOR: TextualdetectionType.SECRET,
    GuardName.PII_DETECTOR: TextualdetectionType.PII,
    GuardName.LANGUAGE: "language",
}
