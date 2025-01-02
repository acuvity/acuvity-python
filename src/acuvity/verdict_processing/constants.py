from enum import Enum


class Verdict(str, Enum):
    """Enumeration for check verdicts."""
    PASS = "PASS"
    FAIL = "FAIL"

class ThresholdOperator(str, Enum):
    """Enumeration for threshold comparison operators."""
    GREATER_THAN = ">"
    GREATER_THAN_OR_EQUAL = ">="
    LESS_THAN = "<"
    LESS_THAN_OR_EQUAL = "<="
    EQUAL = "="

# Default action for guards
DEFAULT_ACTION = "deny"

# Base section mapping for each guard
GUARD_TO_SECTION = {
    # Exploits section
    'prompt_injection': 'exploits',
    'jail_break': 'exploits',
    'malicious_url': 'exploits',

    # Topics section guards
    'toxicity': 'topics',
    'bias': 'topics',
    'harmful_content': 'topics',
    'image_classifier': 'topics',
    'corporate_classifier': 'topics',
    'content_classifier': 'topics',

    # Languages section
    'gibberish': 'languages',
    'language': 'languages',

    # Other sections
    'modality': 'modalities',
    'pii_detector': 'piis',
    'pattern_detector': 'detections',
    'generic_classifier': 'intent'
}

# Special prefixes for topics section
TOPIC_PREFIXES = {
    'toxicity': 'content/toxic',
    'bias': 'content/bias',
    'harmful_content': 'content/harmful',
    'image_classifier': 'image',
    'corporate_classifier': 'department',
    'content_classifier': 'category'
}
