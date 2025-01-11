from enum import Enum
from typing import Dict


class Verdict(str, Enum):
    """Enumeration for check verdicts."""
    PASS = "PASS"
    FAIL = "FAIL"

class ComparisonOperator(Enum):
    """Valid comparison operators for thresholds"""
    GREATER_THAN = '>'
    GREATER_EQUAL = '>='
    EQUAL = '=='
    LESS_EQUAL = '<='
    LESS_THAN = '<'

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

analyzer_id_name_map: Dict[str, str] = {
            'en-text-prompt_injection-detector': 'prompt_injection',
            'en-text-jailbreak-detector': 'jail_break',
            'url-malicious-detector': 'malicious_url',
            'en-text-toxicity-detector': 'toxicity',
            'en-text-bias-detector': 'bias',
            'en-text-harmful-content-detector': 'harmful_content',
            'image-classifier': 'image_classifier',
            'en-text-corporate-classifier': 'corporate_classifier',
            'en-text-content-classifier': 'content_classifier',
            'text-gibberish-classifier': 'gibberish',
            'text-language-classifier': 'language',
            'modality-detector': 'modality',
            'en-text-ner-detector': 'pii_detector',
            'text-pattern-detector': 'secrets_detector',
            'en-text-generic-classifier': 'generic_classifier',
            'text-keyword-detector': 'keyword_detector'
        }

class GuardName(Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAIL_BREAK = "jail_break"
    MALICIOUS_URL = "malicious_url"
    TOXICITY = "toxicity"
    BIAS = "bias"
    HARMFUL_CONTENT = "harmful_content"
    IMAGE_CLASSIFIER = "image_classifier"
    CORPORATE_CLASSIFIER = "corporate_classifier"
    CONTENT_CLASSIFIER = "content_classifier"
    GIBBERISH = "gibberish"
    LANGUAGE = "language"
    MODALITY = "modality"
    PII_DETECTOR = "pii_detector"
    SECRETS_DETECTOR = "secrets_detector"
    GENERIC_CLASSIFIER = "generic_classifier"
    KEYWORD_DETECTOR = "keyword_detector"
