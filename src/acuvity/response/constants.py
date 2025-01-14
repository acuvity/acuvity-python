from typing import Dict


from ..guard.constants import GuardName

# Default action for guards
DEFAULT_ACTION = "deny"

guardname_analyzer_id_map: Dict[GuardName, str] = {
    # Exploit guards
    GuardName.PROMPT_INJECTION: 'en-text-prompt_injection-detector',
    GuardName.JAIL_BREAK: 'en-text-jailbreak-detector',
    GuardName.MALICIOUS_URL: 'url-malicious-detector',

    # Topic guards with prefixes
    GuardName.TOXICITY: 'en-text-toxicity-detector',
    GuardName.BIAS: 'en-text-bias-detector',
    GuardName.HARMFUL_CONTENT: 'en-text-harmful-content-detector',

    # Other guards
    GuardName.LANGUAGE: 'text-language-classifier',
    GuardName.PII_DETECTOR: 'en-text-ner-detector',
    GuardName.SECRETS_DETECTOR:'text-pattern-detector',
    GuardName.KEYWORD_DETECTOR: 'text-keyword-detector',
    GuardName.MODALITY: 'modality-detector',
}