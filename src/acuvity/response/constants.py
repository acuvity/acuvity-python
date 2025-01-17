from acuvity.guard.constants import GuardName
from acuvity.models.textualdetection import TextualdetectionType

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
