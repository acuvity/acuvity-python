from acuvity.guard.constants import GuardName

# Topic prefixes mapping
TOPIC_PREFIXES = {
    GuardName.TOXICITY: 'content/toxic',
    GuardName.BIAS: 'content/bias',
    GuardName.HARMFUL_CONTENT: 'content/harmful',
}