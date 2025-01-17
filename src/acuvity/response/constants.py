from acuvity.guard.constants import GuardName

# Topic prefixes mapping
TOPIC_PREFIXES = {
    GuardName.TOXIC: 'content/toxic',
    GuardName.BIASED: 'content/biased',
    GuardName.HARMFUL: 'content/harmful',
}