import os

from rich import print

import acuvity
from acuvity import Acuvity, Guard, GuardName

s = Acuvity(
    # not required at all if set in environment variables
    security=acuvity.Security(
       token=os.getenv("ACUVITY_TOKEN", ""),
    )
)

print("--------------------------------------------------------------------------------")
print("Scenario: single prompt with gibberish detection")
gibberish_text = "hjasdgfabfjkfabfkjabfajkbfkjbfjkbafhbajfjkuf"
gc = [Guard.create(GuardName.LANGUAGE)]
matches = s.apex.scan(gibberish_text, guard_config=gc).matches()
print("Input:\n", gibberish_text)
print("Config:\n", gc)
print("Matches:\n", matches)
