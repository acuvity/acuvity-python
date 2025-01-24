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
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

file_path = os.path.join(SCRIPT_DIR, "test_data", "pi-test.txt")
config_path = os.path.join(SCRIPT_DIR, "configs", "pii_detailed_guard_config.yaml")

input_messages = [
    "corporate sales number are 10k filling, in.abcd@gmail.com, 123abcd@yahoo.com hate you, 792-77-3459, 792-77-3453, 792-77-3454",
]

print("--------------------------------------------------------------------------------")
print("Scenario: single pii prompts with pii guard config")
matches = s.apex.scan(*input_messages, guard_config=config_path).matches()
print("Input:\n", input_messages)
print("Config:\n", "default")
print("Matches:\n", matches)
