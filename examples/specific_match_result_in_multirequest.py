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

guard_config = {
    "guardrails": [
        {
            "name": "prompt_injection",
            "threshold": ">= 0.2"
        },
        {
            "name": "jailbreak",
            "threshold": ">= 0.7"
        },
        {
            "name": "malicious_url",
            "threshold": ">= 0.7"
        },
        {
        "name": "pii_detector",
        "count_threshold": 4,
        },
        {
            "name": "secrets_detector"
        },
        {
            "name": "biased"
        },
        {
            "name": "toxic"
        },
        {
            "name": "language"
        }
    ]
}


input_messages = [
    "corporate sales number are 10k filling, in.abcd@gmail.com, 123abcd@yahoo.com hate you, 792-77-3459, 792-77-3453, 792-77-3454",
    "hello how are you",
]
file="./test_data/pi-test.txt"

print("--------------------------------------------------------------------------------")
print("Scenario: multimodal with multiple text prompts and file with guard config in a variable to understand matches on specific guards")
response = s.apex.scan(*input_messages, files=file, guard_config=guard_config)
print("Input:\n", input_messages, file)
print("Matches:\n", response.matches())

print("--------------------------------------------------------------------------------")
# To check a specific guard match on the first file (0 based index)
print("Prompt Injection Match on first file (0 based index):\n", response.guard_match(GuardName.PROMPT_INJECTION, file_index=0))

print("--------------------------------------------------------------------------------")
# To check a specific guard match on the second text (0 based index)
print("Prompt Injection Match on second text (0 based index):\n", response.guard_match(GuardName.PROMPT_INJECTION, msg_index=1))

