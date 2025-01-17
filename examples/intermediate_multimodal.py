import os

from rich import print

import acuvity
from acuvity import Acuvity

s = Acuvity(
    # not required at all if set in environment variables
    security=acuvity.Security(
       token=os.getenv("ACUVITY_TOKEN", ""),
    )
)

print("---------------------------------------------------------------------------------------------------------------")
print("Scenario: multimodal with multiple text prompts and file with guard config in a variable")
input_messages = [
    "corporate sales number are 10k filling, in.abcd@gmail.com, 123abcd@yahoo.com hate you, 792-77-3459, 792-77-3453, 792-77-3454",
    "hello how are you",
]
file="./examples/test_data/pi-test.txt"
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
matches = s.apex.scan(*input_messages, files=file, guard_config=guard_config).matches()
print("Input:\n", input_messages, file)
print("Matches:\n", matches)

print("---------------------------------------------------------------------------------------------------------------")
print("Scenario: multimodal with multiple text prompts and file with guard config")
matches = s.apex.scan(*input_messages, files=file, guard_config="./examples/configs/simple_default_guard_config.yaml").matches()
print("Input:\n", input_messages)
print("Matches:\n", matches)
