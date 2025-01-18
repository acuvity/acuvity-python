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
print("Scenario: single file with prompt injection detection")
file="./test_data/pi-test.txt"
matches = s.apex.scan(files=file).matches()
print("Input:\n", file)
print("Config:\n", "default")
print("Matches:\n", matches)


print("--------------------------------------------------------------------------------")
print("Scenario: single file with prompt injection detection and guard config in a dictionary variable")
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
        }
    ]
}
matches = s.apex.scan(files=file, guard_config=guard_config).matches()
print("Input:\n", file)
print("Config:\n", guard_config)
print("Matches:\n", matches)


print("--------------------------------------------------------------------------------")
print("Scenario: single file with prompt injection detection and guard config in a variable")
gc = [
    Guard.create(GuardName.PROMPT_INJECTION)
]
matches = s.apex.scan(files=file, guard_config=gc).matches()
print("Input:\n", file)
print("Config:\n", gc)
print("Matches:\n", matches)


print("--------------------------------------------------------------------------------")
print("Scenario: single file with prompt injection detection and guard config")
file="./test_data/pi-test.txt"
config="./configs/simple_default_guard_config.yaml"
matches = s.apex.scan(files=file, guard_config=config).matches()
print("Input:\n", file)
print("Config:\n", config)
print("Matches:\n", matches)
