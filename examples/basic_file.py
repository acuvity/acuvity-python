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
config_path = os.path.join(SCRIPT_DIR, "configs", "simple_default_guard_config.yaml")

print("--------------------------------------------------------------------------------")
print("Scenario: single file with prompt injection detection")
matches = s.apex.scan(files=file_path).matches()
print("Input:\n", file_path)
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
matches = s.apex.scan(files=file_path, guard_config=guard_config).matches()
print("Input:\n", file_path)
print("Config:\n", guard_config)
print("Matches:\n", matches)


print("--------------------------------------------------------------------------------")
print("Scenario: single file with prompt injection detection and guard config in a variable")
gc = [
    Guard.create(GuardName.PROMPT_INJECTION)
]
matches = s.apex.scan(files=file_path, guard_config=gc).matches()
print("Input:\n", file_path)
print("Config:\n", gc)
print("Matches:\n", matches)


print("--------------------------------------------------------------------------------")
print("Scenario: single file with prompt injection detection and guard config")
matches = s.apex.scan(files=file_path, guard_config=config_path).matches()
print("Input:\n", file_path)
print("Config:\n", config_path)
print("Matches:\n", matches)
