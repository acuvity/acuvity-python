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

input_messages = [
    "corporate sales number are 10k filling, in.abcd@gmail.com, 123abcd@yahoo.com hate you, 792-77-3459, 792-77-3453, 792-77-3454",
    "hello how are you",
]

print("--------------------------------------------------------------------------------")
print("Scenario: multiple prompts")
matches = s.apex.scan(*input_messages).matches()
print("Input:\n", input_messages)
print("Config:\n", "default")
print("Matches:\n", matches)


print("--------------------------------------------------------------------------------")
print("Scenario: multiple prompts with guard config as a dictionary variable")
guard_config = {
    "guardrails": [
        {
            "name": "prompt_injection",
            "threshold": ">= 0.2"
        },
        {
            "name": "pii_detector",
            "count_threshold": 4,
        }
    ]
}
matches = s.apex.scan(*input_messages, guard_config=guard_config).matches()
print("Input:\n", input_messages)
print("Config:\n", guard_config)
print("Matches:\n", matches)


print("--------------------------------------------------------------------------------")
print("Scenario: multiple prompts with guard config as a variable")
gc = [
    Guard.create(GuardName.PROMPT_INJECTION)
]
matches = s.apex.scan(*input_messages, guard_config=gc).matches()
print("Input:\n", input_messages)
print("Config:\n", gc)
print("Matches:\n", matches)


print("--------------------------------------------------------------------------------")
print("Scenario: multiple prompts with guard config")
config="./configs/simple_default_guard_config.yaml"
matches = s.apex.scan(*input_messages, guard_config=config).matches()
print("Input:\n", input_messages)
print("Config:\n", config)
print("Matches:\n", matches)