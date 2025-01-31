import os
import tempfile

from rich import print

import acuvity
from acuvity import Acuvity

# Initialize Acuvity
s = Acuvity(
    security=acuvity.Security(
        token=os.getenv("ACUVITY_TOKEN", ""),
    )
)

# Create temporary file with the content
def create_temp_file(content):
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
        temp.write(content)
        return temp.name

# PII Guard config content
pii_config_content = """guardrails:
  - name: pii_detector
    count_threshold: 2
    matches:
      # example: Optional redact: true, default redact: False
      email_address:
        threshold: "0.5"
        count_threshold: 1
        redact: true
      ssn:
        threshold: "0.5"
        count_threshold: 1
        redact: true
      person:
        threshold: "0.5"
        count_threshold: 2
        redact: true
      # all possible PIIs (redact default False)
      aba_routing_number:
      address:
      bank_account:
      bitcoin_wallet:
      credit_card:
      driver_license:
      itin_number:
      location:
      medical_license:
      money_amount:
      passport_number:
      phone_number:"""

# Create temporary config file
config_path = create_temp_file(pii_config_content)

input_messages = [
    "corporate sales number are 10k filling, in.abcd@gmail.com, 123abcd@yahoo.com hate you, 792-77-3459, 792-77-3453, 792-77-3454",
]

print("--------------------------------------------------------------------------------")
print("Scenario: single pii prompts with pii guard config")
matches = s.apex.scan(*input_messages, guard_config=config_path).matches()
print("Input:\n", input_messages)
print("Config:\n", "default")
print("Matches:\n", matches)

# Clean up temporary file
os.unlink(config_path)
