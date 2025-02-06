import os

import httpx
from rich import print

import acuvity
from acuvity import Acuvity
from acuvity.guard.constants import GuardName

s = Acuvity(
    # not required at all if set in environment variables
    security=acuvity.Security(
       token=os.getenv("ACUVITY_TOKEN", ""),
    ),
    client=httpx.Client(verify=False)
)

# This is to show the list of available guards supported by Acuvity.
print("--------------------------------------------------------------------------------")
print("Avaiable Guards and Categories: ")
print("--------------------------------------------------------------------------------")
for g in s.apex.list_available_guards():
    print(f" - {g}")
    if g == str(GuardName.PII_DETECTOR):
        for pii in s.apex.list_detectable_piis():
            print(f"     - {pii}")
    elif g == str(GuardName.SECRETS_DETECTOR):
        for secrets in s.apex.list_detectable_secrets():
            print(f"     - {secrets}")
