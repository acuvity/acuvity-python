<!-- Start SDK Example Usage [usage] -->
### Process a scan request

You can submit a scan request using the Scan API.

```python
# Synchronous Example
import acuvity
from acuvity import Acuvity
import os

with Acuvity(
    security=acuvity.Security(
        token=os.getenv("ACUVITY_TOKEN", ""),
    ),
) as acuvity:

    res = acuvity.apex.scan_request(request={
        "analyzers": [
            "Detectors",
            "en-text-prompt_injection-detector",
            "ocr-handwritten-text-extractor",
        ],
        "annotations": {
            "key1": "value1",
            "key2": "value2",
        },
        "anonymization": acuvity.Anonymization.FIXED_SIZE,
        "bypass_hash": "6f37d752-bce1-4973-88f6-28b6c100ceb8",
        "keywords": [
            "legal",
            "technical",
            "scientific",
        ],
        "messages": [
            "Summarize the main points of this article in bullet points.",
            "Generate a list of creative product names for a futuristic tech gadget.",
        ],
        "redactions": [
            "person",
            "ssn",
            "location",
        ],
    })

    # Handle response
    print(res)
```

</br>

The same SDK client can also be used to make asychronous requests by importing asyncio.
```python
# Asynchronous Example
import acuvity
from acuvity import Acuvity
import asyncio
import os

async def main():
    async with Acuvity(
        security=acuvity.Security(
            token=os.getenv("ACUVITY_TOKEN", ""),
        ),
    ) as acuvity:

        res = await acuvity.apex.scan_request_async(request={
            "analyzers": [
                "Detectors",
                "en-text-prompt_injection-detector",
                "ocr-handwritten-text-extractor",
            ],
            "annotations": {
                "key1": "value1",
                "key2": "value2",
            },
            "anonymization": acuvity.Anonymization.FIXED_SIZE,
            "bypass_hash": "6f37d752-bce1-4973-88f6-28b6c100ceb8",
            "keywords": [
                "legal",
                "technical",
                "scientific",
            ],
            "messages": [
                "Summarize the main points of this article in bullet points.",
                "Generate a list of creative product names for a futuristic tech gadget.",
            ],
            "redactions": [
                "person",
                "ssn",
                "location",
            ],
        })

        # Handle response
        print(res)

asyncio.run(main())
```

### List all available analyzers

Now you can list all available analyzers that can be used in the Scan API.

```python
# Synchronous Example
import acuvity
from acuvity import Acuvity
import os

with Acuvity(
    security=acuvity.Security(
        token=os.getenv("ACUVITY_TOKEN", ""),
    ),
) as acuvity:

    res = acuvity.apex.list_analyzers()

    # Handle response
    print(res)
```

</br>

The same SDK client can also be used to make asychronous requests by importing asyncio.
```python
# Asynchronous Example
import acuvity
from acuvity import Acuvity
import asyncio
import os

async def main():
    async with Acuvity(
        security=acuvity.Security(
            token=os.getenv("ACUVITY_TOKEN", ""),
        ),
    ) as acuvity:

        res = await acuvity.apex.list_analyzers_async()

        # Handle response
        print(res)

asyncio.run(main())
```
<!-- End SDK Example Usage [usage] -->