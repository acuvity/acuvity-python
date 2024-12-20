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
        "bypass_hash": "6f37d752-bce1-4973-88f6-28b6c100ceb8",
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
            "bypass_hash": "6f37d752-bce1-4973-88f6-28b6c100ceb8",
        })

        # Handle response
        print(res)

asyncio.run(main())
```

### Process a scan and police request

You can submit a scan and police request using the Scan API.

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

    res = acuvity.apex.police_request(request={
        "annotations": {
            "0": "{",
            "1": "\n" +
            "",
            "2": " ",
            "3": " ",
            "4": "\"",
            "5": "k",
            "6": "e",
            "7": "y",
            "8": "\"",
            "9": ":",
            "10": " ",
            "11": "\"",
            "12": "v",
            "13": "a",
            "14": "l",
            "15": "u",
            "16": "e",
            "17": "\"",
            "18": "\n" +
            "",
            "19": "}",
            "key1": "value1",
            "key2": "value2",
        },
        "bypass_hash": "6f37d752-bce1-4973-88f6-28b6c100ceb8",
        "messages": [
            "Summarize the main points of this article in bullet points.",
            "Generate a list of creative product names for a futuristic tech gadget.",
        ],
        "provider": "openai",
        "user": {
            "claims": [
                "@org=acuvity.ai",
                "given_name=John",
                "family_name=Doe",
            ],
            "name": "John Doe",
        },
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

        res = await acuvity.apex.police_request_async(request={
            "annotations": {
                "0": "{",
                "1": "\n" +
                "",
                "2": " ",
                "3": " ",
                "4": "\"",
                "5": "k",
                "6": "e",
                "7": "y",
                "8": "\"",
                "9": ":",
                "10": " ",
                "11": "\"",
                "12": "v",
                "13": "a",
                "14": "l",
                "15": "u",
                "16": "e",
                "17": "\"",
                "18": "\n" +
                "",
                "19": "}",
                "key1": "value1",
                "key2": "value2",
            },
            "bypass_hash": "6f37d752-bce1-4973-88f6-28b6c100ceb8",
            "messages": [
                "Summarize the main points of this article in bullet points.",
                "Generate a list of creative product names for a futuristic tech gadget.",
            ],
            "provider": "openai",
            "user": {
                "claims": [
                    "@org=acuvity.ai",
                    "given_name=John",
                    "family_name=Doe",
                ],
                "name": "John Doe",
            },
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