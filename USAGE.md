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
) as a_client:

    res = a_client.apex.scan_request(request={
        "analyzers": [
            "Malcontents",
        ],
        "annotations": {
            "key1": "value1",
            "key2": "value2",
        },
        "bypass_hash": "6f37d752-bce1-4973-88f6-28b6c100ceb8",
        "extractions": [
            {
                "tool_results": [
                    {
                        "call_id": "toolu_019X5QaEeVTDFrQPHqMMgd1n",
                    },
                ],
                "tool_uses": [
                    {
                        "call_id": "toolu_019X5QaEeVTDFrQPHqMMgd1n",
                        "name": "get_weather",
                        "server_name": "deepwiki",
                    },
                ],
            },
        ],
        "keywords": [
            "legal",
            "technical",
            "scientific",
        ],
        "messages": [
            "Summarize the main points of this article in bullet points.",
            "Generate a list of creative product names for a futuristic tech gadget.",
        ],
        "model": "claude-3-7-sonnet",
        "redactions": [
            "person",
            "ssn",
            "location",
        ],
        "tools": {
            "tool1": {
                "description": "This is a tool.",
                "name": "tool1",
            },
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
    ) as a_client:

        res = await a_client.apex.scan_request_async(request={
            "analyzers": [
                "Malcontents",
            ],
            "annotations": {
                "key1": "value1",
                "key2": "value2",
            },
            "bypass_hash": "6f37d752-bce1-4973-88f6-28b6c100ceb8",
            "extractions": [
                {
                    "tool_results": [
                        {
                            "call_id": "toolu_019X5QaEeVTDFrQPHqMMgd1n",
                        },
                    ],
                    "tool_uses": [
                        {
                            "call_id": "toolu_019X5QaEeVTDFrQPHqMMgd1n",
                            "name": "get_weather",
                            "server_name": "deepwiki",
                        },
                    ],
                },
            ],
            "keywords": [
                "legal",
                "technical",
                "scientific",
            ],
            "messages": [
                "Summarize the main points of this article in bullet points.",
                "Generate a list of creative product names for a futuristic tech gadget.",
            ],
            "model": "claude-3-7-sonnet",
            "redactions": [
                "person",
                "ssn",
                "location",
            ],
            "tools": {
                "tool1": {
                    "description": "This is a tool.",
                    "name": "tool1",
                },
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
) as a_client:

    res = a_client.apex.list_analyzers()

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
    ) as a_client:

        res = await a_client.apex.list_analyzers_async()

        # Handle response
        print(res)

asyncio.run(main())
```
<!-- End SDK Example Usage [usage] -->