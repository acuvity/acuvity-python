<!-- Start SDK Example Usage [usage] -->
### Process a scan request

Now you can submit a scan request using the Scan API.

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
        "bypass_hash": "Alice",
        "user": {
            "claims": [
                "@org=acuvity.ai",
                "given_name=John",
                "family_name=Doe",
            ],
            "name": "Alice",
        },
    })

    if res is not None:
        # handle response
        pass
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
            "bypass_hash": "Alice",
            "user": {
                "claims": [
                    "@org=acuvity.ai",
                    "given_name=John",
                    "family_name=Doe",
                ],
                "name": "Alice",
            },
        })

        if res is not None:
            # handle response
            pass

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

    if res is not None:
        # handle response
        pass
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

        if res is not None:
            # handle response
            pass

asyncio.run(main())
```
<!-- End SDK Example Usage [usage] -->