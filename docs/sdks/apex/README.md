# Apex
(*apex*)

## Overview

This tag is for group 'apex'

### Available Operations

* [list_analyzers](#list_analyzers) - List of all available analyzers.
* [police_request](#police_request) - Processes the scan and police request.
* [scan_request](#scan_request) - Processes the scan request.

## list_analyzers

List of all available analyzers.

### Example Usage

```python
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

### Parameters

| Parameter                                                           | Type                                                                | Required                                                            | Description                                                         |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `retries`                                                           | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)    | :heavy_minus_sign:                                                  | Configuration to override the default retry behavior of the client. |

### Response

**[List[models.Analyzer]](../../models/.md)**

### Errors

| Error Type            | Status Code           | Content Type          |
| --------------------- | --------------------- | --------------------- |
| models.Elementalerror | 400, 401, 500         | application/json      |
| models.APIError       | 4XX, 5XX              | \*/\*                 |

## police_request

Processes the scan and police request.

### Example Usage

```python
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

### Parameters

| Parameter                                                           | Type                                                                | Required                                                            | Description                                                         |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `request`                                                           | [models.Policerequest](../../models/policerequest.md)               | :heavy_check_mark:                                                  | The request object to use for the request.                          |
| `retries`                                                           | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)    | :heavy_minus_sign:                                                  | Configuration to override the default retry behavior of the client. |

### Response

**[models.Policeresponse](../../models/policeresponse.md)**

### Errors

| Error Type            | Status Code           | Content Type          |
| --------------------- | --------------------- | --------------------- |
| models.Elementalerror | 400, 403, 422, 500    | application/json      |
| models.APIError       | 4XX, 5XX              | \*/\*                 |

## scan_request

Processes the scan request.

### Example Usage

```python
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

### Parameters

| Parameter                                                           | Type                                                                | Required                                                            | Description                                                         |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `request`                                                           | [models.Scanrequest](../../models/scanrequest.md)                   | :heavy_check_mark:                                                  | The request object to use for the request.                          |
| `retries`                                                           | [Optional[utils.RetryConfig]](../../models/utils/retryconfig.md)    | :heavy_minus_sign:                                                  | Configuration to override the default retry behavior of the client. |

### Response

**[models.Scanresponse](../../models/scanresponse.md)**

### Errors

| Error Type            | Status Code           | Content Type          |
| --------------------- | --------------------- | --------------------- |
| models.Elementalerror | 400, 403, 422, 500    | application/json      |
| models.APIError       | 4XX, 5XX              | \*/\*                 |