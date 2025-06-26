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
            "0": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "1": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "2": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "3": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "4": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "5": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "6": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "7": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "8": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "9": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "10": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "11": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "12": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "13": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "14": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "15": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "16": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "17": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "18": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "19": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "20": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "21": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "22": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "23": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "24": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "25": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "26": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "27": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "28": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "29": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "30": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "31": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "32": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "33": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "34": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "35": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "36": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "37": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "38": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "39": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "40": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "41": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "42": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "43": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "44": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "45": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "46": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "47": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "48": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "49": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "50": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "51": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "52": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "53": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "54": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "55": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "56": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "57": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "58": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "59": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "60": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "61": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "62": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "63": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "64": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "65": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "66": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "67": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "68": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "69": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "70": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "71": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "72": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "73": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "74": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "75": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "76": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "77": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "78": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "79": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "80": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
            },
            "81": {
                "mcp_server": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "allowed_tools": [
                        "deepwiki_search",
                        "deepwiki_fetch",
                    ],
                    "name": "deepwiki",
                },
                "category": acuvity.Category.CLIENT,
                "description": "Get the current weather in a given location",
                "name": "get_weather",
                "type": "computer_20250124",
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
                "0": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "1": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "2": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "3": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "4": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "5": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "6": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "7": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "8": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "9": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "10": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "11": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "12": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "13": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "14": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "15": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "16": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "17": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "18": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "19": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "20": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "21": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "22": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "23": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "24": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "25": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "26": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "27": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "28": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "29": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "30": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "31": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "32": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "33": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "34": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "35": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "36": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "37": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "38": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "39": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "40": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "41": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "42": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "43": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "44": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "45": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "46": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "47": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "48": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "49": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "50": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "51": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "52": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "53": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "54": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "55": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "56": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "57": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "58": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "59": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "60": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "61": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "62": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "63": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "64": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "65": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "66": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "67": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "68": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "69": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "70": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "71": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "72": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "73": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "74": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "75": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "76": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "77": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "78": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "79": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "80": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
                },
                "81": {
                    "mcp_server": {
                        "url": "https://mcp.deepwiki.com/mcp",
                        "allowed_tools": [
                            "deepwiki_search",
                            "deepwiki_fetch",
                        ],
                        "name": "deepwiki",
                    },
                    "category": acuvity.Category.CLIENT,
                    "description": "Get the current weather in a given location",
                    "name": "get_weather",
                    "type": "computer_20250124",
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