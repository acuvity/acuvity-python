# Toolresult

Represents the tool result as passed in by the user or application after calling
a tool.


## Fields

| Field                                                                        | Type                                                                         | Required                                                                     | Description                                                                  | Example                                                                      |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `call_id`                                                                    | *str*                                                                        | :heavy_check_mark:                                                           | The ID of the tool use as previously returned by a models tool use response. | toolu_019X5QaEeVTDFrQPHqMMgd1n                                               |
| `content`                                                                    | *Optional[str]*                                                              | :heavy_minus_sign:                                                           | The content of the tool call results.                                        |                                                                              |
| `is_error`                                                                   | *Optional[bool]*                                                             | :heavy_minus_sign:                                                           | Indicates if the tool call failed.                                           |                                                                              |