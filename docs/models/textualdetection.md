# Textualdetection

Represents a textual detection done by policy.


## Fields

| Field                                                                           | Type                                                                            | Required                                                                        | Description                                                                     |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `end`                                                                           | *Optional[int]*                                                                 | :heavy_minus_sign:                                                              | The end position of the detection.                                              |
| `key`                                                                           | *Optional[str]*                                                                 | :heavy_minus_sign:                                                              | The key that is used in the name's place, If empty, a sequence of X's are used. |
| `name`                                                                          | *Optional[str]*                                                                 | :heavy_minus_sign:                                                              | The name of the detection.                                                      |
| `score`                                                                         | *Optional[float]*                                                               | :heavy_minus_sign:                                                              | The confidence score of the detection.                                          |
| `start`                                                                         | *Optional[int]*                                                                 | :heavy_minus_sign:                                                              | The start position of the detection.                                            |
| `type`                                                                          | [Optional[models.TextualdetectionType]](../models/textualdetectiontype.md)      | :heavy_minus_sign:                                                              | The type of detection.                                                          |