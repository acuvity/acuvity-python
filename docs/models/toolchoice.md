# Toolchoice

Represents the tool choice that can be passed along together with tools.


## Fields

| Field                                                               | Type                                                                | Required                                                            | Description                                                         |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `choice`                                                            | [Optional[models.Choice]](../models/choice.md)                      | :heavy_minus_sign:                                                  | Model instructions on tool choice.                                  |
| `name`                                                              | *Optional[str]*                                                     | :heavy_minus_sign:                                                  | If choice is Tool, this will be set to the name of the tool to use. |