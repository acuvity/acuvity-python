# Mcptoolannotations

Represents the tool annotations as they can be optionally defined for MCP tools.


## Fields

| Field                                                             | Type                                                              | Required                                                          | Description                                                       |
| ----------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------- |
| `destructive_hint`                                                | *Optional[bool]*                                                  | :heavy_minus_sign:                                                | If true, the tool may perform destructive updates.                |
| `idempotent_hint`                                                 | *Optional[bool]*                                                  | :heavy_minus_sign:                                                | If true, repeated calls with same args have no additional effect. |
| `open_world_hint`                                                 | *Optional[bool]*                                                  | :heavy_minus_sign:                                                | If true, tool interacts with external entities.                   |
| `read_only_hint`                                                  | *Optional[bool]*                                                  | :heavy_minus_sign:                                                | If true, the tool does not modify its environment.                |
| `title`                                                           | *Optional[str]*                                                   | :heavy_minus_sign:                                                | Human-readable title for the tool.                                |