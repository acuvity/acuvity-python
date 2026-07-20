# ExtractionKind

The kind of content carried by this extraction. Used together with role to
label what the extracted blob represents so the UI can render it correctly and
analyzers can dispatch appropriately:
- Message: free-form natural language (default).
- Thinking: model reasoning trace (e.g. Anthropic thinking, OpenAI reasoning,
Gemini thought).
- ToolDefinition: tool/function schema advertised to the model (name,
description, JSON schema).
- ToolInput: structured arguments the model passes when invoking a tool.
- ToolOutput: result returned to the model after a tool call.
- File: uploaded or attached file payload.
- Resource: externally-supplied context injected into the prompt (RAG
document, search result, MCP resource).
- Event: control or lifecycle marker with no analyzable content.


## Values

| Name              | Value             |
| ----------------- | ----------------- |
| `MESSAGE`         | Message           |
| `THINKING`        | Thinking          |
| `TOOL_DEFINITION` | ToolDefinition    |
| `TOOL_INPUT`      | ToolInput         |
| `TOOL_OUTPUT`     | ToolOutput        |
| `FILE`            | File              |
| `RESOURCE`        | Resource          |
| `EVENT`           | Event             |