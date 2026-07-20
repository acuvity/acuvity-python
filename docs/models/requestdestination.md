# Requestdestination

RequestDestination holds the destination information for a request. When app
and component are set, the request is evaluated against the app component's
policies instead of a provider. In that case, the provider field must not be
set.


## Fields

| Field                                                               | Type                                                                | Required                                                            | Description                                                         | Example                                                             |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `app`                                                               | *Optional[str]*                                                     | :heavy_minus_sign:                                                  | The name of the destination application.                            | other-ai-app                                                        |
| `component`                                                         | *Optional[str]*                                                     | :heavy_minus_sign:                                                  | The component of the destination application.                       | backend                                                             |
| `host`                                                              | *Optional[str]*                                                     | :heavy_minus_sign:                                                  | The host name of the destination. Optional, for logging enrichment. | api.openai.com                                                      |
| `ip`                                                                | *Optional[str]*                                                     | :heavy_minus_sign:                                                  | The destination IP address. Optional, for logging enrichment.       | 192.0.2.42                                                          |