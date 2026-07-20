# RoundtriperrorType

The source of the failure. PlatformError covers apex-side stages
(Extraction, Analysis, ContentPolicy, AccessPolicy). UpstreamError
covers anything attributable to the upstream provider (transport
failures or non-2xx HTTP responses).


## Values

| Name             | Value            |
| ---------------- | ---------------- |
| `PLATFORM_ERROR` | PlatformError    |
| `UPSTREAM_ERROR` | UpstreamError    |