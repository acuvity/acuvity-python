# Decision

User-facing outcome of the roundtrip. Reflects the policy
engine's verdict, or in case of platform failure, the result of the
failClose strategy (Deny on fail-close, Allow on fail-open, with
structured error field carring the detail). NotApplicable is
used by the scan and police APIs, which analyze content without
rendering an enforcement decision. Error and UpstreamError stay
in the allowed_choices list for backward compatibility with
clients that still PUT those values; new round-trips never emit
them — platform/upstream failures now surface via the structured
Error field instead.
NOTE: safe to drop Error and UpstreamError from this enum on or
after 2026-07-19 (two months after the structured RoundtripError
landed on 2026-05-19), once consumers have rolled forward.


## Values

| Name             | Value            |
| ---------------- | ---------------- |
| `DENY`           | Deny             |
| `ALLOW`          | Allow            |
| `ASK`            | Ask              |
| `REPORT`         | Report           |
| `BYPASSED`       | Bypassed         |
| `FORBIDDEN_USER` | ForbiddenUser    |
| `SKIPPED`        | Skipped          |
| `REDIRECTED`     | Redirected       |
| `NOT_APPLICABLE` | NotApplicable    |
| `ERROR`          | Error            |
| `UPSTREAM_ERROR` | UpstreamError    |