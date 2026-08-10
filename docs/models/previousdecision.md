# PreviousDecision

The decision produced before the failClose or failOpen mutation
flipped it. Set only when the user-facing Decision is the result
of a platform-error override, so the audit log can surface what
the policy would have decided otherwise.


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