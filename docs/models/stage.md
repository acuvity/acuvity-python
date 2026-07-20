# Stage

The pipeline component that produced the error. Combined with the
Type axis on the parent round-trip (Input/Output) and the Offband
flag, gives the full discrimination of where a platform/upstream
failure originated. Each value maps to an ownership tier:
Proofpoint AI Security-owned (Extraction, Analysis, AssignPolicy, AccessPolicy),
customer-owned (ContentPolicy), provider-owned (Upstream).


## Values

| Name             | Value            |
| ---------------- | ---------------- |
| `EXTRACTION`     | Extraction       |
| `ANALYSIS`       | Analysis         |
| `CONTENT_POLICY` | ContentPolicy    |
| `ASSIGN_POLICY`  | AssignPolicy     |
| `ACCESS_POLICY`  | AccessPolicy     |
| `UPSTREAM`       | Upstream         |