# Alertevent

Represents an alert event raised by a policy.


## Fields

| Field                                                                | Type                                                                 | Required                                                             | Description                                                          | Example                                                              |
| -------------------------------------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `alert_definition`                                                   | *str*                                                                | :heavy_check_mark:                                                   | The name of the alert definition that triggered the alert event.     | warning-notification                                                 |
| `principal`                                                          | [models.Principal](../models/principal.md)                           | :heavy_check_mark:                                                   | Describe the principal.                                              |                                                                      |
| `alert_definition_namespace`                                         | *Optional[str]*                                                      | :heavy_minus_sign:                                                   | The namespace of the alert definition.                               |                                                                      |
| `provider`                                                           | *Optional[str]*                                                      | :heavy_minus_sign:                                                   | The provider used that the alert came from.                          |                                                                      |
| `timestamp`                                                          | [date](https://docs.python.org/3/library/datetime.html#date-objects) | :heavy_minus_sign:                                                   | When the alert event was raised.                                     |                                                                      |