# Principalapp

Describes the principal information of an application.


## Fields

| Field                                                  | Type                                                   | Required                                               | Description                                            | Example                                                |
| ------------------------------------------------------ | ------------------------------------------------------ | ------------------------------------------------------ | ------------------------------------------------------ | ------------------------------------------------------ |
| `labels`                                               | List[*str*]                                            | :heavy_minus_sign:                                     | The list of labels attached to an application request. | [<br/>"country=us",<br/>"another-label"<br/>]          |
| `name`                                                 | *Optional[str]*                                        | :heavy_minus_sign:                                     | The name of the application.                           | MyApp                                                  |
| `tier`                                                 | *Optional[str]*                                        | :heavy_minus_sign:                                     | The tier of the application request.                   | frontend                                               |