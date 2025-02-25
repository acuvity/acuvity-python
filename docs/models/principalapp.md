# Principalapp

Describes the principal information of an application.


## Fields

| Field                                                  | Type                                                   | Required                                               | Description                                            | Example                                                |
| ------------------------------------------------------ | ------------------------------------------------------ | ------------------------------------------------------ | ------------------------------------------------------ | ------------------------------------------------------ |
| `component`                                            | *Optional[str]*                                        | :heavy_minus_sign:                                     | The component of the application request.              | frontend                                               |
| `labels`                                               | List[*str*]                                            | :heavy_minus_sign:                                     | The list of labels attached to an application request. | [<br/>"country=us",<br/>"another-label"<br/>]          |
| `name`                                                 | *Optional[str]*                                        | :heavy_minus_sign:                                     | The name of the application.                           | MyApp                                                  |