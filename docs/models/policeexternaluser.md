# Policeexternaluser

PoliceExternalUser holds the information about the remote user for a
PoliceRequest.


## Fields

| Field                                                       | Type                                                        | Required                                                    | Description                                                 | Example                                                     |
| ----------------------------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------- |
| `claims`                                                    | List[*str*]                                                 | :heavy_check_mark:                                          | List of claims extracted from the user query.               | [<br/>"@org=acuvity.ai",<br/>"given_name=John",<br/>"family_name=Doe"<br/>] |
| `name`                                                      | *str*                                                       | :heavy_check_mark:                                          | The name of the external user.                              | John Doe                                                    |