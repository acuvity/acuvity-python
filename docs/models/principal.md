# Principal

Describe the principal.


## Fields

| Field                                                        | Type                                                         | Required                                                     | Description                                                  | Example                                                      |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| `type`                                                       | [models.PrincipalType](../models/principaltype.md)           | :heavy_check_mark:                                           | The type of principal.                                       | [<br/>"User"<br/>]                                           |
| `app`                                                        | [Optional[models.Principalapp]](../models/principalapp.md)   | :heavy_minus_sign:                                           | Describes the principal information of an application.       |                                                              |
| `auth_type`                                                  | [Optional[models.AuthType]](../models/authtype.md)           | :heavy_minus_sign:                                           | The type of authentication.                                  |                                                              |
| `claims`                                                     | List[*str*]                                                  | :heavy_minus_sign:                                           | List of claims extracted from the user query.                |                                                              |
| `team`                                                       | *Optional[str]*                                              | :heavy_minus_sign:                                           | The team that was used to authorize the request.             | admins                                                       |
| `token_name`                                                 | *Optional[str]*                                              | :heavy_minus_sign:                                           | The name of the token, if any.                               | my-user-token                                                |
| `user`                                                       | [Optional[models.Principaluser]](../models/principaluser.md) | :heavy_minus_sign:                                           | Describes the principal information of a user.               |                                                              |