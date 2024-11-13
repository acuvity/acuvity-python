# SPDX-License-Identifier: Apache-2.0
# 
# Copyright (C) 2024 Acuvity, Inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Code generated by elegen. DO NOT EDIT.
# Source: github.com/acuvity/regolithe-python (templates/model.py.tmpl)

from .elemental import ElementalModel
from .principalapp import PrincipalApp
from .principaluser import PrincipalUser
from enum import Enum
from pydantic import ConfigDict, Field, model_validator
from typing import Optional, List


class PrincipalAuthTypeEnum(str, Enum):
    """
    PrincipalAuthTypeEnum represents all the allowed values for the authType field in a Principal.
    """
    APP_TOKEN = "AppToken"
    CERTIFICATE = "Certificate"
    EXTERNAL = "External"
    HOSTNAME = "Hostname"
    TIER_TOKEN = "TierToken"
    TOKEN = "Token"
    USER_TOKEN = "UserToken"


class PrincipalTypeEnum(str, Enum):
    """
    PrincipalTypeEnum represents all the allowed values for the type field in a Principal.
    """
    APP = "App"
    USER = "User"


class Principal(ElementalModel):
    """
    Describe the principal.

    Attributes:
        app: The application principal information if type is App.
        auth_type: The type of authentication.
        claims: List of claims extracted from the user query.
        team: The team that was used to authorize the request.
        token_name: The name of the token, if any.
        type: The type of principal.
        user: The user principal information if type is User.
    """
    # there is a few things to know about elemental based models:
    # - they can never be strict
    # - we need to use enum values instead of their keys
    # - because of that we also need to use validate_default, otherwise the keys are used for enums on defaults
    # - we allow population by field name to make it more natural to use from python
    model_config = ConfigDict(
        strict=False,
        use_enum_values=True,
        validate_default=True,
        populate_by_name=True,
        extra="forbid",
    )

    # all spec fields
    app: Optional[PrincipalApp] = Field(
        None,
        alias="app",
        description="The application principal information if type is App.",
    )
    auth_type: Optional[PrincipalAuthTypeEnum] = Field(
        None,
        alias="authType",
        description="The type of authentication.",
    )
    claims: Optional[List[str]] = Field(
        None,
        alias="claims",
        description="List of claims extracted from the user query.",
    )
    team: Optional[str] = Field(
        None,
        alias="team",
        description="The team that was used to authorize the request.",
        examples=["admins"],
    )
    token_name: Optional[str] = Field(
        None,
        alias="tokenName",
        description="The name of the token, if any.",
        examples=["my-user-token"],
    )
    type: PrincipalTypeEnum = Field(
        ...,
        alias="type",
        description="The type of principal.",
        examples=[PrincipalTypeEnum.USER],
    )
    user: Optional[PrincipalUser] = Field(
        None,
        alias="user",
        description="The user principal information if type is User.",
    )

    # additional validation methods for the model
    @model_validator(mode='after')
    def __additional_model_validation(self) -> 'Principal':
        if self.type == PrincipalTypeEnum.APP:
            if self.app is None:
                raise ValueError(f"'app' must have its information defined.")
        elif self.type == PrincipalTypeEnum.USER:
            if self.user is None:
                raise ValueError(f"'user' must have its information defined.")

    def model_dump(self, *args, **kwargs):
        # Overriding this method allows us to set defaults
        # which reflect the necessary settings when sending things to the APIs
        kwargs.setdefault('exclude_none', True)
        kwargs.setdefault('by_alias', True)
        return super().model_dump(*args, **kwargs)

    def model_dump_json(self, *args, **kwargs):
        # Overriding this method allows us to set defaults
        # which reflect the necessary settings when sending things to the APIs
        # without the need to explicitly call them out
        kwargs.setdefault('exclude_none', True)
        kwargs.setdefault('by_alias', True)
        return super().model_dump_json(*args, **kwargs)
