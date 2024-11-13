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
from pydantic import Field, field_validator, ValidationInfo, ConfigDict
from typing import List, Any


class ScanExternalUser(ElementalModel):
    """
    ScanExternalUser holds the information about the remote user for a ScanRequest.

    Attributes:
        claims: List of claims extracted from the user query.
        name: The name of the external user.
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
    claims: List[str] = Field(
        ...,
        alias="claims",
        description="List of claims extracted from the user query.",
        examples=["@org=acuvity.ai", "given_name=John", "family_name=Doe"],
    )
    name: str = Field(
        ...,
        alias="name",
        description="The name of the external user.",
        examples=["Alice"],
    )

    # additional validation methods for model fields
    @field_validator("claims", mode="after")
    def __claims_validate_non_empty_list(cls, v: List[Any], info: ValidationInfo):
        if not isinstance(v, list):
            raise ValueError(f"{info.field_name} must be a list")
        if len(v) == 0:
            raise ValueError(f"{info.field_name} must not be empty")
        return v

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