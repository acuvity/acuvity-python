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
# Code generated by regolithe-python. DO NOT EDIT.
# Source: github.com/acuvity/regolithe-python (templates/model.py.tmpl)

from .elemental import ElementalModel
from .principal import Principal
from datetime import datetime
from pydantic import ConfigDict, Field
from typing import Optional


class AlertEvent(ElementalModel):
    """
    Represents an alert event raised by a policy.

    Attributes:
        alert_definition: The name of the alert definition that triggered the alert event.
        alert_definition_namespace: The namespace of the alert definition.
        principal: The principal of the object.
        provider: The provider used that the alert came from.
        timestamp: When the alert event was raised.
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
    alert_definition: str = Field(
        ...,
        alias="alertDefinition",
        description="The name of the alert definition that triggered the alert event.",
        examples=["warning-notification"],
    )
    alert_definition_namespace: Optional[str] = Field(
        None,
        alias="alertDefinitionNamespace",
        description="The namespace of the alert definition.",
    )
    principal: Principal = Field(
        ...,
        alias="principal",
        description="The principal of the object.",
    )
    provider: Optional[str] = Field(
        None,
        alias="provider",
        description="The provider used that the alert came from.",
    )
    timestamp: Optional[datetime] = Field(
        None,
        alias="timestamp",
        description="When the alert event was raised.",
        frozen=True,
    )

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
