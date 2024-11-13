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

from .alertevent import AlertEvent
from .elemental import ElementalModel
from .extraction import Extraction
from .latency import Latency
from .principal import Principal
from datetime import datetime
from enum import Enum
from pydantic import ConfigDict, Field
from typing import Dict, List, Optional


class ScanResponseDecisionEnum(str, Enum):
    """
    ScanResponseDecisionEnum represents all the allowed values for the decision field in a ScanResponse.
    """
    ALLOW = "Allow"
    ASK = "Ask"
    BYPASSED = "Bypassed"
    DENY = "Deny"
    FORBIDDEN_USER = "ForbiddenUser"


class ScanResponseTypeEnum(str, Enum):
    """
    ScanResponseTypeEnum represents all the allowed values for the type field in a ScanResponse.
    """
    INPUT = "Input"
    OUTPUT = "Output"


class ScanResponse(ElementalModel):
    """
    This is a scan response.

    Attributes:
        id: ID is the identifier of the object.
        alerts: List of alerts that got raised during the policy resolution.
        annotations: Annotations attached to the log.
        decision: Tell what was the decision about the data.
        extractions: The extractions to log.
        hash: The hash of the input.
        latency: Information about latency of various stage of request and response.
        namespace: The namespace of the object.
        pipeline_name: The name of the particular pipeline that extracted the text.
        principal: The principal of the object.
        provider: the provider to use.
        reasons: The various reasons returned by the policy engine.
        time: Set the time of the message request.
        type: The type of text.
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
    id: Optional[str] = Field(
        None,
        alias="ID",
        description="ID is the identifier of the object.",
        frozen=True,
    )
    alerts: Optional[List[AlertEvent]] = Field(
        None,
        alias="alerts",
        description="List of alerts that got raised during the policy resolution.",
    )
    annotations: Optional[Dict[str, str]] = Field(
        None,
        alias="annotations",
        description="Annotations attached to the log.",
    )
    decision: Optional[ScanResponseDecisionEnum] = Field(
        None,
        alias="decision",
        description="Tell what was the decision about the data.",
    )
    extractions: Optional[List[Extraction]] = Field(
        None,
        alias="extractions",
        description="The extractions to log.",
    )
    hash: Optional[str] = Field(
        None,
        alias="hash",
        description="The hash of the input.",
    )
    latency: Optional[Latency] = Field(
        None,
        alias="latency",
        description="Information about latency of various stage of request and response.",
    )
    namespace: Optional[str] = Field(
        None,
        alias="namespace",
        description="The namespace of the object.",
        frozen=True,
    )
    pipeline_name: Optional[str] = Field(
        None,
        alias="pipelineName",
        description="The name of the particular pipeline that extracted the text.",
    )
    principal: Principal = Field(
        ...,
        alias="principal",
        description="The principal of the object.",
    )
    provider: Optional[str] = Field(
        None,
        alias="provider",
        description="the provider to use.",
        examples=["openai"],
    )
    reasons: Optional[List[str]] = Field(
        None,
        alias="reasons",
        description="The various reasons returned by the policy engine.",
    )
    time: Optional[datetime] = Field(
        None,
        alias="time",
        description="Set the time of the message request.",
    )
    type: Optional[ScanResponseTypeEnum] = Field(
        None,
        alias="type",
        description="The type of text.",
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
