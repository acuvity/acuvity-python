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
from enum import Enum
from pydantic import ConfigDict, Field
from typing import Optional


class TextualDetectionTypeEnum(str, Enum):
    """
    TextualDetectionTypeEnum represents all the allowed values for the type field in a TextualDetection.
    """
    KEYWORD = "Keyword"
    PII = "PII"
    SECRET = "Secret"


class TextualDetection(ElementalModel):
    """
    Represents a textual detection done by policy.

    Attributes:
        content: The original detected content.
        end: The end position of the detection.
        key: The key that is used in the name's place, If empty, a sequence of X's are used.
        name: The name of the detection.
        score: The confidence score of the detection.
        start: The start position of the detection.
        type: The type of detection.
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
    content: Optional[str] = Field(
        None,
        alias="content",
        description="The original detected content.",
        exclude=True,
    )
    end: Optional[int] = Field(
        None,
        alias="end",
        description="The end position of the detection.",
    )
    key: Optional[str] = Field(
        None,
        alias="key",
        description="The key that is used in the name's place, If empty, a sequence of X's are used.",
    )
    name: Optional[str] = Field(
        None,
        alias="name",
        description="The name of the detection.",
    )
    score: Optional[float] = Field(
        None,
        alias="score",
        description="The confidence score of the detection.",
    )
    start: Optional[int] = Field(
        None,
        alias="start",
        description="The start position of the detection.",
    )
    type: Optional[TextualDetectionTypeEnum] = Field(
        None,
        alias="type",
        description="The type of detection.",
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