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
from pydantic import ConfigDict, Field, field_validator, field_serializer
from typing import Optional, Dict
import base64


class ExtractionRequest(ElementalModel):
    """
    Represents the extractection that the user wants to extract.

    Attributes:
        annotations: Annotations attached to the extraction.
        data: The data extracted.
        internal: If true, this extraction is for internal use only.
        label: A means of distinguishing what was extracted, such as prompt, input file or code.
        lua_id: An internal field for lua code. it is ignored by the API.
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
    annotations: Optional[Dict[str, str]] = Field(
        None,
        alias="annotations",
        description="Annotations attached to the extraction.",
    )
    data: Optional[bytes] = Field(
        None,
        alias="data",
        description="The data extracted.",
    )
    internal: Optional[bool] = Field(
        None,
        alias="internal",
        description="If true, this extraction is for internal use only.",
    )
    label: Optional[str] = Field(
        None,
        alias="label",
        description="A means of distinguishing what was extracted, such as prompt, input file or code.",
    )
    lua_id: Optional[str] = Field(
        None,
        alias="luaID",
        description="An internal field for lua code. it is ignored by the API.",
    )

    # additional methods for the model
    # Use field_validator to decode Base64 when initializing
    @field_validator("data", mode="before")
    def __data_base64_decode(cls, value: str) -> bytes:
        if isinstance(value, str):
            return base64.b64decode(value)
        return value

    # Use field_serializer to encode Base64 when serializing
    @field_serializer("data")
    def __data_base64_encode(cls, value: bytes) -> str:
        return base64.b64encode(value).decode("utf-8")

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