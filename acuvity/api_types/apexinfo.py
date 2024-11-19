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

from pydantic import Field, ConfigDict
from typing import Optional

# this is a little bit of an outlier here, but it made more sense to structure it like this
# as the types here are not auto-generated
from ..apex_types import ElementalModel

class ApexInfo(ElementalModel):
    """
    ApexInfo holds the well known URL and CA information for an apex for a namespace.

    Fields:
    - url: the URL of the Apex
    - CAs: the CA certificates that verify the certificates that this apex is serving
    """
    model_config = ConfigDict(strict=False)

    url: str = Field(..., description="The URL of the Apex.")
    cas: Optional[str] = Field(None, description="The CA certificates that verify the certificates that this apex is serving.", alias="CAs")
    port: Optional[int] = Field(None, description="The port of the Apex.")
    port_no_mtls: Optional[int] = Field(None, description="The port of the Apex without mTLS.", alias="portNoMTLS")
