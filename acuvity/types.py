import re

from typing import Iterable, List, Any, Dict, Sequence, Union, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class PrincipalApp(BaseModel):
    """
    PrincipalApp represents the model of a principalapp

    Fields:
    - labels: The list of labels attached to an application request.
    - name: The name of the application.
    - tier: The tier of the application request.
    """
    model_config = ConfigDict(strict=False)

    labels: Optional[List[str]] = Field(None, description="The list of labels attached to an application request.")
    name: Optional[str] = Field(None, description="The name of the application.")
    tier: Optional[str] = Field(None, description="The tier of the application request.")


class PrincipalUser(BaseModel):
    """
    PrincipalUser represents the model of a principaluser

    Fields:
    - name: Identification bit that will be used to identify the origin of the request.
    """
    name: str = Field(..., description="Identification bit that will be used to identify the origin of the request.")


class Principal(BaseModel):
    """
    Principal represents the model of a principal
    """
    model_config = ConfigDict(strict=False)

    app : Optional[PrincipalApp] = Field(None, description="The application principal information if type is App.")
    authType: str = Field(..., description="The type of authentication.")
    claims: Optional[List[str]] = Field(None, description="List of claims extracted from the user query.")
    team: Optional[str] = Field(None, description="The team that was used to authorize the request.")
    tokenName: str = Field(..., description="The name of the token, if any.")
    type: str = Field(..., description="The type of principal.")
    user: Optional[PrincipalUser] = Field(None, description="The user principal information if type is User.")


class AlertEvent(BaseModel):
    """
    AlertEvent represents the model of a alertevent
    """
    model_config = ConfigDict(strict=False)

    alertDefinition: str = Field(..., description="The name of the alert definition that triggered the alert event.")
    alertDefinitionNamespace: str = Field(..., description="The namespace of the alert definition.")
    principal: Principal = Field(..., description="The principal of the object.")
    provider: str = Field(..., description="The provider used that the alert came from.")
    timestamp: Optional[datetime] = Field(None, description="When the alert event was raised.")


class Modality(BaseModel):
    """
    Modality represents the model of a modality
    """
    model_config = ConfigDict(strict=False)

    group: str = Field(..., description="The group of data.")
    type: str = Field(..., description="The type of data.")


class TextualDetection(BaseModel):
    """
    TextualDetection represents the model of a textualdetection
    """
    model_config = ConfigDict(strict=False)

    end: int = Field(..., description="The end position of the detection.")
    hash: str = Field(..., description="The detection Hash.")
    name: Optional[str] = Field(None, description="The name of the detection.")
    score: float = Field(..., description="The confidence score of the detection.")
    start: int = Field(..., description="The start position of the detection.")
    type: str = Field(..., description="The type of detection.")


class Extraction(BaseModel):
    """
    Extraction represents the model of a extraction
    """
    model_config = ConfigDict(strict=False)

    PIIs: Optional[Dict[str, float]] = Field(None, description="The PIIs found during classification.")
    annotations: Optional[Dict[str, str]] = Field(None, description="Annotations attached to the extraction.")
    categories: Optional[List[Modality]] = Field(None, description="The categories are remapping of the modalities in a more human friendly way.")
    confidentiality: Optional[float] = Field(None, description="The level of general confidentiality of the input.")
    data: str = Field(..., description="The data extracted.")
    detections: Optional[List[TextualDetection]] = Field(None, description="The detections found while applying policies.")
    exploits: Optional[Dict[str, float]] = Field(None, description="The various exploits attempts.")
    hash: str = Field(..., description="The hash of the extraction.")
    intent: Optional[Dict[str, float]] = Field(None, description="The estimated intent embodied into the text.")
    internal: Optional[bool] = Field(None, description="If true, this extraction is for internal use only.")
    keywords: Optional[Dict[str, float]] = Field(None, description="The keywords found during classification.")
    label: Optional[str] = Field(None, description="A means of distinguishing what was extracted, such as prompt, input file or code.")
    languages: Optional[Dict[str, float]] = Field(None, description="The language of the classification.")
    luaID: Optional[str] = Field(None, description="An internal field for lua code. it is ignored by the API.")
    modalities: Optional[List[Modality]] = Field(None, description="The modalities of data detected in the data.")
    redactions: Optional[List[TextualDetection]] = Field(None, description="The redactions that has been performed.")
    relevance: Optional[float] = Field(None, description="The level of general organization relevance of the input.")
    secrets: Optional[Dict[str, float]] = Field(None, description="The secrets found during classification.")
    topics: Optional[Dict[str, float]] = Field(None, description="The topic of the classification.")


class Latency(BaseModel):
    """
    Latency represents the model of a latency
    """
    model_config = ConfigDict(strict=False)

    accessPolicy: int = Field(..., description="How much time it took to run the access policy in nanoseconds.")
    analysis: int = Field(..., description="How much time it took to run content analysis in nanoseconds.")
    assignPolicy: int = Field(..., description="How much time it took to run the assign policy in nanoseconds.")
    contentPolicy: int = Field(..., description="How much time it took to run content policy in nanoseconds.")
    extraction: int = Field(..., description="How much time it took to run input or output extraction in nanoseconds.")


class ValidateResponse(BaseModel):
    """
    ValidateResponse represents the model of a response to a validate API call
    """
    model_config = ConfigDict(strict=False)

    ID: Optional[str] = Field(None, description="The identifier of the object.")
    alerts: Optional[List[AlertEvent]] = Field(None, description="List of alerts that got raised during the policy resolution.")
    annotations: Optional[Dict[str, str]] = Field(None, description="Annotations attached to the log.")
    decision: str = Field(..., description="Tell what was the decision about the data.")
    extractions: List[Extraction] = Field(..., description="The extractions to log.")
    hash: str = Field(..., description="The hash of the input.")
    importHash: Optional[str] = Field(None, description="The hash of the structure used to compare with new import version.")
    importLabel: Optional[str] = Field(None, description="The user-defined import label that allows the system to group resources from the same import operation.")
    latency: Latency = Field(..., description="Information about latency of various stage of request and response.")
    namespace: Optional[str] = Field(None, description="The namespace of the object.")
    pipelineName: str = Field(..., description="The name of the particular pipeline that extracted the text.")
    principal: Principal = Field(..., description="The principal of the object.")
    provider: str = Field(..., description="The provider to use.")
    reasons: Optional[List[str]] = Field(None, description="The various reasons returned by the policy engine.")
    time: datetime = Field(..., description="Set the time of the message request.")
    type: str = Field(..., description="The type of text.")
