# pylint: disable=protected-access

import os
import base64
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union
from acuvity.models import Analyzer, Extractionrequest, Policerequest, Policeresponse, Scanrequest, Scanresponse, ScanrequestType, Type, ScanrequestAnonymization, Anonymization, Policeexternaluser
from acuvity.sdkconfiguration import SDKConfiguration

from .apex import Apex

class ApexExtended(Apex):
    def __init__(self, sdk_config: SDKConfiguration) -> None:
        super().__init__(sdk_config)
        self._available_analyzers: Optional[List[Analyzer]] = None

    def list_analyzer_groups(self) -> List[str]:
        """
        list_analyzer_groups() returns a list of all available analyzer groups. These can be passed in a scan request
        to activate/deactivate a whole group of analyzers at once.

        NOTE: this call is cached for the lifetime of the SDK object.
        """
        if self._available_analyzers is None:
            self._available_analyzers = self.list_analyzers()
        return sorted({ a.group for a in self._available_analyzers if a.group is not None })

    def list_analyzer_names(self, group: Optional[str] = None) -> List[str]:
        """
        list_analyzer_names() returns a list of all available analyzer names. These can be passed in a scan request
        to activate/deactivate specific analyzers.

        :param group: the group of analyzers to filter the list by. If not provided, all analyzers will be returned.

        NOTE: this call is cached for the lifetime of the SDK object.
        """
        if self._available_analyzers is None:
            self._available_analyzers = self.list_analyzers()
        return sorted([ a.id for a in self._available_analyzers if (group is None or a.group == group) and a.id is not None ])

    def scan(
        self,
        *messages: str,
        files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
        request_type: Union[ScanrequestType,str] = ScanrequestType.INPUT,
        annotations: Optional[Dict[str, str]] = None,
        analyzers: Optional[List[str]] = None,
        bypass_hash: Optional[str] = None,
        anonymization: Union[ScanrequestAnonymization, str, None] = None,
        redactions: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        access_policy: Optional[str] = None,
        content_policy: Optional[str] = None,
    ) -> Scanresponse:
        """
        scan() runs the provided messages (prompts) through the Acuvity detection engines and returns the results. Alternatively, you can run model output through the detection engines.
        Returns a Scanresponse object on success, and raises different exceptions on failure.

        This function allows to use and try different analyzers and make use of the redaction feature.
        You can also run access policies and content policies by passing them as parameters.

        :param messages: the messages to scan. These are the prompts that you want to scan. Required if no files or a direct request object are provided.
        :param files: the files to scan. These are the files that you want to scan. Required if no messages are provided. Can be used in addition to messages.
        :param request_type: the type of the validation. This can be either ScanrequestType.INPUT or ScanrequestType.OUTPUT. Defaults to ScanrequestType.INPUT. Use ScanrequestType.OUTPUT if you want to run model output through the detection engines.
        :param annotations: the annotations to use. These are the annotations that you want to use. If not provided, no annotations will be used.
        :param analyzers: the analyzers to use. These are the analyzers that you want to use. If not provided, the internal default analyzers will be used. Use "+" to include an analyzer and "-" to exclude an analyzer. For example, ["+image-classifier", "-modality-detector"] will include the image classifier and exclude the modality detector. If any analyzer does not start with a '+' or '-', then the default analyzers will be replaced by whatever is provided. Call `list_analyzers()` and/or its variants to get a list of available analyzers.
        :param bypass_hash: the bypass hash to use. This is the hash that you want to use to bypass the detection engines. If not provided, no bypass hash will be used.
        :param anonymization: the anonymization to use. This is the anonymization that you want to use. If not provided, but the returned detections contain redactions, then the system will use the internal defaults for anonymization which is subject to change.
        :param redactions: the redactions to apply. If your want to redact certain parts of the returned detections, you can provide a list of redactions that you want to apply. If not provided, no redactions will be applied.
        :param keywords: the keywords to detect in the input. If you want to detect certain keywords in the input, you can provide a list of keywords that you want to detect. If not provided, no keyword detection will be run.
        :param access_policy: the access policy to run. This is the rego access policy that you can run. If not provided, no access policy will be applied.
        :param content_policy: the content policy to run. This is the rego content policy that you can run. If not provided, no content policy will be applied.
        """
        return self.scan_request(request=self.__build_scan_request(
            *messages,
            files=files,
            request_type=request_type,
            annotations=annotations,
            analyzers=analyzers,
            bypass_hash=bypass_hash,
            anonymization=anonymization,
            redactions=redactions,
            keywords=keywords,
            access_policy=access_policy,
            content_policy=content_policy,
        ))

    async def scan_async(
        self,
        *messages: str,
        files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
        request_type: Union[ScanrequestType,str] = ScanrequestType.INPUT,
        annotations: Optional[Dict[str, str]] = None,
        analyzers: Optional[List[str]] = None,
        bypass_hash: Optional[str] = None,
        anonymization: Union[ScanrequestAnonymization, str, None] = None,
        redactions: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        access_policy: Optional[str] = None,
        content_policy: Optional[str] = None,
    ) -> Scanresponse:
        """
        scan_async() runs the provided messages (prompts) through the Acuvity detection engines and returns the results. Alternatively, you can run model output through the detection engines.
        Returns a Scanresponse object on success, and raises different exceptions on failure.

        This function allows to use and try different analyzers and make use of the redaction feature.
        You can also run access policies and content policies by passing them as parameters.

        :param messages: the messages to scan. These are the prompts that you want to scan. Required if no files or a direct request object are provided.
        :param files: the files to scan. These are the files that you want to scan. Required if no messages are provided. Can be used in addition to messages.        :param request_type: the type of the validation. This can be either ScanrequestType.INPUT or ScanrequestType.OUTPUT. Defaults to ScanrequestType.INPUT. Use ScanrequestType.OUTPUT if you want to run model output through the detection engines.
        :param annotations: the annotations to use. These are the annotations that you want to use. If not provided, no annotations will be used.
        :param analyzers: the analyzers to use. These are the analyzers that you want to use. If not provided, the internal default analyzers will be used. Use "+" to include an analyzer and "-" to exclude an analyzer. For example, ["+image-classifier", "-modality-detector"] will include the image classifier and exclude the modality detector. If any analyzer does not start with a '+' or '-', then the default analyzers will be replaced by whatever is provided. Call `list_analyzers()` and/or its variants to get a list of available analyzers.
        :param bypass_hash: the bypass hash to use. This is the hash that you want to use to bypass the detection engines. If not provided, no bypass hash will be used.
        :param anonymization: the anonymization to use. This is the anonymization that you want to use. If not provided, but the returned detections contain redactions, then the system will use the internal defaults for anonymization which is subject to change.
        :param redactions: the redactions to apply. If your want to redact certain parts of the returned detections, you can provide a list of redactions that you want to apply. If not provided, no redactions will be applied.
        :param keywords: the keywords to detect in the input. If you want to detect certain keywords in the input, you can provide a list of keywords that you want to detect. If not provided, no keyword detection will be run.
        :param access_policy: the access policy to run. This is the rego access policy that you can run. If not provided, no access policy will be applied.
        :param content_policy: the content policy to run. This is the rego content policy that you can run. If not provided, no content policy will be applied.
        """
        return await self.scan_request_async(request=self.__build_scan_request(
            *messages,
            files=files,
            request_type=request_type,
            annotations=annotations,
            analyzers=analyzers,
            bypass_hash=bypass_hash,
            anonymization=anonymization,
            redactions=redactions,
            keywords=keywords,
            access_policy=access_policy,
            content_policy=content_policy,
        ))

    def police(
        self,
        *messages: str,
        files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
        request_type: Union[Type,str] = Type.INPUT,
        annotations: Optional[Dict[str, str]] = None,
        bypass_hash: Optional[str] = None,
        anonymization: Union[Anonymization, str, None] = None,
        provider: Optional[str] = None,
        user: Optional[Union[Policeexternaluser,Tuple[str, List[str]],Dict[str, Any]]] = None,
    ) -> Policeresponse:
        """
        police() runs the provided messages (prompts) through the Acuvity detection engines, applies policies, and returns the results. Alternatively, you can run model output through the detection engines.
        Returns a Policeresponse object on success, and raises different exceptions on failure.

        This function does **NOT** allow to use different analyzers or redactions as policies are being **managed** by the Acuvity backend.
        To configure different analyzers and redactions you must do so in the Acuvity backend.

        :param messages: the messages to scan. These are the prompts that you want to scan. Required if no files or a direct request object are provided.
        :param files: the files to scan. These are the files that you want to scan. Required if no messages are provided. Can be used in addition to messages.        :param request_type: the type of the validation. This can be either Type.INPUT or Type.OUTPUT. Defaults to Type.INPUT. Use Type.OUTPUT if you want to run model output through the detection engines.
        :param annotations: the annotations to use. These are the annotations that you want to use. If not provided, no annotations will be used.
        :param bypass_hash: the bypass hash to use. This is the hash that you want to use to bypass the detection engines. If not provided, no bypass hash will be used.
        :param anonymization: the anonymization to use. This is the anonymization that you want to use. If not provided, but the returned detections contain redactions, then the system will use the internal defaults for anonymization which is subject to change.
        :param provider: the provider to use. This is the provider name that you want to use for policy resolutions. If not provided, it will default to the principal name (the application itself).
        :param user: the user to use. This is the user name and their claims that you want to use.
        """
        return self.police_request(request=self.__build_police_request(
            *messages,
            files=files,
            request_type=request_type,
            annotations=annotations,
            bypass_hash=bypass_hash,
            anonymization=anonymization,
            provider=provider,
            user=user,
        ))

    async def police_async(
        self,
        *messages: str,
        files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
        request_type: Union[Type,str] = Type.INPUT,
        annotations: Optional[Dict[str, str]] = None,
        bypass_hash: Optional[str] = None,
        anonymization: Union[Anonymization, str, None] = None,
        provider: Optional[str] = None,
        user: Optional[Union[Policeexternaluser,Tuple[str, List[str]],Dict[str, Any]]] = None,
    ) -> Policeresponse:
        """
        police_async() runs the provided messages (prompts) through the Acuvity detection engines, applies policies, and returns the results. Alternatively, you can run model output through the detection engines.
        Returns a Policeresponse object on success, and raises different exceptions on failure.

        This function does **NOT** allow to use different analyzers or redactions as policies are being **managed** by the Acuvity backend.
        To configure different analyzers and redactions you must do so in the Acuvity backend.

        :param messages: the messages to scan. These are the prompts that you want to scan. Required if no files or a direct request object are provided.
        :param files: the files to scan. These are the files that you want to scan. Required if no messages are provided. Can be used in addition to messages.        :param request_type: the type of the validation. This can be either Type.INPUT or Type.OUTPUT. Defaults to Type.INPUT. Use Type.OUTPUT if you want to run model output through the detection engines.
        :param annotations: the annotations to use. These are the annotations that you want to use. If not provided, no annotations will be used.
        :param bypass_hash: the bypass hash to use. This is the hash that you want to use to bypass the detection engines. If not provided, no bypass hash will be used.
        :param anonymization: the anonymization to use. This is the anonymization that you want to use. If not provided, but the returned detections contain redactions, then the system will use the internal defaults for anonymization which is subject to change.
        :param provider: the provider to use. This is the provider name that you want to use for policy resolutions. If not provided, it will default to the principal name (the application itself).
        :param user: the user to use. This is the user name and their claims that you want to use.
        """
        return await self.police_request_async(request=self.__build_police_request(
            *messages,
            files=files,
            request_type=request_type,
            annotations=annotations,
            bypass_hash=bypass_hash,
            anonymization=anonymization,
            provider=provider,
            user=user,
        ))

    def __build_police_request(
        self, # pylint: disable=unused-argument
        *messages: str,
        files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
        request_type: Union[Type,str] = Type.INPUT,
        annotations: Optional[Dict[str, str]] = None,
        bypass_hash: Optional[str] = None,
        anonymization: Union[Anonymization, str, None] = None,
        provider: Optional[str] = None,
        user: Optional[Union[Policeexternaluser,Tuple[str, List[str]],Dict[str, Any]]] = None,
    ) -> Policerequest:
        request = Policerequest.model_construct()

        # messages must be strings
        for message in messages:
            if not isinstance(message, str):
                raise ValueError("messages must be strings")
        if len(messages) == 0 and files is None:
            raise ValueError("no messages and no files provided")
        if len(messages) > 0:
            request.messages = list(messages)

        # files must be a list of strings (or paths) or a single string (or path)
        extractions: List[Extractionrequest] = []
        if files is not None:
            process_files: List[Union[os.PathLike, str]] = []
            if isinstance(files, str):
                process_files.append(files)
            elif isinstance(files, os.PathLike):
                process_files.append(files)
            elif isinstance(files, Iterable):
                for file in files:
                    if not isinstance(file, str) and not isinstance(file, os.PathLike):
                        raise ValueError("files must be strings or paths")
                    process_files.append(file)
            else:
                raise ValueError("files must be strings or paths")
            for process_file in process_files:
                with open(process_file, 'rb') as opened_file:
                    file_content = opened_file.read()
                    # base64 encode the file content and then append
                    extractions.append(Extractionrequest(
                        data=base64.b64encode(file_content).decode("utf-8"),
                    ))
        if len(extractions) > 0:
            request.extractions = extractions

        # request_type must be either "Input" or "Output"
        if isinstance(request_type, Type):
            request.type = request_type
        elif isinstance(request_type, str):
            if request_type not in ("Input", "Output"):
                raise ValueError("request_type must be either 'Input' or 'Output'")
            request.type = Type(request_type)
        else:
            raise ValueError("type must be a 'str' or 'Type'")

        # annotations must be a dictionary of strings
        if annotations is not None:
            if not isinstance(annotations, dict):
                raise ValueError("annotations must be a dictionary")
            for key, value in annotations.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise ValueError("annotations must be strings")
            request.annotations = annotations

        # bypass_hash must be a string
        if bypass_hash is not None:
            if not isinstance(bypass_hash, str):
                raise ValueError("bypass_hash must be a string")
            request.bypass_hash = bypass_hash

        # anonymization must be "FixedSize" or "VariableSize"
        if anonymization is not None:
            if isinstance(anonymization, Anonymization):
                request.anonymization = anonymization
            elif isinstance(anonymization, str):
                if anonymization not in ("FixedSize", "VariableSize"):
                    raise ValueError("anonymization must be 'FixedSize' or 'VariableSize'")
                request.anonymization = Anonymization(anonymization)
            else:
                raise ValueError("anonymization must be a 'str' or 'Anonymization'")

        # provider must be a string
        if provider is not None:
            if not isinstance(provider, str):
                raise ValueError("provider must be a string")
            request.provider = provider

        if user is not None:
            if isinstance(user, tuple):
                if len(user) != 2:
                    raise ValueError("user tuple must have exactly 2 elements to represent the name and claims")
                if not isinstance(user[0], str):
                    raise ValueError("user tuple first element must be a string to represent the name")
                if not isinstance(user[1], list):
                    raise ValueError("user tuple second element must be a list to represent the claims")
                for claim in user[1]:
                    if not isinstance(claim, str):
                        raise ValueError("user tuple second element must be a list of strings to represent the claims")
                request.user = Policeexternaluser(name=user[0], claims=user[1])
            elif isinstance(user, dict):
                name = user.get("name", None)
                if name is None:
                    raise ValueError("user dictionary must have a 'name' key to represent the name")
                if not isinstance(name, str):
                    raise ValueError("user dictionary 'name' key must be a string to represent the name")
                claims = user.get("claims", None)
                if claims is None:
                    raise ValueError("user dictionary must have a 'claims' key to represent the claims")
                if not isinstance(claims, list):
                    raise ValueError("user dictionary 'claims' key must be a list to represent the claims")
                for claim in claims:
                    if not isinstance(claim, str):
                        raise ValueError("user dictionary 'claims' key must be a list of strings to represent the claims")
                request.user = Policeexternaluser(name=name, claims=claims)
            elif isinstance(user, Policeexternaluser):
                request.user = user
            else:
                raise ValueError("user must be a tuple, dictionary or Policeexternaluser object")

        return request

    def __build_scan_request(
        self,
        *messages: str,
        files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
        request_type: Union[ScanrequestType,str] = ScanrequestType.INPUT,
        annotations: Optional[Dict[str, str]] = None,
        analyzers: Optional[List[str]] = None,
        bypass_hash: Optional[str] = None,
        anonymization: Union[ScanrequestAnonymization, str, None] = None,
        redactions: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        access_policy: Optional[str] = None,
        content_policy: Optional[str] = None,
    ) -> Scanrequest:
        request = Scanrequest.model_construct()

        # messages must be strings
        for message in messages:
            if not isinstance(message, str):
                raise ValueError("messages must be strings")
        if len(messages) == 0 and files is None:
            raise ValueError("no messages and no files provided")
        if len(messages) > 0:
            request.messages = list(messages)

        # files must be a list of strings (or paths) or a single string (or path)
        extractions: List[Extractionrequest] = []
        if files is not None:
            process_files: List[Union[os.PathLike, str]] = []
            if isinstance(files, str):
                process_files.append(files)
            elif isinstance(files, os.PathLike):
                process_files.append(files)
            elif isinstance(files, Iterable):
                for file in files:
                    if not isinstance(file, str) and not isinstance(file, os.PathLike):
                        raise ValueError("files must be strings or paths")
                    process_files.append(file)
            else:
                raise ValueError("files must be strings or paths")
            for process_file in process_files:
                with open(process_file, 'rb') as opened_file:
                    file_content = opened_file.read()
                    # base64 encode the file content and then append
                    extractions.append(Extractionrequest(
                        data=base64.b64encode(file_content).decode("utf-8"),
                    ))
        if len(extractions) > 0:
            request.extractions = extractions

        # request_type must be either "Input" or "Output"
        if isinstance(request_type, ScanrequestType):
            request.type = request_type
        elif isinstance(request_type, str):
            if request_type not in ("Input", "Output"):
                raise ValueError("request_type must be either 'Input' or 'Output'")
            request.type = ScanrequestType(request_type)
        else:
            raise ValueError("type must be a 'str' or 'Type'")

        # annotations must be a dictionary of strings
        if annotations is not None:
            if not isinstance(annotations, dict):
                raise ValueError("annotations must be a dictionary")
            for key, value in annotations.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise ValueError("annotations must be strings")
            request.annotations = annotations

        # analyzers must be a list of strings
        if analyzers is not None:
            if not isinstance(analyzers, List):
                raise ValueError("analyzers must be a list")
            analyzers_list = self.list_analyzer_groups() + self.list_analyzer_names()
            for analyzer in analyzers:
                if not isinstance(analyzer, str):
                    raise ValueError("analyzers must be strings")
                if analyzer.startswith(("+", "-")):
                    analyzer = analyzer[1:]
                if analyzer not in analyzers_list:
                    raise ValueError(f"analyzer '{analyzer}' is not in list of analyzer groups or analyzers: {analyzers_list}")
            request.analyzers = analyzers

        # bypass_hash must be a string
        if bypass_hash is not None:
            if not isinstance(bypass_hash, str):
                raise ValueError("bypass_hash must be a string")
            request.bypass_hash = bypass_hash

        # anonymization must be "FixedSize" or "VariableSize"
        if anonymization is not None:
            if isinstance(anonymization, ScanrequestAnonymization):
                request.anonymization = anonymization
            elif isinstance(anonymization, str):
                if anonymization not in ("FixedSize", "VariableSize"):
                    raise ValueError("anonymization must be 'FixedSize' or 'VariableSize'")
                request.anonymization = ScanrequestAnonymization(anonymization)
            else:
                raise ValueError("anonymization must be a 'str' or 'Anonymization'")

        # redactions must be a list of strings
        if redactions is not None:
            if not isinstance(redactions, List):
                raise ValueError("redactions must be a list")
            for redaction in redactions:
                if not isinstance(redaction, str):
                    raise ValueError("redactions must be strings")
            request.redactions = redactions

        # keywords must be a list of strings
        if keywords is not None:
            if not isinstance(keywords, List):
                raise ValueError("keywords must be a list")
            for keyword in keywords:
                if not isinstance(keyword, str):
                    raise ValueError("keywords must be strings")
            request.keywords = keywords

        # local access policy
        if access_policy is not None:
            if not isinstance(access_policy, str):
                raise ValueError("access_policy must be a string")
            request.access_policy = access_policy

        # local content policy
        if content_policy is not None:
            if not isinstance(content_policy, str):
                raise ValueError("content_policy must be a string")
            request.content_policy = content_policy

        return request
