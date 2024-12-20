# pylint: disable=protected-access

import os
import base64
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union
from acuvity.models import Analyzer, Extractionrequest, Scanrequest, Scanresponse, Type, Anonymization, Scanexternaluser

from .apex import Apex

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

_available_analyzers: Optional[List[Analyzer]] = None

setattr(Apex, "_available_analyzers", _available_analyzers)
setattr(Apex, "list_analyzer_groups", list_analyzer_groups)
setattr(Apex, "list_analyzer_names", list_analyzer_names)
