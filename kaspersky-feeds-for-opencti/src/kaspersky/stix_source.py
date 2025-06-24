#!/usr/bin/env python3
#
# © 2024 AO Kaspersky Lab. All Rights Reserved.
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
"""Kaspersky stix source module."""

from datetime import datetime
from typing import Dict, Generator


# pylint: disable-next=too-few-public-methods
class Stix21Source:
    """Interface for source of stix 2.1 objects."""

    def enumerate(self, added_after: datetime = None) -> Generator[Dict, None, None]:
        """
            Enumerate available stix 2.1 objects.
        :param added_after: datetime filter to skip old objects (optional).
        :return: generator of the stix items.
        """
        raise NotImplementedError()
