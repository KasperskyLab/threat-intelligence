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
"""Kaspersky transform module."""

from typing import Dict, List


class Transform:
    """
    Transform interface provides methods for building additional stix 2.1
    objects and relationships by checking context of stix 2.1 indicator
    object received from Kaspersky TAXII server.
    """

    def __init__(self, author: Dict) -> None:
        """Initialize transform object."""
        self._author = author

    # pylint: disable-next=unused-argument
    def build_objects(self, indicator: Dict, context: Dict) -> List[Dict]:
        """
            Build new stix 2.1 objects based on indicator's context.
        :param indicator: original stix 2.1 indicator object.
        :param context: parsed context of the indicator object.
        :return: list of new stix 2.1 objects.
        """
        return []

    # pylint: disable-next=unused-argument
    def build_relationships(self, stix_objects: List[Dict]) -> List[Dict]:
        """
            Build new stix 2.1 relationships between objects.
        :param stix_objects: all stix 2.1 objects to consider.
        :return: list of new stix 2.1 relationships.
        """
        return []
