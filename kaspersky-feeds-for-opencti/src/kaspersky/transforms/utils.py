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
"""Kaspersky utils module."""

import json
import re
from enum import Enum
from typing import Dict

import stix2
from pycti import StixCoreRelationship


# pylint: disable-next=pointless-string-statement
"""Prefix to mark internal attributes."""
TEMPORAL_ATTRIBUTE_PREFIX = "x-kaspersky-"


# pylint: disable-next=pointless-string-statement
"""Attribute fields to store some internal information for processing strix objects."""
LOCATION_ROLE = f"{TEMPORAL_ATTRIBUTE_PREFIX}location_role"
MALWARE_ROLE = f"{TEMPORAL_ATTRIBUTE_PREFIX}malware_role"


# Regular expression to match quoted words that may contain escaped quotation mark inside
QUOTED_WORD_PATTERN = re.compile(
    r"'((?:\\'|[^'])*)'"
)

class LocationRoles(Enum):
    """Meanings of location."""

    ACTOR = "actor"
    TARGET = "target"


class MalwareRoles(Enum):
    """Meanings of location."""

    REAL_ACTOR = "actor"
    FAKE_GROUP = "group"


def build_relationship(source: Dict, target: Dict, link_type: str, created_by_ref: str, description: str = "", labels: list[str] = []) -> Dict:
    """
        Creates stix 2.1 relationship object.
    :param source: relationship source object.
    :param target: relationship target object.
    :param link_type: relationship type.
    :return: stix 2.1 relationship object.
    """
    link_source = source["id"]
    link_target = target["id"]
    stix_object = stix2.v21.Relationship(
        id=StixCoreRelationship.generate_id(
            relationship_type=link_type, source_ref=link_source, target_ref=link_target
        ),
        relationship_type=link_type,
        source_ref=link_source,
        target_ref=link_target,
        created_by_ref=created_by_ref,
        description=description,
        labels=labels,
    )
    return json.loads(stix_object.serialize())

def extract_first_quoted_word(pattern: str):
    match = QUOTED_WORD_PATTERN.search(pattern)
    if match:
        return match.group(1)
