#!/usr/bin/env python3
# © 2024 AO Kaspersky Lab. All Rights Reserved.
"""Kaspersky utils module."""

import json
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


class LocationRoles(Enum):
    """Meanings of location."""

    ACTOR = "actor"
    TARGET = "target"


class MalwareRoles(Enum):
    """Meanings of location."""

    REAL_ACTOR = "actor"
    FAKE_GROUP = "group"


def build_relationship(source: Dict, target: Dict, link_type: str) -> Dict:
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
    )
    return json.loads(stix_object.serialize())
