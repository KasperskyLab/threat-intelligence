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
"""Kaspersky actors transform module."""

import json
from typing import Dict, List

import stix2
from pycti import ThreatActor

from .transform import Transform
from .utils import (
    LOCATION_ROLE,
    MALWARE_ROLE,
    LocationRoles,
    MalwareRoles,
    build_relationship,
)


def location_link_type(location_object: Dict) -> str:
    """Estimate relationship link type based on location object attributes."""
    match location_object.get(LOCATION_ROLE, None):
        case LocationRoles.ACTOR:
            return "located-at"
        case LocationRoles.TARGET:
            return "targets"
        case _:
            return "related-to"


class ActorsTransform(Transform):
    """Transform for threat actors."""

    def build_objects(self, indicator: Dict, context: Dict) -> List[Dict]:
        if "actors" not in context:
            return []

        stix_objects = []
        for actor_name in context["actors"].split(","):
            actor_name = actor_name.strip()
            if len(actor_name) == 0:
                continue

            stix_object = stix2.v21.ThreatActor(
                id=ThreatActor.generate_id(actor_name),
                name=actor_name,
                created_by_ref=self._author["id"],
            )
            stix_objects.append(json.loads(stix_object.serialize()))

        return stix_objects

    def build_relationships(self, stix_objects: List[Dict]) -> List[Dict]:
        threat_actors = filter(
            lambda stix_object: stix_object["type"] == "threat-actor", stix_objects
        )

        relationships = []
        for threat_actor in threat_actors:
            for stix_object in stix_objects:
                # pylint: disable-next=duplicate-code
                object_type = stix_object["type"]

                if object_type == "identity":
                    identity_class = stix_object["identity_class"]
                    if identity_class == "class":
                        relationships.append(
                            build_relationship(
                                source=threat_actor,
                                target=stix_object,
                                link_type="targets",
                            )
                        )

                elif object_type == "location":
                    link_type = location_link_type(stix_object)
                    relationships.append(
                        build_relationship(
                            source=threat_actor, target=stix_object, link_type=link_type
                        )
                    )

                elif object_type == "malware":
                    # pylint: disable-next=duplicate-code
                    malware_role = stix_object.get(MALWARE_ROLE, None)
                    if malware_role == MalwareRoles.REAL_ACTOR:
                        relationships.append(
                            build_relationship(
                                source=threat_actor,
                                target=stix_object,
                                link_type="uses",
                            )
                        )

        return relationships
