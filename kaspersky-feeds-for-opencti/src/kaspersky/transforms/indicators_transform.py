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
"""Kaspersky indicators transform module."""

from typing import Dict, List

from .transform import Transform
from .utils import (
    LOCATION_ROLE,
    MALWARE_ROLE,
    LocationRoles,
    MalwareRoles,
    build_relationship,
)


class IndicatorsTransform(Transform):
    """Transform for indicators."""

    def build_relationships(self, stix_objects: List[Dict]) -> List[Dict]:
        indicators = filter(lambda object: object["type"] == "indicator", stix_objects)

        relationships = []
        for indicator in indicators:
            for stix_object in stix_objects:
                # pylint: disable-next=duplicate-code
                object_type = stix_object["type"]

                if object_type == "threat-actor":
                    relationships.append(
                        build_relationship(
                            source=indicator, target=stix_object, link_type="indicates"
                        )
                    )

                elif object_type == "location":
                    if LOCATION_ROLE in stix_object:
                        location_role = stix_object[LOCATION_ROLE]
                        if location_role == LocationRoles.ACTOR:
                            relationships.append(
                                build_relationship(
                                    source=indicator,
                                    target=stix_object,
                                    link_type="related-to",
                                )
                            )

                elif object_type == "malware":
                    # pylint: disable-next=duplicate-code
                    malware_role = stix_object.get(MALWARE_ROLE, None)
                    if malware_role == MalwareRoles.REAL_ACTOR:
                        relationships.append(
                            build_relationship(
                                source=indicator,
                                target=stix_object,
                                link_type="indicates",
                            )
                        )

        return relationships
