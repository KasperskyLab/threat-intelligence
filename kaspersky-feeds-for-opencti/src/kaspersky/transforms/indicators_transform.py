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

    def __init__(self, author: Dict, link_with_observables: bool = False):
        super().__init__(author=author)
        self.link_with_observables = link_with_observables

    def build_relationships(self, stix_objects: List[Dict]) -> List[Dict]:
        if self.link_with_observables:
            indicators = filter(lambda object: object["type"] in [
                "file",
                "domain-name",
                "url",
                "ipv4-addr"
            ], stix_objects)
        else:
            indicators = filter(lambda object: object["type"] == "indicator", stix_objects)

        relationships = []
        for indicator in indicators:
            for stix_object in stix_objects:
                # pylint: disable-next=duplicate-code
                object_type = stix_object["type"]

                if object_type == "threat-actor":
                    relationships.append(
                        build_relationship(
                            source=indicator,
                            target=stix_object,
                            link_type="indicates" if not self.link_with_observables else "related-to",
                            created_by_ref=self._author["id"],
                            description=indicator.get("description", ""),
                            labels=indicator.get("labels", []),
                        )
                    )

                elif object_type == "location":
                    relationships.append(
                        build_relationship(
                            source=indicator,
                            target=stix_object,
                            link_type="related-to",
                            created_by_ref=self._author["id"],
                            description=indicator.get("description", ""),
                            labels=indicator.get("labels", []),
                        )
                    )

                elif object_type == "malware":
                    relationships.append(
                        build_relationship(
                            source=indicator,
                            target=stix_object,
                            link_type="related-to",
                            created_by_ref=self._author["id"],
                            description=indicator.get("description", ""),
                            labels=indicator.get("labels", []),
                        )
                    )

                elif object_type == "identity":
                    identity_class = stix_object["identity_class"]
                    if identity_class == "class":
                        relationships.append(
                            build_relationship(
                                source=indicator,
                                target=stix_object,
                                link_type="related-to",
                                created_by_ref=self._author["id"],
                                description=indicator.get("description", ""),
                                labels=indicator.get("labels", []),
                            )
                        )

                elif not self.link_with_observables and object_type in ["file", "domain-name", "url", "ipv4-addr"]:
                    relationships.append(
                        build_relationship(
                            source=indicator,
                            target=stix_object,
                            link_type="based-on",
                            created_by_ref=self._author["id"],
                            description=indicator.get("description", ""),
                            labels=indicator.get("labels", []),
                        )
                    )

        return relationships
