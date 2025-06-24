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
"""Kaspersky locations transform module."""

import json
from typing import Dict, List

import stix2
from pycti import Location

from .transform import Transform
from .locations import decode_locations
from .utils import LOCATION_ROLE, LocationRoles


def parse_locations(value: str, location_role: str, author_id: str):
    """
        Check the input string and generate stix2 location objects
        if there are locations defined. Specified location role is
        applied for all generated stix2 objects as special attribute.
    :param value: input string to parse.
    :param location_role: role to apply for all parsed locations.
    :return:
    """
    stix_objects = []
    locations = decode_locations(value)
    for location in locations:
        stix_object = stix2.v21.Location(
            id=Location.generate_id(
                name=location.country.geo_code, x_opencti_location_type="Country"
            ),
            name=location.country.title,
            country=location.country.geo_code,
            region=location.sub_region.stix_code,
            labels=location.country.labels,
            created_by_ref=author_id,
        )
        stix_object = json.loads(stix_object.serialize())
        stix_object[LOCATION_ROLE] = location_role
        stix_objects.append(stix_object)

        stix_object = stix2.v21.Location(
            id=Location.generate_id(
                name=location.sub_region.stix_code, x_opencti_location_type="Region"
            ),
            name=location.sub_region.title,
            region=location.sub_region.stix_code,
            created_by_ref=author_id,
        )

        stix_object = json.loads(stix_object.serialize())
        stix_object[LOCATION_ROLE] = location_role
        stix_objects.append(stix_object)

    return stix_objects


class LocationsTransform(Transform):
    """Transform for locations."""

    def build_objects(self, indicator: Dict, context: Dict) -> List[Dict]:
        stix_objects = []

        fields = [
            (LocationRoles.TARGET, "geo"),
            (LocationRoles.TARGET, "users_geo"),
            (LocationRoles.ACTOR, "ip_geo"),
        ]

        for location_role, field_name in fields:
            if field_name in context:
                locations = parse_locations(
                    value=context[field_name],
                    location_role=location_role,
                    author_id=self._author["id"],
                )
                stix_objects.extend(locations)

        return stix_objects
