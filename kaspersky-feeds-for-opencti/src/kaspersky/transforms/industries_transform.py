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
"""Kaspersky industries transform module."""

import json
from typing import Dict, List

import stix2
from pycti import Identity

from .transform import Transform


class IndustriesTransform(Transform):
    """Transform for industries."""

    def build_objects(self, indicator: Dict, context: Dict) -> List[Dict]:
        industry_names = []
        for field_name in ["industries", "industry"]:
            if field_name in context:
                industry_names.extend(context[field_name].split(","))

        stix_objects = []
        for industry_name in industry_names:
            industry_name = industry_name.strip()
            if len(industry_name) == 0:
                continue
            if industry_name.lower() == "other":
                continue

            identity_class = "class"
            stix_object = stix2.v21.Identity(
                id=Identity.generate_id(
                    name=industry_name, identity_class=identity_class
                ),
                name=industry_name,
                identity_class=identity_class,
                created_by_ref=self._author["id"],
            )
            stix_objects.append(json.loads(stix_object.serialize()))

        return stix_objects
