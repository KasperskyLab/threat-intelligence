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
""" Kaspersky stix transformer module."""

import json
from typing import Dict, Generator
from datetime import datetime

import stix2
from pycti import Identity

from .stix_source import Stix21Source
from .transforms import (
    TEMPORAL_ATTRIBUTE_PREFIX,
    ActorsTransform,
    IndicatorsTransform,
    IndustriesTransform,
    LocationsTransform,
    MalwaresTransform,
    ReportsTransform,
)


KASPERSKY_NAME = "Kaspersky"
KASPERSKY_CONTACTS = "site: www.kaspersky.com"
KASPERSKY_DESCRIPTION = (
    "Kaspersky Lab develops and markets antivirus, internet security, "
    "password management, endpoint security, and other cybersecurity "
    "products and services"
)


def create_author() -> Dict:
    """Create stix 2.1 identity object which is represented Kaspersky Lab."""
    identity_class = "organization"
    stix_object = stix2.v21.Identity(
        id=Identity.generate_id(name=KASPERSKY_NAME, identity_class=identity_class),
        name=KASPERSKY_NAME,
        identity_class=identity_class,
        description=KASPERSKY_DESCRIPTION,
        contact_information=KASPERSKY_CONTACTS,
    )
    return json.loads(stix_object.serialize())


def extract_context(stix_object: Dict) -> Dict:
    """Extract context from stix 2.1 indicator object."""
    if "description" not in stix_object:
        return {}

    context = {}
    for item in stix_object["description"].split(";"):
        parts = item.split("=")
        if len(parts) < 2:
            continue
        field_name = parts[0]
        field_value = "=".join(parts[1:])
        context[field_name] = field_value

    return context


def processed_stix_object(stix_object: Dict) -> Dict:
    """Process stix2 object by adjusting some fields."""
    attributes = list(stix_object.keys())
    for attribute in attributes:
        if attribute.startswith(TEMPORAL_ATTRIBUTE_PREFIX):
            del stix_object[attribute]
    return stix_object


# pylint: disable-next=too-few-public-methods
class Stix21Transformer(Stix21Source):
    """
    Wrapper for stix 2.1 objects source to scan indicators
    context and generate additional objects from the context.
    """

    def __init__(self, source: Stix21Source):
        """
            Initialize stix 2.1 transformer.
        :param source: source of stix 2.1 objects.
        """
        super().__init__()
        self._source = source
        self._author = create_author()
        self._enumerated_objects = set()
        self._transforms = [
            ActorsTransform(author=self._author),
            IndicatorsTransform(author=self._author),
            IndustriesTransform(author=self._author),
            LocationsTransform(author=self._author),
            MalwaresTransform(author=self._author),
            ReportsTransform(author=self._author),
        ]

    def enumerate(self, added_after: datetime = None) -> Generator[Dict, None, None]:
        """
            Enumerate available stix 2.1 objects.
        :param added_after: datetime filter to skip old objects (optional).
        :return: generator of the stix items.
        """
        is_first_object = True
        for stix_object in self._source.enumerate(added_after):
            if is_first_object:
                is_first_object = False
                yield self._author

            object_type = stix_object["type"]
            if object_type != "indicator":
                yield stix_object
                continue

            author_id = self._author["id"]
            stix_object["created_by_ref"] = author_id

            stix_objects = [stix_object]
            context = extract_context(stix_object)
            for transform in self._transforms:
                stix_objects.extend(
                    transform.build_objects(indicator=stix_object, context=context)
                )

            stix_relationships = []
            if len(stix_objects) > 1:
                for transform in self._transforms:
                    stix_relationships.extend(
                        transform.build_relationships(stix_objects)
                    )

            # note: the first object is original indicator and we
            # don't want to use self._enumerated_objects filter for
            # it, so we handle it separetly.
            yield processed_stix_object(stix_objects[0])

            for stix_object in stix_objects[1:]:
                object_id = stix_object["id"]
                if object_id in self._enumerated_objects:
                    continue

                self._enumerated_objects.add(object_id)
                yield processed_stix_object(stix_object)

            for stix_relationship in stix_relationships:
                yield stix_relationship

        # cleanup allocated resources
        self._enumerated_objects = set()
