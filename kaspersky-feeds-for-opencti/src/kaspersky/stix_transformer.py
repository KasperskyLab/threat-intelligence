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

import re
import json
from typing import Dict, Generator, List
from datetime import datetime

import stix2
from pycti import Identity, Indicator

from .stix_source import Stix21Source
from .transforms import (
    TEMPORAL_ATTRIBUTE_PREFIX,
    ActorsTransform,
    IndicatorsTransform,
    IndustriesTransform,
    LocationsTransform,
    MalwaresTransform,
    ReportsTransform,
    ObservableTransform,
    extract_first_quoted_word
)


KASPERSKY_NAME = "Kaspersky"
KASPERSKY_CONTACTS = "site: www.kaspersky.com"
KASPERSKY_DESCRIPTION = (
    "Kaspersky Lab develops and markets antivirus, internet security, "
    "password management, endpoint security, and other cybersecurity "
    "products and services"
)
DEFAULT_SOURCE_BATCH_SIZE = 100


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
    # set name to first value in pattern
    if stix_object["type"] == "indicator" and "pattern" in stix_object:
        ioc_type = stix_object.get("name", "")
        pattern = stix_object["pattern"]

        match = re.search(r"\[(.+?):.*'(.*?)\'\]", pattern)
        if match is not None:
            if match[1] == "ipv4-addr":
                stix_object["x_opencti_main_observable_type"] = "IPv4-Addr"
            elif match[1] == "ipv6-addr":
                stix_object["x_opencti_main_observable_type"] = "IPv6-Addr"
            elif match[1] == "file":
                stix_object["x_opencti_main_observable_type"] = "File"
            elif match[1] == "domain-name":
                stix_object["x_opencti_main_observable_type"] = "Domain-Name"
            elif match[1] == "url":
                stix_object["x_opencti_main_observable_type"] = "Url"
            elif match[1] == "email-addr":
                stix_object["x_opencti_main_observable_type"] = "Email-Addr"

        if ioc_type == "URL" and " LIKE " in pattern[:pattern.find("'")]:
            stix_object["name"] = extract_first_quoted_word(pattern).replace("%", "*").replace("_", "?")
        else:
            stix_object["name"] = extract_first_quoted_word(pattern)

    # remove internal attributes
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

    def __init__(self, source: Stix21Source, expand_objects: bool, create_indicators: bool, create_observables: bool):
        """
            Initialize stix 2.1 transformer.
        :param source: source of stix 2.1 objects.
        """
        super().__init__()
        self._source = source
        self._author = create_author()
        self._expand_objects = expand_objects
        self._create_indicators = create_indicators
        self._create_observables = create_observables

    def _build_transforms(self):
        if not self._expand_objects:
            return []

        transforms = [
            ActorsTransform(author=self._author),
            IndicatorsTransform(
                author=self._author,
                link_with_observables=(
                    self._create_observables and not self._create_indicators
                ),
            ),
            IndustriesTransform(author=self._author),
            LocationsTransform(author=self._author),
            MalwaresTransform(author=self._author),
            ReportsTransform(author=self._author),
        ]
        if self._create_observables:
            transforms.append(ObservableTransform(author=self._author))
        return transforms

    def _source_batches(
        self, added_after: datetime = None, size: int = DEFAULT_SOURCE_BATCH_SIZE
    ) -> Generator[List[Dict], None, None]:
        if size <= 0:
            raise ValueError("source batch size must be greater than zero")

        batch = []
        for stix_object in self._source.enumerate(added_after):
            batch.append(stix_object)
            if len(batch) >= size:
                yield batch
                batch = []

        if batch:
            yield batch

    def _append_deduplicated(
        self,
        bundle_order: List[str],
        bundle_by_id: Dict,
        stix_object: Dict,
    ):
        object_id = stix_object["id"]
        if object_id not in bundle_by_id:
            bundle_order.append(object_id)
        # Keep the latest representation, e.g. a finalized report with
        # complete batch-local object_refs.
        bundle_by_id[object_id] = processed_stix_object(stix_object)

    @staticmethod
    def _normalize_indicator_id(stix_object: Dict) -> None:
        if stix_object.get("type") != "indicator" or "pattern" not in stix_object:
            return

        source_id = stix_object.get("id")
        standard_id = Indicator.generate_id(stix_object["pattern"])
        if source_id == standard_id:
            return

        source_ids = list(stix_object.get("x_opencti_stix_ids") or [])
        if source_id and source_id not in source_ids:
            source_ids.append(source_id)
        stix_object["x_opencti_stix_ids"] = source_ids
        stix_object["id"] = standard_id

    def _transform_source_batch(self, source_batch: List[Dict]) -> List[Dict]:
        transforms = self._build_transforms()
        bundle_order = []
        bundle_by_id = {}

        self._append_deduplicated(bundle_order, bundle_by_id, dict(self._author))

        for stix_object in source_batch:
            object_type = stix_object["type"]
            if object_type != "indicator":
                self._append_deduplicated(bundle_order, bundle_by_id, stix_object)
                continue

            author_id = self._author["id"]
            self._normalize_indicator_id(stix_object)
            stix_object["created_by_ref"] = author_id

            stix_objects = [stix_object]
            context = extract_context(stix_object)
            for transform in transforms:
                stix_objects.extend(
                    transform.build_objects(indicator=stix_object, context=context)
                )

            stix_relationships = []
            if len(stix_objects) > 1:
                for transform in transforms:
                    if self._create_indicators:
                        stix_relationships.extend(
                            transform.build_relationships(stix_objects)
                        )
                    else:
                        # do not create relationships for indicators
                        # because they are not created
                        stix_relationships.extend(
                            transform.build_relationships(stix_objects[1:])
                        )

            if self._create_indicators:
                self._append_deduplicated(
                    bundle_order, bundle_by_id, stix_objects[0]
                )

            for expanded_object in stix_objects[1:]:
                self._append_deduplicated(
                    bundle_order, bundle_by_id, expanded_object
                )

            for relationship in stix_relationships:
                self._append_deduplicated(bundle_order, bundle_by_id, relationship)

        for transform in transforms:
            for stix_object in transform.finalize_objects():
                self._append_deduplicated(bundle_order, bundle_by_id, stix_object)

        return [bundle_by_id[object_id] for object_id in bundle_order]

    def enumerate_batches(
        self,
        added_after: datetime = None,
        size: int = DEFAULT_SOURCE_BATCH_SIZE,
    ) -> Generator[List[Dict], None, None]:
        """
            Enumerate self-contained transformed STIX 2.1 bundles.
        :param added_after: datetime filter to skip old objects (optional).
        :param size: number of source objects to transform into one bundle.
        :return: generator of bundle lists.
        """
        for source_batch in self._source_batches(added_after=added_after, size=size):
            transformed_batch = self._transform_source_batch(source_batch)
            if transformed_batch:
                yield transformed_batch

    def enumerate_clusters(
        self, added_after: datetime = None
    ) -> Generator[List[Dict], None, None]:
        """
            Enumerate available stix 2.1 objects grouped into atomic clusters.
        :param added_after: datetime filter to skip old objects (optional).
        :return: generator of cluster lists.
        """
        yield from self.enumerate_batches(added_after=added_after, size=1)

    def enumerate(self, added_after: datetime = None) -> Generator[Dict, None, None]:
        """
            Enumerate available stix 2.1 objects.
        :param added_after: datetime filter to skip old objects (optional).
        :return: generator of the stix items.
        """
        for cluster in self.enumerate_clusters(added_after=added_after):
            for stix_object in cluster:
                yield stix_object
