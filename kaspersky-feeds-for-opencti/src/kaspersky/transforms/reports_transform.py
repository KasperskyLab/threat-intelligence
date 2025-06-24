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
"""Kaspersky reports transform module."""

import json
from typing import Dict, List

import stix2
from pycti import Report

from .transform import Transform


def format_report_url(report_id: str):
    """Make url to access report."""
    # pylint: disable-next=line-too-long
    return f"https://tip.kaspersky.com/api/publications/get_one?publication_id={report_id}&include_info=pdf"


def build_external_reference(
    report_name: str, report_uuid: str
) -> List[stix2.v21.ExternalReference]:
    """Build ExternalReference stix2 object if it could be created."""
    if report_uuid is None:
        return None

    report_url = format_report_url(report_uuid)
    report_object = stix2.v21.ExternalReference(
        source_name="Kaspersky",
        description=report_name,
        external_id=report_uuid,
        url=report_url,
    )
    return [report_object]


class ReportsTransform(Transform):
    """Transform for reports."""

    def build_objects(self, indicator: Dict, context: Dict) -> List[Dict]:
        if "publication_name" not in context:
            return []

        report_name = context["publication_name"]
        report_uuid = context.get("api_publication_id", None)
        report_timestamp = context.get("detection_date", "1900-01-01T00:00:00.000Z")
        stix_object = stix2.v21.Report(
            id=Report.generate_id(name=report_name, published=report_timestamp),
            name=report_name,
            published=report_timestamp,
            report_types=["indicator"],
            object_refs=[indicator["id"]],
            created_by_ref=self._author["id"],
            external_references=build_external_reference(
                report_name=report_name, report_uuid=report_uuid
            ),
        )
        return [json.loads(stix_object.serialize())]

    def build_relationships(self, stix_objects: List[Dict]) -> List[Dict]:
        linked_types = ["threat-actor", "indicator"]

        object_refs = []
        report_types = set()
        for stix_object in stix_objects:
            object_type = stix_object["type"]
            if object_type in linked_types:
                object_refs.append(stix_object["id"])
                report_types.add(object_type)
                continue

        if len(object_refs) == 0:
            return []

        reports = filter(lambda object: object["type"] == "report", stix_objects)
        for report in reports:
            report["object_refs"] = object_refs
            report["report_types"] = list(report_types)

        return []
