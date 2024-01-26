#!/usr/bin/env python3
# © 2024 AO Kaspersky Lab. All Rights Reserved.
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
