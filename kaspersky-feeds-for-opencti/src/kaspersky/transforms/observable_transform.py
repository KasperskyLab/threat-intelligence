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
"""Kaspersky observable transform module."""

import json
import re
from typing import Dict, List

import stix2
from pycti import StixCoreRelationship

from .transform import Transform
from .utils import extract_first_quoted_word

# Regular expression to match hash types and values
HASH_PATTERN = re.compile(
    r"file:hashes\.'?(MD5|SHA-1|SHA-256)'? ?= ?'([a-fA-F0-9]{32,64})'"
)

def extract_file_hashes(pattern: str):
    hashes = {}
    # Find all hash occurrences in the pattern
    matches = HASH_PATTERN.findall(pattern)
    for hash_type, hash_value in matches:
        hashes[hash_type] = hash_value
    return hashes

def extract_multiple_file_hashes(pattern: str):
    files = []
    hashes = {}
    # Find all hash occurrences in the pattern
    matches = HASH_PATTERN.findall(pattern)
    for hash_type, hash_value in matches:
        if hash_type == "MD5" and hashes.get("MD5") is not None:
            files.append(hashes.copy())
            hashes = {}
        hashes[hash_type] = hash_value
    if hashes.get("MD5") is not None:
        files.append(hashes.copy())
    return files

class ObservableTransform(Transform):
    """Transform for observables."""

    def build_objects(self, indicator: Dict, context: Dict) -> List[Dict]:
        if "pattern" not in indicator:
            return []

        return list(map(lambda stix_object: json.loads(stix_object.serialize()), self.create_observables(indicator)))

    def create_observables(self, stix_indicator: Dict) -> List[Dict]:
        ioc_type = stix_indicator.get("name", "")
        shared = {
            "allow_custom": True,
            "x_opencti_created_by_ref": self._author["id"],
            "custom_properties": {
                "x_opencti_score": stix_indicator.get("x_opencti_score", []),
                "x_opencti_labels": stix_indicator.get("labels", []),
                "x_opencti_description": stix_indicator.get("description", "")
            },
        }
        stix_observ_arr = []
        if ioc_type == "Hash":
            stix_observ_arr.append(stix2.v21.File(
                hashes=extract_file_hashes(stix_indicator["pattern"]), **shared
            ))
        elif ioc_type == "URL":
            if "domain-name:value" in stix_indicator["pattern"]:
                stix_observ_arr.append(stix2.v21.DomainName(
                    value=extract_first_quoted_word(stix_indicator["pattern"]), **shared
                ))
            else:
                stix_observ_arr.append(stix2.v21.URL(
                    value=extract_first_quoted_word(stix_indicator["pattern"]), **shared
                ))
        elif ioc_type == "IP":
            stix_observ_arr.append(stix2.v21.IPv4Address(
                value=extract_first_quoted_word(stix_indicator["pattern"]), **shared
            ))
        elif ioc_type == "Exploit":
            for hashes in extract_multiple_file_hashes(stix_indicator["pattern"]):
                stix_observ_arr.append(stix2.v21.File(
                    hashes=hashes, **shared
                ))
        else:
            return []
        return stix_observ_arr