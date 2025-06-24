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
"""Kaspersky location types module."""

from typing import List
from dataclasses import dataclass


@dataclass
class Country:
    """Information about country."""

    title: str
    labels: List[str]
    geo_code: str


@dataclass
class Region:
    """Information about region."""

    title: str
    stix_code: str


@dataclass
class Location:
    """Location description."""

    country: Country
    region: Region
    sub_region: Region
