#!/usr/bin/env python3
# © 2024 AO Kaspersky Lab. All Rights Reserved.
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
