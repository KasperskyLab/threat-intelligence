#!/usr/bin/env python3
# © 2024 AO Kaspersky Lab. All Rights Reserved.
"""Kaspersky location methods module."""

from typing import List
from .types import Country, Region, Location
from .datasheet import REGISTRY


def text_contains_pattern(text: str, pattern: str) -> bool:
    """
        Check whether specified country name pattern contained
        in the input text with comma separated list of country
        names. This function not so simple because there are
        misleading country names like 'Sudan' and 'South Sudan'
        and country names with comma like 'Korea, Republic of'.

    :param text: text with comma separated list of country names
    :param pattern: name of country to find in the input text
    :return: flag whether text contains pattern or not
    """
    pattern_length = len(pattern)
    if pattern_length == 0:
        return False

    pattern_offset = 0
    text_end = len(text)
    while True:
        found_position = text.find(pattern, pattern_offset)
        if found_position == -1:
            return False

        left_bound = found_position
        while (
            left_bound != 0 and text[left_bound - 1].isspace()
        ):  # some kind of left strip
            left_bound -= 1

        right_bound = found_position + pattern_length
        while (
            right_bound != text_end and text[right_bound].isspace()
        ):  # some kind of right strip
            right_bound += 1

        left_good = left_bound == 0 or text[left_bound - 1] == ","
        right_good = right_bound == text_end or text[right_bound] == ","
        if left_good and right_good:
            return True

        pattern_offset = found_position + 1


def decode_locations(value: str) -> List[Location]:
    """
        Extract information about locations specified in the unput argument.
        Location can be specified by country name or country geo code.
        There are could be multiple locations listed with comma symbol.

        Examples:
            - 'jp,au' should gives information abour Japan and Australia
            - 'Rwanda, Dominican Republic' should gives information abour
            Rwanda and Dominican Republic

    :param value: input string to decode
    :return: list of locations if any found
    """
    value = value.upper().strip()
    if len(value) == 0:
        return []

    geo_found = False
    geo_codes = map(lambda geo_code: geo_code.strip(), value.split(","))

    records = []
    for geo_code in geo_codes:
        record = REGISTRY.get(geo_code, None)
        if record is None:
            continue
        geo_found = True
        records.append(record)

    if not geo_found:
        for record in REGISTRY.values():
            pattern = record["country_pattern"]
            if text_contains_pattern(text=value, pattern=pattern):
                records.append(record)

    locations = []
    for record in records:
        locations.append(
            Location(
                country=Country(
                    geo_code=record["country_code"],
                    title=record["country_title"],
                    labels=record["country_labels"],
                ),
                region=Region(
                    stix_code=record["region_code"], title=record["region_title"]
                ),
                sub_region=Region(
                    stix_code=record["sub_region_code"],
                    title=record["sub_region_title"],
                ),
            )
        )

    return locations
