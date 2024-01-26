#!/usr/bin/env python3
# © 2024 AO Kaspersky Lab. All Rights Reserved.
"""Kaspersky locations datasheet module."""

from pathlib import Path
import json


# pylint: disable-next=pointless-string-statement
"""Mapping for M49 regions to stix 2.1 region codes vocabulary."""
M49_REGIONS = {
    "Africa": "africa",
    "Eastern Africa": "eastern-africa",
    "Middle Africa": "middle-africa",
    "Northern Africa": "northern-africa",
    "Southern Africa": "southern-africa",
    "Western Africa": "western-africa",
    "Americas": "americas",
    "Caribbean": "caribbean",
    "Central America": "central-america",
    "Latin America and the Caribbean": "latin-america-caribbean",
    "Northern America": "northern-america",
    "South America": "south-america",
    "Asia": "asia",
    "Central Asia": "central-asia",
    "Eastern Asia": "eastern-asia",
    "Southern Asia": "southern-asia",
    "South-eastern Asia": "south-eastern-asia",
    "Western Asia": "western-asia",
    "Europe": "europe",
    "Eastern Europe": "eastern-europe",
    "Northern Europe": "northern-europe",
    "Southern Europe": "southern-europe",
    "Western Europe": "western-europe",
    "Oceania": "oceania",
    "Australia and New Zealand": "australia-new-zealand",
    "Melanesia": "melanesia",
    "Micronesia": "micronesia",
    "Polynesia": "polynesia",
}


def to_stix_region(m49_region: str):
    """Convert m49 region name to stix 2.1 region code."""
    if m49_region not in M49_REGIONS:
        raise RuntimeError(f"unknown M42 region {m49_region}")
    return M49_REGIONS[m49_region]


def read_datasheet(filename):
    """Read specified datasheet file."""
    datasheat_path = Path(__file__).resolve().parent / filename
    if not datasheat_path.is_file():
        error = f"datasheet file '{datasheat_path}' not found"
        raise RuntimeError(error)

    with open(datasheat_path, "r", encoding="UTF-8") as datasheet_file:
        return json.load(datasheet_file)


def raise_datasheet_error(filename, message, record=None):
    """Raise exception about broken datasheet file."""
    error = f"datasheet file '{filename}' is broken: '{message}'"
    if record is not None:
        data = json.dumps(record)
        error = f"'{error}' in record '{data}'"
    raise RuntimeError(error)


def validate_datasheet_record(filename, record):
    """Validate specified datasheet file record."""
    fields = [
        "code",
        "title",
        "pattern",
        "labels",
        "region",
        "inter_region",
        "sub_region",
    ]
    for field in fields:
        if field not in record:
            message = f"field '{field}' not found"
            raise_datasheet_error(filename=filename, message=message, record=record)

        if field == "labels":
            values = record["labels"]
            good = isinstance(values, list) and all(
                isinstance(value, str) for value in values
            )
            if not good:
                message = f"field '{field}' expected to be a list of strings"
                raise_datasheet_error(filename=filename, message=message, record=record)
        else:
            value = record[field]
            if not isinstance(value, str):
                message = f"field '{field}' expected to be a string"
                raise_datasheet_error(filename=filename, message=message, record=record)


def initialize_registry():
    """Initialize locations registry based on datasheet file."""

    datasheat_filename = "datasheet.json"
    datasheet = read_datasheet(filename=datasheat_filename)

    registry = {}
    country_titles = set()
    country_patterns = set()

    for record in datasheet:
        validate_datasheet_record(filename=datasheat_filename, record=record)

        country_code = record["code"].upper()
        if country_code in registry:
            message = f"country code '{country_code}' found more than once"
            raise_datasheet_error(filename=datasheat_filename, message=message)

        country_title = record["title"]
        if country_title in country_titles:
            message = f"country title '{country_title}' found more than once"
            raise_datasheet_error(filename=datasheat_filename, message=message)

        country_pattern = record["pattern"].upper()
        if country_pattern in country_patterns:
            message = f"country pattern '{country_pattern}' found more than once"
            raise_datasheet_error(filename=datasheat_filename, message=message)

        country_labels = [value.upper() for value in record["labels"]]

        region_title = record["region"]
        region_code = to_stix_region(region_title)

        sub_region_title = record.get("inter_region", None)
        if sub_region_title is None or len(sub_region_title) == 0:
            sub_region_title = record.get("sub_region", None)
            if sub_region_title is None or len(sub_region_title) == 0:
                message = "neither 'sub_region' field nor 'inter_region' field found"
                raise_datasheet_error(
                    filename=datasheat_filename, message=message, record=record
                )
        sub_region_code = to_stix_region(sub_region_title)

        registry[country_code] = {
            "country_code": country_code,
            "country_title": country_title,
            "country_pattern": country_pattern,
            "country_labels": country_labels,
            "region_title": region_title,
            "region_code": region_code,
            "sub_region_title": sub_region_title,
            "sub_region_code": sub_region_code,
        }
        country_titles.add(country_title)
        country_patterns.add(country_pattern)

    return registry


# pylint: disable-next=pointless-string-statement
"""Known locations registry."""
REGISTRY = initialize_registry()
