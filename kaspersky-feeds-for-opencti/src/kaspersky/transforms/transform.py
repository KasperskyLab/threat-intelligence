#!/usr/bin/env python3
# © 2024 AO Kaspersky Lab. All Rights Reserved.
"""Kaspersky transform module."""

from typing import Dict, List


class Transform:
    """
    Transform interface provides methods for building additional stix 2.1
    objects and relationships by checking context of stix 2.1 indicator
    object received from Kaspersky TAXII server.
    """

    def __init__(self, author: Dict) -> None:
        """Initialize transform object."""
        self._author = author

    # pylint: disable-next=unused-argument
    def build_objects(self, indicator: Dict, context: Dict) -> List[Dict]:
        """
            Build new stix 2.1 objects based on indicator's context.
        :param indicator: original stix 2.1 indicator object.
        :param context: parsed context of the indicator object.
        :return: list of new stix 2.1 objects.
        """
        return []

    # pylint: disable-next=unused-argument
    def build_relationships(self, stix_objects: List[Dict]) -> List[Dict]:
        """
            Build new stix 2.1 relationships between objects.
        :param stix_objects: all stix 2.1 objects to consider.
        :return: list of new stix 2.1 relationships.
        """
        return []
