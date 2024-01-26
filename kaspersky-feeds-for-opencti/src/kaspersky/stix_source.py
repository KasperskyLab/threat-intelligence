#!/usr/bin/env python3
# © 2024 AO Kaspersky Lab. All Rights Reserved.
"""Kaspersky stix source module."""

from datetime import datetime
from typing import Dict, Generator


# pylint: disable-next=too-few-public-methods
class Stix21Source:
    """Interface for source of stix 2.1 objects."""

    def enumerate(self, added_after: datetime = None) -> Generator[Dict, None, None]:
        """
            Enumerate available stix 2.1 objects.
        :param added_after: datetime filter to skip old objects (optional).
        :return: generator of the stix items.
        """
        raise NotImplementedError()
