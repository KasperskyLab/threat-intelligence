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
"""Shared helpers for connector-authored labels."""

from typing import List


SUPPORTED_LABEL_FORMATS = ("legacy", "new", "both")


def append_unique_labels(labels: List[str], extra_labels: List[str]) -> List[str]:
    """Append labels preserving order and removing duplicates."""
    result = list(labels)
    seen = set(result)
    for label in extra_labels:
        if label not in seen:
            result.append(label)
            seen.add(label)
    return result


def get_label_variants(
    legacy_label: str, new_label: str, label_format: str
) -> List[str]:
    """Build label variants for the requested label format."""
    if label_format == "legacy":
        return [legacy_label]
    if label_format == "new":
        return [new_label]
    if label_format == "both":
        return [legacy_label, new_label]
    raise RuntimeError(f"Unsupported label format: {label_format}")


def make_feed_label(name: str) -> str:
    """Create label from TAXII collection name."""
    return name.removeprefix("TAXII_").lower()


def get_feed_labels(name: str, label_format: str) -> List[str]:
    """Create feed label variants from TAXII collection name."""
    legacy_label = make_feed_label(name)
    return get_label_variants(
        legacy_label=legacy_label,
        new_label=f"kaspersky:{legacy_label}",
        label_format=label_format,
    )


def get_malicious_activity_labels(label_format: str) -> List[str]:
    """Create malicious-activity label variants."""
    return get_label_variants(
        legacy_label="malicious-activity:kaspersky",
        new_label="kaspersky:malicious-activity",
        label_format=label_format,
    )


def get_threat_score_labels(level: str, label_format: str) -> List[str]:
    """Create threat score label variants."""
    return get_label_variants(
        legacy_label=f"threat_score:kaspersky:{level}",
        new_label=f"kaspersky:threat_score:{level}",
        label_format=label_format,
    )
