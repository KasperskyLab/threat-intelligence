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
"""Kaspersky connector main module."""

import os
import re
import sys
import time
import json
import uuid
import copy
import argparse
from typing import Dict, List
from datetime import datetime, timezone, timedelta
import urllib3
import yaml

from pycti import OpenCTIConnectorHelper
from kaspersky import Taxii21Client, Stix21Source, Stix21Transformer


class Configuration:
    """Configuration reader"""

    CONFIG_FILE = "./config.yml"
    APPLICATION_NAMESPACE = "kaspersky"
    DEFAULT_CONFIGURATION = {
        "opencti.ssl_verify": True,
        "connector.type": "EXTERNAL_IMPORT",
        "connector.name": "Kaspersky Feeds",
        "connector.scope": "kaspersky",
        "connector.confidence_level": 100,
        "connector.threat_score": 100,
        "connector.threat_score_high": 75,
        "connector.threat_score_medium": 50,
        "connector.log_level": "info",
        "connector.update_existing_data": False,
        f"{APPLICATION_NAMESPACE}.api_root": "https://taxii.tip.kaspersky.com/v2",
        f"{APPLICATION_NAMESPACE}.connection_timeout": 60,
        f"{APPLICATION_NAMESPACE}.ssl_verify": True,
        f"{APPLICATION_NAMESPACE}.initial_history": 604800,  # is 7 days
        f"{APPLICATION_NAMESPACE}.update_interval": 3600,  # is 1 hour
        f"{APPLICATION_NAMESPACE}.expand_objects": True,
        f"{APPLICATION_NAMESPACE}.collections": ["TAXII_*_Data_Feed"],
    }

    def __init__(self):
        """Initialize configuration reader object"""
        self._config = Configuration._build_configuration(
            file_cfg=Configuration._read_file_config(),
            env_cfg=Configuration._read_environment_config(),
            default_cfg=Configuration._read_default_config(),
        )

    @property
    def api_root(self) -> str:
        """API root parameter."""
        parameter = f"{Configuration.APPLICATION_NAMESPACE}.api_root"
        return self._read_string(parameter)
    
    @property
    def connection_timeout(self) -> str:
        """API connection timeout parameter."""
        parameter = f"{Configuration.APPLICATION_NAMESPACE}.connection_timeout"
        return self._read_number(parameter)

    @property
    def api_token(self) -> str:
        """API access token parameter."""
        parameter = f"{Configuration.APPLICATION_NAMESPACE}.api_token"
        return self._read_string(parameter)

    @property
    def ssl_verify(self) -> bool:
        """API access token parameter."""
        parameter = f"{Configuration.APPLICATION_NAMESPACE}.ssl_verify"
        return self._read_bool(parameter)

    @property
    def initial_history(self) -> int:
        """Initial history offset."""
        parameter = f"{Configuration.APPLICATION_NAMESPACE}.initial_history"
        return self._read_number(parameter)

    @property
    def update_interval(self) -> int:
        """Update interval value."""
        parameter = f"{Configuration.APPLICATION_NAMESPACE}.update_interval"
        return self._read_number(parameter)

    @property
    def update_existing_data(self) -> bool:
        """Whether to update existing data."""
        parameter = f"{Configuration.APPLICATION_NAMESPACE}.update_existing_data"
        return self._read_bool(parameter)

    @property
    def expand_objects(self) -> bool:
        """Whether to expand downloading objects."""
        parameter = f"{Configuration.APPLICATION_NAMESPACE}.expand_objects"
        return self._read_bool(parameter)

    @property
    def collections(self) -> List[str]:
        """TAXII collections."""
        parameter = f"{Configuration.APPLICATION_NAMESPACE}.collections"
        return self._read_string_list(parameter)

    @property
    def all(self) -> Dict:
        """All configuration as dictionary."""
        return self._config

    def __str__(self) -> str:
        """Format configuration as string."""
        masked_config = copy.deepcopy(self._config)
        for _, section in masked_config.items():
            for key, _ in section.items():
                if "token" in key:
                    section[key] = "*****"
        return str(masked_config)

    def _read_bool(self, field_name: str) -> bool:
        """Read specified field as boolean."""
        value = self._read_raw_value(field_name, is_number=False)
        return bool(value) if value is not None else None

    def _read_number(self, field_name: str) -> int:
        """Read specified field as number."""
        value = self._read_raw_value(field_name, is_number=True)
        return int(value) if value is not None else None

    def _read_string(self, field_name: str) -> str:
        """Read specified field as string."""
        value = self._read_raw_value(field_name, is_number=False)
        return str(value) if value is not None else None

    def _read_string_list(self, field_name: str) -> List[str]:
        """Read specified field as string list."""
        value = self._read_raw_value(field_name, is_number=False)
        if value is None:
            return None
        if isinstance(value, list):
            # pylint: disable-next=unnecessary-lambda
            return list(map(lambda item: str(item), value))
        if isinstance(value, str):
            return value.split(",")
        return [str(value)]

    def _read_raw_value(self, field_name: str, is_number: bool):
        """Read specified field without type casting."""
        field_path = Configuration._to_field_path(field_name)
        if field_path[0] not in self._config:
            return None
        section = self._config[field_path[0]]
        if field_path[1] not in section:
            return None
        value = section[field_path[1]]
        if is_number:
            return int(value)
        return value

    @staticmethod
    def _to_field_path(field_name: str) -> List[str]:
        """Convert field name to yaml-file path."""
        return field_name.split(".")

    @staticmethod
    def _get_namespaces() -> List[str]:
        return ["opencti", "connector", Configuration.APPLICATION_NAMESPACE]

    @staticmethod
    def _read_file_config() -> Dict[str, str]:
        """Read configuration from configuration file."""
        config_path = Configuration.CONFIG_FILE
        if not os.path.isabs(config_path):
            base_path = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(base_path, config_path)
        if not os.path.isfile(config_path):
            return {}
        with open(config_path, "r", encoding="utf-8") as config_file:
            return yaml.safe_load(config_file)

    @staticmethod
    def _read_environment_config() -> Dict[str, str]:
        """Read configuration from environment variables."""
        namespaces = Configuration._get_namespaces()
        env_mappings = {f"{namespace}_".upper(): namespace for namespace in namespaces}

        env_config = {}
        for var_name, var_value in os.environ.items():
            for env_prefix, section in env_mappings.items():
                if var_name.startswith(env_prefix):
                    if section not in env_config:
                        env_config[section] = {}
                    field = var_name[len(env_prefix) :].lower()
                    env_config[section][field] = var_value

        return env_config

    @staticmethod
    def _read_default_config() -> Dict[str, str]:
        """Read default configuration."""
        default_cfg = {}
        for field_name, field_value in Configuration.DEFAULT_CONFIGURATION.items():
            field_path = Configuration._to_field_path(field_name)
            if field_path[0] not in default_cfg:
                default_cfg[field_path[0]] = {}
            default_cfg[field_path[0]][field_path[1]] = field_value
        return default_cfg

    @staticmethod
    def _build_configuration(
        file_cfg: Dict[str, str], env_cfg: Dict[str, str], default_cfg: Dict[str, str]
    ) -> Dict[str, str]:
        """Build application configuration by merging all the sources."""
        merged_config = {}
        for namespace in Configuration._get_namespaces():
            merged_config[namespace] = default_cfg.get(namespace, {})
            merged_config[namespace].update(file_cfg.get(namespace, {}))
            merged_config[namespace].update(env_cfg.get(namespace, {}))
        return merged_config


# pylint: disable-next=too-few-public-methods
class Connector:
    """Kaspersky TAXII Server connector for OpenCTI."""

    # pylint: disable-next=too-many-arguments
    def __init__(
        self,
        opencti_api: OpenCTIConnectorHelper,
        stix_source: Stix21Source,
        update_interval: int,
        initial_history: int = None,
        update_existing_data: bool = None,
        dry_run: bool = None,
    ) -> None:
        self._opencti_api = opencti_api
        self._stix_source = stix_source
        self._update_existing_data = update_existing_data
        self._initial_history = initial_history
        self._update_interval = update_interval
        self._dry_run = dry_run

    def run(self) -> None:
        """Run connector execution."""
        self._opencti_api.log_info("Connector started")
        last_added = None

        while True:
            app_state = self._opencti_api.get_state()
            first_launch = app_state is None or "last_added" not in app_state
            if first_launch:
                self._opencti_api.log_info("Connector has never run")
                if self._initial_history is not None:
                    last_added = datetime.now(timezone.utc) - timedelta(
                        seconds=self._initial_history
                    )
                    self._opencti_api.log_info(
                        "Connector initial timestamp: "
                        + last_added.strftime("%Y-%m-%d %H:%M:%S")
                    )
            else:
                last_added = datetime.fromtimestamp(app_state["last_added"], timezone.utc)
                self._opencti_api.log_info(
                    "Connector last added timestamp: "
                    + last_added.strftime("%Y-%m-%d %H:%M:%S")
                )

            try:
                objects_count = 0
                timestamp = 0

                for stix_object in self._stix_source.enumerate(added_after=last_added):
                    stix_object = self._processed_object(stix_object)

                    # get date_added from description
                    if stix_object.get("type", "") == "indicator":
                        timestamp = max(timestamp, self._get_date_added_ts_from_description(stix_object.get("description", "")))

                    if self._dry_run:
                        self._print_object(stix_object)
                    else:
                        self._send_object(stix_object)
                    objects_count += 1

                if self._dry_run:
                    self._opencti_api.log_info(
                        f"Connector sent {objects_count} objects (dry run executed)"
                    )

                else:
                    if timestamp > 0:  # Only update state if we have valid timestamp
                        self._opencti_api.set_state({"last_added": timestamp})
                    self._opencti_api.log_info(
                        f"Connector sent {objects_count} objects"
                    )

            # pylint: disable-next=broad-exception-caught
            except Exception as run_exception:
                self._opencti_api.log_error(
                    f"Error occurred during connector execution: {run_exception}"
                )

            if self._opencti_api.connect_run_and_terminate:
                self._opencti_api.log_info("Run Complete. Stopping connector...")
                sys.exit(0)

            self._opencti_api.log_info(
                f"Run Complete. Sleeping until next run in "
                f"{self._update_interval} seconds"
            )
            time.sleep(self._update_interval)

    def _processed_object(self, stix_object: Dict) -> Dict:
        stix_object = self._update_indicator_properties(stix_object)
        stix_object = self._update_confidence(stix_object)
        stix_object = self._update_score(stix_object)
        return stix_object

    def _update_indicator_properties(self, stix_object: Dict) -> Dict:
        object_type = stix_object["type"]
        if object_type == "indicator":
            stix_object["x_opencti_create_indicators"] = True
        return stix_object

    def _update_confidence(self, stix_object: Dict) -> Dict:
        object_types_with_confidence = [
            "attack-pattern",
            "course-of-action",
            "threat-actor",
            "intrusion-set",
            "campaign",
            "malware",
            "tool",
            "vulnerability",
            "report",
            "relationship",
            "indicator",
        ]

        object_type = stix_object["type"]
        confidence_level = self._opencti_api.config["connector"]["confidence_level"]
        if object_type in object_types_with_confidence and confidence_level is not None:
            stix_object["confidence"] = int(confidence_level)

        return stix_object

    def _update_score(self, stix_object: Dict) -> Dict:
        object_types_with_score = [
            "indicator",
            "file",
            "domain-name",
            "url",
            "ipv4-addr",
        ]
        default_threat_score = int(self._opencti_api.config["connector"]["threat_score"])
        threat_score_high    = int(self._opencti_api.config["connector"]["threat_score_high"])
        threat_score_medium  = int(self._opencti_api.config["connector"]["threat_score_medium"])
        if stix_object["type"] in object_types_with_score and default_threat_score is not None:
            stix_object["x_opencti_score"] = int(default_threat_score)

        if "description" not in stix_object:
            if "x_opencti_description" not in stix_object:
                return stix_object
            
            description = stix_object["x_opencti_description"]
            labels_key = "x_opencti_labels"
        else:
            description = stix_object["description"]
            labels_key = "labels"

        if labels_key not in stix_object:
            stix_object[labels_key] = []
        if "threat_score=" not in description:
            stix_object[labels_key].append(self._calc_threat_score_label(default_threat_score, threat_score_high, threat_score_medium))
            return stix_object

        for record in str(description).split(";"):
            parts = record.split("=")
            if parts[0] == "threat_score":
                stix_object[labels_key].append(self._calc_threat_score_label(int(parts[1]), threat_score_high, threat_score_medium))

        return stix_object

    def _print_object(self, stix_object: Dict) -> None:
        print(json.dumps(stix_object))

    def _send_object(self, stix_object: Dict) -> None:
        self._opencti_api.log_debug(f"Sending object: {stix_object}")
        self._opencti_api.send_stix2_bundle(
            json.dumps(
                {
                    "type": "bundle",
                    "id": f"bundle--{str(uuid.uuid4())}",
                    "spec_version": "2.1",
                    "objects": [stix_object],
                }
            ),
            update=self._update_existing_data,
        )

    def _get_date_added_ts_from_description(self, description: str) -> str:
        date_added_ts = 0
        if "date_added=" not in description:
            return date_added_ts
        
        date_added_str = description.split("date_added=")[1].split(";")[0]
        if date_added_str:
            try:
                date_added = datetime.strptime(date_added_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
                date_added_ts = int(date_added.timestamp())
            except ValueError:
                self._opencti_api.log_warning(f"Invalid date format in description: {date_added_str}")
        return date_added_ts

    @staticmethod
    def _calc_threat_score_label(score: int, score_high: int, score_medium: int) -> str:
        if score >= score_high:
            return "threat_score:kaspersky:high"
        elif score >= score_medium:
            return "threat_score:kaspersky:medium"
        else:
            return "threat_score:kaspersky:low"


if __name__ == "__main__":
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument("-d", "--dry-run", action="store_true")
    args = args_parser.parse_args()

    # We ignore warnings about insecure SSL/TLS connections when SSL
    # verification is deliberately disabled by the user in the configuration.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    config = Configuration()
    try:
        opencti_client = OpenCTIConnectorHelper(config=config.all)
        opencti_client.log_info(f"Configuration: {config}")

    except ValueError as exception:
        raise RuntimeError(
            "Connector could not be registered in OpenCTI Platform. Probably "
            "versions of OpenCTI Platform and pycti library are incompatible. "
            "Please check and install appropriate version of the pycti library."
        ) from exception

    if opencti_client.opencti_url.lower().startswith("http://"):
        MESSAGE = (
            "Insecure HTTP connection established with the OpenCTI Platform. "
            "Consider to configure HTTPS protocol usage to make your connection "
            "with the OpenCTI Platform secure and mitigate the risks of data "
            "corruption and leakage."
        )
        opencti_client.log_warning(MESSAGE)

    if config.api_root.lower().startswith("http://"):
        MESSAGE = (
            "Insecure HTTP connection with the Kaspersky Threat Intelligence "
            "Portal TAXII server is forbidden. Please configure HTTPS protocol "
            "usage to make connections with the TAXII server secure."
        )
        opencti_client.log_error(MESSAGE)
        raise RuntimeError(MESSAGE)

    taxii_client = Taxii21Client(
        api_root=config.api_root,
        api_token=config.api_token,
        ssl_verify=config.ssl_verify,
        collections=config.collections,
        timeout=config.connection_timeout,
        logger=opencti_client,
    )

    if config.expand_objects:
        stix_provider = Stix21Transformer(source=taxii_client)
        opencti_client.log_info("Generation of additional stix2 objects enabled")
    else:
        stix_provider = taxii_client

    connector = Connector(
        opencti_api=opencti_client,
        stix_source=stix_provider,
        initial_history=config.initial_history,
        update_interval=config.update_interval,
        update_existing_data=config.update_existing_data,
        dry_run=args.dry_run,
    )
    connector.run()
