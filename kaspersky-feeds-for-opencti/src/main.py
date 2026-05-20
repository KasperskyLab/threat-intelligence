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
import sys
import time
import json
import uuid
import signal
from contextlib import contextmanager
import argparse
import threading
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone, timedelta
import urllib3
import yaml

from pycti import OpenCTIConnectorHelper
from kaspersky import Taxii21Client, Stix21Source, Stix21Transformer
from kaspersky.label_utils import (
    SUPPORTED_LABEL_FORMATS as LABEL_FORMATS,
    append_unique_labels,
    get_threat_score_labels,
)


class Configuration:
    """Configuration reader"""

    CONFIG_FILE = "./config.yml"
    APPLICATION_NAMESPACE = "kaspersky"
    SUPPORTED_LABEL_FORMATS = LABEL_FORMATS
    SUPPORTED_DESCRIPTION_MODES = ("overwrite", "skip", "create_only")
    DEFAULT_CONFIGURATION = {
        "opencti.ssl_verify": True,
        "connector.type": "EXTERNAL_IMPORT",
        "connector.name": "Kaspersky Feeds",
        "connector.scope": "kaspersky",
        "connector.confidence_level": 100,
        "connector.threat_score_from_description": False,
        "connector.threat_score": 100,
        "connector.threat_score_high": 75,
        "connector.threat_score_medium": 50,
        "connector.log_level": "info",
        "connector.update_existing_data": False,
        "connector.label_format": "legacy",
        "connector.description_mode": "overwrite",
        f"{APPLICATION_NAMESPACE}.api_root": "https://taxii.tip.kaspersky.com/v2",
        f"{APPLICATION_NAMESPACE}.connection_timeout": 60,
        f"{APPLICATION_NAMESPACE}.ssl_verify": True,
        f"{APPLICATION_NAMESPACE}.initial_history": 604800,  # is 7 days
        f"{APPLICATION_NAMESPACE}.update_interval": 3600,  # is 1 hour
        f"{APPLICATION_NAMESPACE}.expand_objects": True,
        f"{APPLICATION_NAMESPACE}.create_indicators": True,
        f"{APPLICATION_NAMESPACE}.create_observables": True,
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
        parameter = f"connector.update_existing_data"
        return self._read_bool(parameter)

    @property
    def threat_score_from_description(self) -> bool:
        """Whether to read threat score from STIX description instead of labels."""
        parameter = "connector.threat_score_from_description"
        return self._read_bool(parameter)

    @property
    def label_format(self) -> str:
        """Label formatting mode for connector-authored labels."""
        parameter = "connector.label_format"
        return self._read_string_choice(
            parameter, Configuration.SUPPORTED_LABEL_FORMATS
        )

    @property
    def description_mode(self) -> str:
        """Description handling mode for outgoing objects."""
        parameter = "connector.description_mode"
        return self._read_string_choice(
            parameter, Configuration.SUPPORTED_DESCRIPTION_MODES
        )

    @property
    def expand_objects(self) -> bool:
        """Whether to expand downloading objects."""
        parameter = f"{Configuration.APPLICATION_NAMESPACE}.expand_objects"
        return self._read_bool(parameter)

    @property
    def create_indicators(self) -> bool:
        """Whether to create indicators."""
        parameter = f"{Configuration.APPLICATION_NAMESPACE}.create_indicators"
        return self._read_bool(parameter)

    @property
    def create_observables(self) -> bool:
        """Whether to create observables."""
        parameter = f"{Configuration.APPLICATION_NAMESPACE}.create_observables"
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
        masked_config = {}
        for namespace, section in self._config.items():
            masked_config[namespace] = {}
            for key, value in section.items():
                masked_config[namespace][key] = "*****" if "token" in key else value
        return str(masked_config)

    def _read_bool(self, field_name: str) -> bool:
        """Read specified field as boolean."""
        value = self._read_raw_value(field_name, is_number=False)
        if value is None:
            return None
        if isinstance(value, str):
            if value.lower() in ['true', 'yes']:
                return True
            if value.lower() in ['false', 'no']:
                return False
            raise RuntimeError(f"Invalid configuration: '{field_name}' contains invalid boolean value: '{value}'")
        return bool(value)

    def _read_number(self, field_name: str) -> int:
        """Read specified field as number."""
        value = self._read_raw_value(field_name, is_number=True)
        return int(value) if value is not None else None

    def _read_string(self, field_name: str) -> str:
        """Read specified field as string."""
        value = self._read_raw_value(field_name, is_number=False)
        return str(value) if value is not None else None

    def _read_string_choice(self, field_name: str, choices: Tuple[str, ...]) -> str:
        """Read specified field as string and validate allowed values."""
        value = self._read_string(field_name)
        if value is None:
            return None
        if value not in choices:
            raise RuntimeError(
                f"Invalid configuration: '{field_name}' contains invalid value: "
                f"'{value}'. Supported values: {', '.join(choices)}"
            )
        return value

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
            if var_value == "":
                continue
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


class ConnectorStopRequested(BaseException):
    """Signal-driven graceful stop request."""

    def __init__(self, signal_name: str):
        super().__init__(f"Connector stop requested by {signal_name}")
        self.signal_name = signal_name


# pylint: disable-next=too-few-public-methods
class Connector:
    """Kaspersky TAXII Server connector for OpenCTI."""

    CYBER_OBSERVABLE_TYPES = {
        "artifact",
        "autonomous-system",
        "directory",
        "domain-name",
        "email-addr",
        "email-message",
        "file",
        "hostname",
        "ipv4-addr",
        "ipv6-addr",
        "mac-addr",
        "mutex",
        "network-traffic",
        "process",
        "software",
        "url",
        "user-account",
        "windows-registry-key",
        "x509-certificate",
    }
    DESCRIPTION_FIELDS = ("description", "x_opencti_description")
    DESCRIPTION_LOOKUP_CHUNK_SIZE = 200
    GRACEFUL_STOP_TIMEOUT_SEC = 5
    STAGE_IMPORT_TIMEOUT_SEC = 1800
    STAGE_IMPORT_INITIAL_POLL_SEC = 1
    STAGE_IMPORT_MAX_POLL_SEC = 5
    # If no OpenCTI internal work appears after the bounded grace window, we assume
    # the stage was handled synchronously or produced no import work. This is a
    # fail-open path, so the warning emitted there should be monitored in production.
    STAGE_IMPORT_NO_WORK_GRACE_POLLS = 6
    CONNECTOR_WORKS_QUERY_LIMIT = 500
    TERMINAL_WORK_STATUSES = {
        "complete",
        "cancelled",
        "canceled",
        "error",
        "failed",
    }
    SHUTDOWN_SIGNALS = (signal.SIGTERM, signal.SIGINT)
    REFERENCE_FIELDS = (
        "created_by_ref",
        "x_opencti_created_by_ref",
        "source_ref",
        "target_ref",
    )
    LIST_REFERENCE_FIELDS = ("object_refs",)
    STIX_OBJECT_LOOKUP_ATTRIBUTES = """
        ... on StixObject {
            id
            standard_id
            x_opencti_stix_ids
        }
        ... on StixCoreRelationship {
            id
            standard_id
        }
        ... on StixSightingRelationship {
            id
            standard_id
        }
    """

    # pylint: disable-next=too-many-arguments
    def __init__(
        self,
        opencti_api: OpenCTIConnectorHelper,
        stix_source: Stix21Source,
        update_interval: int,
        initial_history: int = None,
        update_existing_data: bool = None,
        dry_run: bool = None,
        label_format: str = "legacy",
        description_mode: str = "overwrite",
        threat_score_from_description: bool = False,
    ) -> None:
        self._opencti_api = opencti_api
        self._stix_source = stix_source
        self._update_existing_data = update_existing_data
        self._initial_history = initial_history
        self._update_interval = update_interval
        self._dry_run = dry_run
        self._label_format = label_format
        self._description_mode = description_mode
        self._threat_score_from_description = bool(threat_score_from_description)
        self._known_existing_ids: Set[str] = set()
        self._known_new_ids: Set[str] = set()
        self._run_metrics: Dict[str, float] = {}
        self._last_run_metrics: Dict[str, float] = {}
        self._connector_works_truncation_warned = False
        self._connector_works_direct_query_failed = False
        self._active_work_id: Optional[str] = None
        self._active_work_finalized = False
        self._active_work_objects_count = 0
        self._shutdown_signal_name: Optional[str] = None
        self._defer_stop_exception = False
        self._graceful_shutdown_in_progress = False
        self._reset_run_metrics()

    def get_last_run_metrics(self) -> Dict[str, float]:
        """Return metrics captured for the last completed run."""
        return dict(self._last_run_metrics)

    def run(self) -> None:
        """Run connector execution."""
        self._opencti_api.log_info("Connector started")
        last_added = None
        previous_handlers = self._install_signal_handlers()
        try:
            while True:
                work_id = None
                self._reset_run_shutdown_state()
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
                    last_added = datetime.fromtimestamp(
                        float(app_state["last_added"]), timezone.utc
                    )
                    self._opencti_api.log_info(
                        "Connector last added timestamp: "
                        + last_added.strftime("%Y-%m-%d %H:%M:%S")
                    )

                run_wall_started_at = time.perf_counter()
                self._known_existing_ids = set()
                self._known_new_ids = set()
                self._reset_run_metrics()
                try:
                    run_started_at_dt = datetime.now(timezone.utc)
                    run_started_at = int(run_started_at_dt.timestamp())
                    objects_count = 0
                    timestamp = 0.0
                    run_cancelled = False

                    if not self._dry_run:
                        work_id = self._start_work(run_started_at_dt, last_added)
                        self._active_work_id = work_id

                    for stix_batch in self._enumerate_source_batches(
                        added_after=last_added
                    ):
                        self._raise_if_stop_requested()
                        if work_id and not self._is_work_alive(work_id):
                            run_cancelled = True
                            self._active_work_finalized = True
                            self._opencti_api.log_info(
                                f"OpenCTI work {work_id} is no longer active. "
                                "Stopping current run."
                            )
                            break

                        batch_timestamp = self._get_batch_date_added_ts(stix_batch)
                        self._run_metrics["batches_total"] += 1
                        self._run_metrics["objects_total"] += len(stix_batch)
                        if self._dry_run:
                            self._run_with_deferred_stop(
                                self._prepare_and_print_batch,
                                stix_batch,
                            )
                        else:
                            self._run_with_deferred_stop(
                                self._prepare_and_send_batch,
                                stix_batch,
                                work_id=work_id,
                            )
                        timestamp = max(timestamp, batch_timestamp)
                        objects_count += len(stix_batch)
                        self._active_work_objects_count = objects_count
                        self._raise_if_stop_requested()

                    if self._dry_run:
                        self._opencti_api.log_info(
                            f"Connector sent {objects_count} objects "
                            "(dry run executed)"
                        )

                    elif run_cancelled:
                        self._opencti_api.log_info(
                            f"Connector run cancelled after queueing "
                            f"{objects_count} objects"
                        )

                    else:
                        state_timestamp = run_started_at
                        if timestamp > state_timestamp:
                            state_timestamp = timestamp
                        self._opencti_api.set_state(
                            {"last_added": int(state_timestamp)}
                        )
                        self._sync_state()
                        self._finalize_active_work(
                            f"Connector queued {objects_count} objects for import"
                        )
                        self._opencti_api.log_info(
                            f"Connector queued {objects_count} objects for import"
                        )

                # pylint: disable-next=broad-exception-caught
                except Exception as run_exception:
                    self._finalize_active_work(
                        f"Connector run failed: {run_exception}",
                        in_error=True,
                    )
                    self._opencti_api.log_error(
                        f"Error occurred during connector execution: "
                        f"{run_exception}"
                    )
                finally:
                    self._finalize_run_metrics(
                        time.perf_counter() - run_wall_started_at
                    )

                self._reset_run_shutdown_state()
                if self._opencti_api.connect_run_and_terminate:
                    self._opencti_api.log_info("Run Complete. Stopping connector...")
                    sys.exit(0)

                self._opencti_api.log_info(
                    f"Run Complete. Sleeping until next run in "
                    f"{self._update_interval} seconds"
                )
                time.sleep(self._update_interval)
        except ConnectorStopRequested as stop_requested:
            self._handle_graceful_stop(stop_requested)
            self._reset_run_shutdown_state()
            sys.exit(0)
        finally:
            self._restore_signal_handlers(previous_handlers)

    def _enumerate_source_clusters(self, added_after: datetime = None):
        enumerate_clusters = getattr(self._stix_source, "enumerate_clusters", None)
        if callable(enumerate_clusters):
            yield from enumerate_clusters(added_after=added_after)
            return

        for stix_object in self._stix_source.enumerate(added_after=added_after):
            yield [stix_object]

    def _enumerate_source_batches(self, added_after: datetime = None):
        enumerate_batches = getattr(self._stix_source, "enumerate_batches", None)
        if callable(enumerate_batches):
            for stix_batch in enumerate_batches(added_after=added_after):
                processed_batch = [
                    self._processed_object(stix_object)
                    for stix_object in stix_batch
                ]
                if processed_batch:
                    yield processed_batch
            return

        yield from self._get_batches(
            self._enumerate_source_clusters(added_after=added_after), 1000
        )

    def _get_batches(self, stix_clusters, size: int):
        batch = []
        for cluster in stix_clusters:
            processed_cluster = [
                self._processed_object(stix_object) for stix_object in cluster
            ]
            if not processed_cluster:
                continue

            cluster_size = len(processed_cluster)
            if batch and len(batch) + cluster_size > size:
                yield batch
                batch = []

            if cluster_size > size:
                yield processed_cluster
                continue

            batch.extend(processed_cluster)
        if batch:
            yield batch

    def _processed_object(self, stix_object: Dict) -> Dict:
        stix_object = self._update_confidence(stix_object)
        stix_object = self._update_score(stix_object)
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

        if self._threat_score_from_description:
            if "threat_score=" in description:
                for record in str(description).split(";"):
                    parts = record.split("=")
                    if parts[0] == "threat_score":
                        score = int(parts[1])
                        stix_object["x_opencti_score"] = score
            return stix_object

        if labels_key not in stix_object:
            stix_object[labels_key] = []
        if "threat_score=" not in description:
            stix_object[labels_key] = append_unique_labels(
                stix_object[labels_key],
                self._calc_threat_score_labels(
                    default_threat_score, threat_score_high, threat_score_medium
                ),
            )
            return stix_object

        for record in str(description).split(";"):
            parts = record.split("=")
            if parts[0] == "threat_score":
                stix_object[labels_key] = append_unique_labels(
                    stix_object[labels_key],
                    self._calc_threat_score_labels(
                        int(parts[1]), threat_score_high, threat_score_medium
                    ),
                )

        return stix_object

    def _print_object(self, stix_objects: List) -> None:
        for obj in stix_objects:
            print(json.dumps(obj))

    def _send_objects(self, stix_objects: List, work_id: Optional[str] = None) -> List:
        for obj in stix_objects:
            self._opencti_api.log_debug(f"Sending object: {obj}")
        return self._opencti_api.send_stix2_bundle(
            json.dumps(
                {
                    "type": "bundle",
                    "id": f"bundle--{str(uuid.uuid4())}",
                    "spec_version": "2.1",
                    "objects": stix_objects,
                }
            ),
            update=self._update_existing_data,
            work_id=work_id,
        )

    def _prepare_and_send_batch(
        self, stix_objects: List[Dict], work_id: Optional[str] = None
    ) -> None:
        self._prepare_batch_for_send(stix_objects)
        stages = self._build_dependency_stages(stix_objects)
        self._run_metrics["stages_total"] += len(stages)
        for stage_index, stage_objects in enumerate(stages, start=1):
            stage_snapshot = self._snapshot_stage_import_state(work_id)
            sent_bundles = self._send_objects(stage_objects, work_id=work_id)
            self._wait_for_stage_import(
                work_id=work_id,
                snapshot=stage_snapshot,
                sent_bundles=sent_bundles,
                fallback_expected_count=len(stage_objects),
                stage_index=stage_index,
                stages_total=len(stages),
            )
            if self._shutdown_signal_name is not None:
                return

    def _prepare_and_print_batch(self, stix_objects: List[Dict]) -> None:
        self._prepare_batch_for_send(stix_objects)
        stages = self._build_dependency_stages(stix_objects)
        self._run_metrics["stages_total"] += len(stages)
        for stage_objects in stages:
            self._print_object(stage_objects)

    def _build_dependency_stages(self, stix_objects: List[Dict]) -> List[List[Dict]]:
        object_by_id = {}
        object_order = []
        for stix_object in stix_objects:
            object_id = stix_object.get("id")
            if object_id is None:
                raise RuntimeError("Unable to stage STIX object without id")
            if object_id not in object_by_id:
                object_order.append(object_id)
            object_by_id[object_id] = stix_object

        object_ids = set(object_by_id.keys())
        dependencies_by_id = {
            object_id: self._get_local_dependency_refs(stix_object, object_ids)
            for object_id, stix_object in object_by_id.items()
        }

        levels = {}
        visiting = set()

        def resolve_level(object_id: str) -> int:
            if object_id in levels:
                return levels[object_id]
            if object_id in visiting:
                raise RuntimeError(f"Cyclic STIX dependency detected for {object_id}")

            visiting.add(object_id)
            dependencies = dependencies_by_id[object_id]
            if not dependencies:
                level = 0
            else:
                level = 1 + max(resolve_level(dependency) for dependency in dependencies)
            visiting.remove(object_id)
            levels[object_id] = level
            return level

        for object_id in object_order:
            resolve_level(object_id)

        stages_by_level = {}
        for object_id in object_order:
            stages_by_level.setdefault(levels[object_id], []).append(
                object_by_id[object_id]
            )

        return [
            stages_by_level[level]
            for level in sorted(stages_by_level.keys())
            if stages_by_level[level]
        ]

    def _get_local_dependency_refs(
        self, stix_object: Dict, local_object_ids: Set[str]
    ) -> Set[str]:
        object_id = stix_object.get("id")
        dependencies = set()

        for field_name in Connector.REFERENCE_FIELDS:
            dependency_id = stix_object.get(field_name)
            if dependency_id is None or dependency_id == object_id:
                continue
            if dependency_id not in local_object_ids:
                raise RuntimeError(
                    f"Unresolved STIX reference field={field_name} "
                    f"object={object_id} ref={dependency_id}"
                )
            dependencies.add(dependency_id)

        for field_name in Connector.LIST_REFERENCE_FIELDS:
            for dependency_id in stix_object.get(field_name) or []:
                if dependency_id == object_id:
                    continue
                if dependency_id not in local_object_ids:
                    raise RuntimeError(
                        f"Unresolved STIX reference field={field_name} "
                        f"object={object_id} ref={dependency_id}"
                    )
                dependencies.add(dependency_id)

        return dependencies

    def _prepare_batch_for_send(self, stix_objects: List[Dict]) -> List[Dict]:
        if self._description_mode == "overwrite":
            return stix_objects

        objects_with_description = [
            stix_object for stix_object in stix_objects if self._has_description(stix_object)
        ]
        if not objects_with_description:
            return stix_objects

        if self._description_mode == "skip":
            self._strip_descriptions(objects_with_description)
            return stix_objects

        if self._description_mode == "create_only":
            self._apply_create_only_description_mode(objects_with_description)
            return stix_objects

        return stix_objects

    def _snapshot_stage_import_state(self, work_id: Optional[str]) -> Dict:
        parent_work = self._get_work_state(work_id) if work_id is not None else None
        parent_processed = (
            self._get_processed_count_from_work(parent_work)
            if parent_work is not None
            else None
        )
        if parent_work is not None and parent_processed is None:
            parent_processed = 0

        return {
            "connector_work_ids": self._snapshot_connector_work_ids(),
            "parent_processed": parent_processed if parent_work is not None else None,
            "parent_errors_count": self._get_errors_count_from_work(parent_work)
            if parent_work is not None
            else 0,
        }

    def _wait_for_stage_import(
        self,
        work_id: Optional[str],
        snapshot: Dict,
        sent_bundles: Optional[List],
        fallback_expected_count: int,
        stage_index: int,
        stages_total: int,
    ) -> None:
        queue_protocol = getattr(self._opencti_api, "queue_protocol", None)
        connector_work_ids = snapshot.get("connector_work_ids")
        expected_increment = self._count_stage_expectations(
            sent_bundles, fallback_expected_count
        )
        parent_processed = snapshot.get("parent_processed")

        if connector_work_ids is not None:
            self._wait_for_connector_stage_works(
                before_work_ids=connector_work_ids,
                parent_work_id=work_id,
                baseline_processed=snapshot.get("parent_processed"),
                baseline_errors_count=snapshot.get("parent_errors_count", 0),
                expected_increment=expected_increment,
                stage_index=stage_index,
                stages_total=stages_total,
            )
            return

        if work_id is not None and parent_processed is not None:
            self._wait_for_parent_work_progress(
                work_id=work_id,
                baseline_processed=parent_processed,
                baseline_errors_count=snapshot.get("parent_errors_count", 0),
                expected_increment=expected_increment,
                stage_index=stage_index,
                stages_total=stages_total,
            )
            return

        if queue_protocol == "api":
            raise RuntimeError(
                "Unable to wait for OpenCTI API stage import: "
                "connector work listing is unavailable"
            )

    def _wait_for_connector_stage_works(
        self,
        before_work_ids: Set[str],
        parent_work_id: Optional[str],
        baseline_processed: Optional[int],
        baseline_errors_count: int,
        expected_increment: int,
        stage_index: int,
        stages_total: int,
    ) -> None:
        deadline = time.time() + Connector.STAGE_IMPORT_TIMEOUT_SEC
        last_seen_new_work_ids = set()
        no_work_polls = 0
        poll_interval = Connector.STAGE_IMPORT_INITIAL_POLL_SEC
        while time.time() < deadline:
            self._raise_if_parent_work_cancelled_or_failed(
                parent_work_id, stage_index, stages_total
            )

            connector_works = self._list_connector_works()
            if connector_works is None:
                raise RuntimeError("Unable to list OpenCTI connector works")

            stage_works = [
                work
                for work in connector_works
                if work.get("id") not in before_work_ids
                and work.get("id") != parent_work_id
            ]
            if stage_works:
                last_seen_new_work_ids = {work.get("id") for work in stage_works}
                self._raise_for_stage_work_errors(stage_works, stage_index, stages_total)
                if all(not self._is_work_alive_from_state(work) for work in stage_works):
                    return
                no_work_polls = 0
            else:
                no_work_polls += 1
                if self._is_parent_stage_progress_complete(
                    parent_work_id=parent_work_id,
                    baseline_processed=baseline_processed,
                    baseline_errors_count=baseline_errors_count,
                    expected_increment=expected_increment,
                    stage_index=stage_index,
                    stages_total=stages_total,
                ):
                    return
                if no_work_polls >= Connector.STAGE_IMPORT_NO_WORK_GRACE_POLLS:
                    if parent_work_id is not None and baseline_processed is not None:
                        # Some OpenCTI/pycti versions update only the parent work
                        # in API mode. Absence of a visible child work is not safe
                        # enough to advance dependency stages while the parent can
                        # still be observed.
                        time.sleep(poll_interval)
                        poll_interval = min(
                            poll_interval * 2, Connector.STAGE_IMPORT_MAX_POLL_SEC
                        )
                        continue
                    if self._connector_works_truncation_warned:
                        raise RuntimeError(
                            f"No OpenCTI internal work detected for stage "
                            f"{stage_index}/{stages_total}; connector work listing "
                            f"may be truncated by pycti"
                        )
                    self._opencti_api.log_warning(
                        f"No OpenCTI internal work detected for stage "
                        f"{stage_index}/{stages_total}; continuing under "
                        f"no-work grace after {no_work_polls} polls. Monitor "
                        f"following works for delayed missing-reference errors."
                    )
                    return

            time.sleep(poll_interval)
            poll_interval = min(
                poll_interval * 2, Connector.STAGE_IMPORT_MAX_POLL_SEC
            )

        raise TimeoutError(
            f"Timed out waiting for OpenCTI stage {stage_index}/{stages_total} "
            f"works={sorted(last_seen_new_work_ids)}"
        )

    def _wait_for_parent_work_progress(
        self,
        work_id: str,
        baseline_processed: int,
        baseline_errors_count: int,
        expected_increment: int,
        stage_index: int,
        stages_total: int,
    ) -> None:
        target_processed = baseline_processed + expected_increment
        deadline = time.time() + Connector.STAGE_IMPORT_TIMEOUT_SEC
        poll_interval = Connector.STAGE_IMPORT_INITIAL_POLL_SEC
        while time.time() < deadline:
            work_state = self._get_work_state(work_id)
            if work_state is None:
                raise RuntimeError(f"Unable to query OpenCTI work {work_id}")

            self._raise_for_stage_work_errors(
                [work_state],
                stage_index,
                stages_total,
                errors_offset=baseline_errors_count,
            )
            if self._is_parent_progress_complete(
                work_state,
                baseline_processed=baseline_processed,
                expected_increment=expected_increment,
            ):
                return
            if self._is_cancelled_or_failed_work(work_state):
                raise RuntimeError(
                    f"OpenCTI work {work_id} stopped before stage "
                    f"{stage_index}/{stages_total} was processed"
                )

            time.sleep(poll_interval)
            poll_interval = min(
                poll_interval * 2, Connector.STAGE_IMPORT_MAX_POLL_SEC
            )

        raise TimeoutError(
            f"Timed out waiting for OpenCTI stage {stage_index}/{stages_total} "
            f"processed={target_processed}"
        )

    def _raise_if_parent_work_cancelled_or_failed(
        self,
        parent_work_id: Optional[str],
        stage_index: int,
        stages_total: int,
    ) -> None:
        if parent_work_id is None:
            return

        work_state = self._get_work_state(parent_work_id)
        if work_state is None or not self._is_cancelled_or_failed_work(work_state):
            return

        raise RuntimeError(
            f"OpenCTI work {parent_work_id} stopped during stage "
            f"{stage_index}/{stages_total}"
        )

    def _raise_for_stage_work_errors(
        self,
        works: List[Dict],
        stage_index: int,
        stages_total: int,
        errors_offset: int = 0,
    ) -> None:
        for work in works:
            errors = (work.get("errors") or [])[errors_offset:]
            status = str(work.get("status") or "").lower()
            if not errors and status not in ("error", "failed"):
                continue

            first_error = errors[0] if errors else {"message": status}
            raise RuntimeError(
                f"OpenCTI stage {stage_index}/{stages_total} failed "
                f"under strict import policy "
                f"work={work.get('id')} error={first_error}"
            )

    def _is_parent_stage_progress_complete(
        self,
        parent_work_id: Optional[str],
        baseline_processed: Optional[int],
        baseline_errors_count: int,
        expected_increment: int,
        stage_index: int,
        stages_total: int,
    ) -> bool:
        if parent_work_id is None or baseline_processed is None:
            return False

        work_state = self._get_work_state(parent_work_id)
        if work_state is None:
            return False

        self._raise_for_stage_work_errors(
            [work_state],
            stage_index,
            stages_total,
            errors_offset=baseline_errors_count,
        )
        return self._is_parent_progress_complete(
            work_state,
            baseline_processed=baseline_processed,
            expected_increment=expected_increment,
        )

    def _is_parent_progress_complete(
        self,
        work_state: Dict,
        baseline_processed: int,
        expected_increment: int,
    ) -> bool:
        processed = self._get_processed_count_from_work(work_state)
        if processed is None:
            return False

        if processed >= baseline_processed + expected_increment:
            return True

        expected_total = self._get_expected_count_from_work(work_state)
        # Some OpenCTI versions expose parent counters as stage-local totals
        # instead of strictly cumulative values.
        return (
            expected_total is not None
            and expected_total != baseline_processed
            and expected_total >= expected_increment
            and processed >= expected_total
        )

    def _snapshot_connector_work_ids(self) -> Optional[Set[str]]:
        connector_works = self._list_connector_works()
        if connector_works is None:
            return None
        return {work.get("id") for work in connector_works}

    def _list_connector_works(self) -> Optional[List[Dict]]:
        work_api = self._get_work_api()
        connector_id = getattr(self._opencti_api, "connector_id", None)
        if work_api is None or connector_id is None:
            return None

        connector_works = self._query_connector_works(connector_id)
        if connector_works is None:
            if not hasattr(work_api, "get_connector_works"):
                return None
            connector_works = list(work_api.get_connector_works(connector_id) or [])
            self._connector_works_truncation_warned = True
            self._opencti_api.log_warning(
                "OpenCTI connector work listing is using pycti fallback; "
                "results may be limited or unsorted"
            )
            self._opencti_api.log_debug(
                f"Listed {len(connector_works)} OpenCTI connector works "
                f"via pycti fallback"
            )
            return connector_works

        self._opencti_api.log_debug(
            f"Listed {len(connector_works)} OpenCTI connector works "
            f"with explicit limit={Connector.CONNECTOR_WORKS_QUERY_LIMIT}"
        )
        if (
            len(connector_works) >= Connector.CONNECTOR_WORKS_QUERY_LIMIT
            and not self._connector_works_truncation_warned
        ):
            self._connector_works_truncation_warned = True
            self._opencti_api.log_warning(
                "OpenCTI connector work listing reached explicit query limit; "
                "stage wait may need pagination/filtering if imports overlap"
            )
        return connector_works

    def _query_connector_works(self, connector_id: str) -> Optional[List[Dict]]:
        work_api = self._get_work_api()
        api_client = getattr(work_api, "api", None)
        query_method = getattr(api_client, "query", None)
        if not callable(query_method):
            return None

        query = """
        query ConnectorWorksQuery(
            $count: Int
            $orderBy: WorksOrdering
            $orderMode: OrderingMode
            $filters: FilterGroup
        ) {
            works(
                first: $count
                orderBy: $orderBy
                orderMode: $orderMode
                filters: $filters
            ) {
                edges {
                    node {
                        id
                        name
                        user {
                            name
                        }
                        timestamp
                        status
                        event_source_id
                        received_time
                        processed_time
                        completed_time
                        tracking {
                            import_expected_number
                            import_processed_number
                        }
                        messages {
                            timestamp
                            message
                            sequence
                            source
                        }
                        errors {
                            timestamp
                            message
                            sequence
                            source
                        }
                    }
                }
            }
        }
        """
        variables = {
            "count": Connector.CONNECTOR_WORKS_QUERY_LIMIT,
            "orderBy": "timestamp",
            "orderMode": "desc",
            "filters": {
                "mode": "and",
                "filters": [{"key": "connector_id", "values": [connector_id]}],
                "filterGroups": [],
            },
        }
        try:
            try:
                result = query_method(query, variables, True)
            except TypeError:
                result = query_method(query, variables)
        except Exception as exception:
            if not self._connector_works_direct_query_failed:
                self._connector_works_direct_query_failed = True
                self._opencti_api.log_warning(
                    "Unable to list OpenCTI connector works with explicit limit; "
                    f"falling back to pycti helper: {exception}"
                )
            return None

        edges = result["data"]["works"]["edges"]
        connector_works = [edge["node"] for edge in edges]
        return sorted(connector_works, key=lambda work: work["timestamp"])

    def _get_work_processed_count(self, work_id: Optional[str]) -> Optional[int]:
        if work_id is None:
            return None

        work_state = self._get_work_state(work_id)
        if work_state is None:
            return None
        return self._get_processed_count_from_work(work_state)

    def _get_work_state(self, work_id: str) -> Optional[Dict]:
        work_api = self._get_work_api()
        if work_api is None or not hasattr(work_api, "get_work"):
            return None

        try:
            return work_api.get_work(work_id)
        except Exception as exception:
            self._opencti_api.log_warning(
                f"Unable to query OpenCTI work {work_id}: {exception}"
            )
            return None

    @staticmethod
    def _get_processed_count_from_work(work_state: Dict) -> Optional[int]:
        if work_state is None:
            return None
        tracking = work_state.get("tracking") or {}
        processed = tracking.get("import_processed_number")
        if processed is None:
            return None
        return int(processed)

    @staticmethod
    def _get_expected_count_from_work(work_state: Dict) -> Optional[int]:
        if work_state is None:
            return None
        tracking = work_state.get("tracking") or {}
        expected = tracking.get("import_expected_number")
        if expected is None:
            return None
        return int(expected)

    @staticmethod
    def _get_errors_count_from_work(work_state: Optional[Dict]) -> int:
        if work_state is None:
            return 0
        return len(work_state.get("errors") or [])

    @staticmethod
    def _count_stage_expectations(
        sent_bundles: Optional[List], fallback_expected_count: int
    ) -> int:
        if not sent_bundles:
            return fallback_expected_count

        expectations = 0
        for bundle in sent_bundles:
            try:
                bundle_data = json.loads(bundle) if isinstance(bundle, str) else bundle
                expectations += len(bundle_data.get("objects") or [])
            except Exception:
                expectations += 1
        return expectations or fallback_expected_count

    def _apply_create_only_description_mode(self, stix_objects: List[Dict]) -> None:
        pending_objects: Dict[str, List[Dict]] = {}
        for stix_object in stix_objects:
            object_id = stix_object.get("id")
            if object_id is None:
                self._log_description_skip(stix_object, "missing-id")
                self._strip_descriptions([stix_object])
                continue

            if object_id in self._known_new_ids:
                continue
            if object_id in self._known_existing_ids:
                self._strip_descriptions([stix_object])
                continue

            pending_objects.setdefault(object_id, []).append(stix_object)

        if not pending_objects:
            return

        pending_ids = list(pending_objects.keys())
        try:
            existing_ids = self._prefetch_existing_object_ids(pending_ids)
        except Exception as exception:
            sample_object = next(iter(pending_objects.values()))[0]
            pending_count = sum(len(objects) for objects in pending_objects.values())
            self._log_description_batch_skip(
                sample_object=sample_object,
                count=pending_count,
                reason=str(exception),
            )
            for objects in pending_objects.values():
                self._strip_descriptions(objects)
            return

        self._known_existing_ids.update(existing_ids)
        self._known_new_ids.update(set(pending_ids) - existing_ids)

        for object_id, objects in pending_objects.items():
            if object_id in existing_ids:
                self._strip_descriptions(objects)

    def _prefetch_existing_object_ids(self, object_ids: List[str]) -> Set[str]:
        api_client = getattr(self._opencti_api, "api", None)
        if api_client is None:
            raise RuntimeError("OpenCTI API client is unavailable")

        reader = getattr(api_client, "opencti_stix_object_or_stix_relationship", None)
        if reader is None or not hasattr(reader, "list"):
            raise RuntimeError(
                "OpenCTI batched existence lookup is unavailable"
            )

        existing_ids: Set[str] = set()
        for chunk in self._chunk_values(object_ids, Connector.DESCRIPTION_LOOKUP_CHUNK_SIZE):
            self._run_metrics["existence_lookup_calls"] += 1
            self._run_metrics["existence_lookup_ids_total"] += len(chunk)
            result = reader.list(
                filters=self._build_ids_filter(chunk),
                first=len(chunk),
                getAll=True,
                customAttributes=Connector.STIX_OBJECT_LOOKUP_ATTRIBUTES,
            )
            requested_ids = set(chunk)
            for item in result or []:
                for key in ("id", "standard_id"):
                    candidate_id = item.get(key)
                    if candidate_id in requested_ids:
                        existing_ids.add(candidate_id)
                for source_stix_id in item.get("x_opencti_stix_ids") or []:
                    if source_stix_id in requested_ids:
                        existing_ids.add(source_stix_id)

        return existing_ids

    def _log_description_skip(self, stix_object: Dict, reason: str) -> None:
        object_type = stix_object.get("type", "<unknown>")
        object_id = stix_object.get("id", "<missing>")
        self._opencti_api.log_warning(
            f"skip description mode=create_only type={object_type} "
            f"id={object_id} reason={reason}"
        )

    def _log_description_batch_skip(
        self, sample_object: Dict, count: int, reason: str
    ) -> None:
        sample_type = sample_object.get("type", "<unknown>")
        sample_id = sample_object.get("id", "<missing>")
        self._opencti_api.log_warning(
            f"skip descriptions mode=create_only count={count} "
            f"reason={reason} sample={sample_type}:{sample_id}"
        )

    def _strip_descriptions(self, stix_objects: List[Dict]) -> None:
        for stix_object in stix_objects:
            if self._has_description(stix_object):
                self._strip_description_fields(stix_object)
                self._run_metrics["descriptions_stripped_total"] += 1

    @staticmethod
    def _has_description(stix_object: Dict) -> bool:
        return any(field in stix_object for field in Connector.DESCRIPTION_FIELDS)

    @staticmethod
    def _strip_description_fields(stix_object: Dict) -> Dict:
        for field_name in Connector.DESCRIPTION_FIELDS:
            stix_object.pop(field_name, None)
        return stix_object

    @staticmethod
    def _chunk_values(values: List[str], chunk_size: int) -> List[List[str]]:
        return [
            values[index : index + chunk_size]
            for index in range(0, len(values), chunk_size)
        ]

    @staticmethod
    def _build_ids_filter(object_ids: List[str]) -> Dict:
        return {
            "mode": "and",
            "filterGroups": [],
            "filters": [
                {
                    "key": "ids",
                    "mode": "or",
                    "values": object_ids,
                }
            ],
        }

    def _reset_run_metrics(self) -> None:
        self._run_metrics = {
            "objects_total": 0,
            "batches_total": 0,
            "stages_total": 0,
            "existence_lookup_calls": 0,
            "existence_lookup_ids_total": 0,
            "descriptions_stripped_total": 0,
        }

    def _finalize_run_metrics(self, wall_time_sec: float) -> None:
        self._last_run_metrics = dict(self._run_metrics)
        self._last_run_metrics["sync_wall_time_sec"] = wall_time_sec
        self._last_run_metrics["objects_per_sec"] = (
            self._run_metrics["objects_total"] / wall_time_sec if wall_time_sec > 0 else 0.0
        )
        self._last_run_metrics["avg_lookup_chunk_size"] = (
            self._run_metrics["existence_lookup_ids_total"]
            / self._run_metrics["existence_lookup_calls"]
            if self._run_metrics["existence_lookup_calls"] > 0
            else 0.0
        )

    def _get_batch_date_added_ts(self, stix_objects: List) -> float:
        timestamp = 0.0
        for obj in stix_objects:
            # Update high-watermark from any object carrying source description.
            # This keeps incremental state progressing even when indicators are not emitted.
            object_description = obj.get("description") or obj.get("x_opencti_description") or ""
            timestamp = max(
                timestamp,
                self._get_date_added_ts_from_description(object_description),
            )
        return timestamp

    def _get_date_added_ts_from_description(self, description: str) -> float:
        date_added_ts = 0.0
        if "date_added=" not in description:
            return date_added_ts

        date_added_str = description.split("date_added=")[1].split(";")[0]
        if date_added_str:
            try:
                date_added = datetime.strptime(date_added_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
                date_added_ts = date_added.timestamp()
            except ValueError:
                self._opencti_api.log_warning(f"Invalid date format in description: {date_added_str}")
        return date_added_ts

    def _sync_state(self) -> None:
        """
        Force state synchronization for one-shot runs.

        In recent pycti versions `set_state()` only updates in-memory state.
        Persisting to OpenCTI happens during ping, which may not execute before
        process exit in run-and-terminate mode.
        """
        force_ping = getattr(self._opencti_api, "force_ping", None)
        if callable(force_ping):
            try:
                force_ping()
            # pylint: disable-next=broad-exception-caught
            except Exception as exception:
                self._opencti_api.log_warning(
                    f"Unable to synchronize connector state: {exception}"
                )

    def _start_work(
        self, run_started_at: datetime, last_added: Optional[datetime]
    ) -> Optional[str]:
        work_api = self._get_work_api()
        connector_id = getattr(self._opencti_api, "connector_id", None)
        if work_api is None or connector_id is None:
            return None

        try:
            work_id = work_api.initiate_work(
                connector_id,
                self._build_work_name(run_started_at, last_added),
            )
        except Exception as exception:
            self._opencti_api.log_warning(
                f"Unable to initiate OpenCTI work tracking: {exception}"
            )
            return None

        if work_id:
            try:
                work_api.to_received(
                    work_id, "Connector started the synchronization run"
                )
            except Exception as exception:
                self._opencti_api.log_warning(
                    f"Unable to mark OpenCTI work as received: {exception}"
                )
        return work_id

    def _complete_work(
        self, work_id: Optional[str], message: str, in_error: bool = False
    ) -> None:
        if work_id is None:
            return

        work_api = self._get_work_api()
        if work_api is None:
            return

        try:
            work_api.to_processed(work_id, message, in_error)
        except Exception as exception:
            self._opencti_api.log_warning(
                f"Unable to finalize OpenCTI work {work_id}: {exception}"
            )

    def _finalize_active_work(self, message: str, in_error: bool = False) -> None:
        if self._active_work_id is None or self._active_work_finalized:
            return

        self._complete_work(self._active_work_id, message, in_error)
        self._active_work_finalized = True

    def _handle_graceful_stop(self, stop_requested: ConnectorStopRequested) -> None:
        signal_name = stop_requested.signal_name
        self._graceful_shutdown_in_progress = True
        self._opencti_api.log_info(
            f"Connector received {signal_name}; finalizing graceful shutdown."
        )

        try:
            if self._active_work_id and not self._active_work_finalized:
                with self._temporary_graceful_stop_timeout():
                    if self._is_work_alive(self._active_work_id):
                        self._finalize_active_work(
                            f"Connector run interrupted by {signal_name} "
                            f"after queueing {self._active_work_objects_count} objects",
                            in_error=True,
                        )
                    else:
                        self._active_work_finalized = True
        # pylint: disable-next=broad-exception-caught
        except Exception as exception:
            self._opencti_api.log_warning(
                f"Graceful shutdown finalization failed: {exception}"
            )
        finally:
            self._graceful_shutdown_in_progress = False

        self._opencti_api.log_info("Connector graceful shutdown complete.")

    def _handle_stop_signal(self, signum, _frame) -> None:
        is_first_signal = self._shutdown_signal_name is None
        if is_first_signal:
            self._shutdown_signal_name = self._get_signal_name(signum)
        if (
            self._defer_stop_exception
            or self._graceful_shutdown_in_progress
            or not is_first_signal
        ):
            return
        raise ConnectorStopRequested(self._shutdown_signal_name)

    def _install_signal_handlers(self) -> Dict[int, object]:
        if threading.current_thread() is not threading.main_thread():
            self._opencti_api.log_warning(
                "Connector.run() is not executing in the main thread; "
                "signal-based graceful shutdown is disabled for this run."
            )
            return {}

        previous_handlers = {}
        for signum in Connector.SHUTDOWN_SIGNALS:
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, self._handle_stop_signal)
        return previous_handlers

    @staticmethod
    def _restore_signal_handlers(previous_handlers: Dict[int, object]) -> None:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)

    def _reset_run_shutdown_state(self) -> None:
        self._active_work_id = None
        self._active_work_finalized = False
        self._active_work_objects_count = 0
        self._shutdown_signal_name = None
        self._defer_stop_exception = False
        self._graceful_shutdown_in_progress = False

    def _run_with_deferred_stop(self, callback, *args, **kwargs):
        self._defer_stop_exception = True
        try:
            return callback(*args, **kwargs)
        finally:
            self._defer_stop_exception = False

    def _raise_if_stop_requested(self) -> None:
        if self._shutdown_signal_name is None:
            return
        raise ConnectorStopRequested(self._shutdown_signal_name)

    @staticmethod
    def _get_signal_name(signum: int) -> str:
        try:
            return signal.Signals(signum).name
        except ValueError:
            return f"SIGNAL-{signum}"

    @contextmanager
    def _temporary_graceful_stop_timeout(self):
        timeout_clients = []
        for client_name in ("api", "api_impersonate"):
            api_client = getattr(self._opencti_api, client_name, None)
            if api_client is None or not hasattr(api_client, "session_requests_timeout"):
                continue

            original_timeout = api_client.session_requests_timeout
            adjusted_timeout = Connector.GRACEFUL_STOP_TIMEOUT_SEC
            if isinstance(original_timeout, (int, float)) and original_timeout > 0:
                adjusted_timeout = min(
                    original_timeout, Connector.GRACEFUL_STOP_TIMEOUT_SEC
                )
            timeout_clients.append((api_client, original_timeout))
            api_client.session_requests_timeout = adjusted_timeout

        try:
            yield
        finally:
            for api_client, original_timeout in timeout_clients:
                api_client.session_requests_timeout = original_timeout

    def _is_work_alive(self, work_id: str) -> bool:
        work_api = self._get_work_api()
        if work_api is None:
            return True

        get_is_work_alive = getattr(work_api, "get_is_work_alive", None)
        if callable(get_is_work_alive):
            try:
                return bool(get_is_work_alive(work_id))
            except Exception as exception:
                self._opencti_api.log_warning(
                    f"Unable to query OpenCTI work liveness for {work_id}: {exception}"
                )
                return True

        get_work = getattr(work_api, "get_work", None)
        if callable(get_work):
            try:
                return self._is_work_alive_from_state(get_work(work_id))
            except Exception as exception:
                if self._is_missing_work_error(exception):
                    self._opencti_api.log_info(
                        f"OpenCTI work {work_id} is no longer available: {exception}"
                    )
                    return False

                self._opencti_api.log_warning(
                    f"Unable to query OpenCTI work liveness for {work_id}: {exception}"
                )
                return True

        return True

    @classmethod
    def _is_work_alive_from_state(cls, work_state: Optional[Dict]) -> bool:
        if not work_state:
            return False

        status = str(work_state.get("status", "")).strip().lower()
        if not status:
            return True
        return status not in cls.TERMINAL_WORK_STATUSES

    @staticmethod
    def _is_cancelled_or_failed_work(work_state: Optional[Dict]) -> bool:
        if not work_state:
            return False
        status = str(work_state.get("status", "")).strip().lower()
        return status in {"cancelled", "canceled", "error", "failed"}

    @staticmethod
    def _is_missing_work_error(exception: Exception) -> bool:
        message = str(exception).strip().lower()
        return any(
            marker in message
            for marker in (
                "not found",
                "no longer available",
                "unknown work",
                "does not exist",
                "doesn't exist",
            )
        )

    def _get_work_api(self):
        api_client = getattr(self._opencti_api, "api", None)
        return getattr(api_client, "work", None)

    @staticmethod
    def _build_work_name(
        run_started_at: datetime, last_added: Optional[datetime]
    ) -> str:
        run_started_label = run_started_at.replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        )
        if last_added is None:
            return f"Kaspersky Feeds run @ {run_started_label}"

        last_added_label = last_added.replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        )
        return (
            f"Kaspersky Feeds run @ {run_started_label} "
            f"(added_after={last_added_label})"
        )

    def _calc_threat_score_labels(
        self, score: int, score_high: int, score_medium: int
    ) -> List[str]:
        if score >= score_high:
            level = "high"
        elif score >= score_medium:
            level = "medium"
        else:
            level = "low"

        return get_threat_score_labels(level, self._label_format)


if __name__ == "__main__":
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument("-d", "--dry-run", action="store_true")
    args = args_parser.parse_args()

    # We ignore warnings about insecure SSL/TLS connections when SSL
    # verification is deliberately disabled by the user in the configuration.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    config = Configuration()

    if not config.expand_objects and not config.create_indicators:
        raise RuntimeError(
            "Invalid configuration: 'kaspersky.expand_objects' and "
            "'kaspersky.create_indicators' are both set to 'false'.\n"
            "No STIX objects will be produced with this configuration. "
            "At least one of these options must be enabled."
        )
    if not config.create_indicators and not config.create_observables:
        raise RuntimeError(
            "Invalid configuration: 'kaspersky.create_indicators' and "
            "'kaspersky.create_observables' are both set to 'false'.\n"
            "At least one must be set to 'true' to ensure meaningful STIX output.")

    try:
        opencti_client = OpenCTIConnectorHelper(config=config.all)
        opencti_client.log_info(f"Configuration: {config}")
        opencti_client.log_info(
            "Feature flags: "
            f"connector.threat_score_from_description={config.threat_score_from_description}, "
            f"connector.label_format={config.label_format}, "
            f"connector.description_mode={config.description_mode}, "
            f"kaspersky.expand_objects={config.expand_objects}, "
            f"kaspersky.create_indicators={config.create_indicators}, "
            f"kaspersky.create_observables={config.create_observables}"
        )

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
        label_format=config.label_format,
    )

    stix_provider = Stix21Transformer(
        source=taxii_client,
        expand_objects=config.expand_objects,
        create_indicators=config.create_indicators,
        create_observables=config.create_observables
    )

    connector = Connector(
        opencti_api=opencti_client,
        stix_source=stix_provider,
        initial_history=config.initial_history,
        update_interval=config.update_interval,
        update_existing_data=config.update_existing_data,
        dry_run=args.dry_run,
        label_format=config.label_format,
        description_mode=config.description_mode,
        threat_score_from_description=config.threat_score_from_description,
    )
    connector.run()
