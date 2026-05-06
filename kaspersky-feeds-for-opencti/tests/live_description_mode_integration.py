#!/usr/bin/env python3
"""Live integration coverage for description_mode regressions."""

import io
import json
import os
import sys
import time
import unittest
import uuid
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pycti import OpenCTIApiClient, OpenCTIConnectorHelper

import main
import manual_perf_sync
from kaspersky import Stix21Transformer, Taxii21Client


LIVE_TAXII_API_ROOT = "https://taxii.tip.kaspersky.com/taxii2"
LIVE_DEFAULT_CANDIDATE_LIMIT = 50
LIVE_WORK_TIMEOUT_SEC = 900
LIVE_QUERY_RETRY_SEC = 5


def _env_bool(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None or raw_value.strip() == "":
        return default
    return int(raw_value)


def _resolve_live_opencti_spec() -> Dict[str, str]:
    opencti_url = os.getenv("LIVE_OPENCTI_URL")
    opencti_token = os.getenv("LIVE_OPENCTI_TOKEN")
    if opencti_url and opencti_token:
        return {
            "url": opencti_url.rstrip("/"),
            "token": opencti_token,
            "compose_dir": None,
            "healthcheck_access_key": "",
            "manage": False,
        }

    compose_dir = Path(
        os.getenv(
            "LIVE_OPENCTI_COMPOSE_DIR", manual_perf_sync.DEFAULT_OPENCTI_COMPOSE_DIR
        )
    )
    env_data = manual_perf_sync._load_env_file(compose_dir / ".env")
    port = env_data.get("OPENCTI_PORT", "8080")

    return {
        "url": f"http://localhost:{port}",
        "token": env_data["OPENCTI_ADMIN_TOKEN"],
        "compose_dir": str(compose_dir),
        "healthcheck_access_key": env_data.get("OPENCTI_HEALTHCHECK_ACCESS_KEY", ""),
        "manage": _env_bool("LIVE_MANAGE_OPENCTI", True),
    }


def _build_helper_config(
    connector_id: str,
    connector_name: str,
    description_mode: str,
    dry_run: bool,
    update_existing_data: bool,
    opencti_spec: Dict[str, str],
    taxii_api_root: str,
    taxii_token: str,
    collection_name: str,
    initial_history: int,
) -> Dict:
    del dry_run
    return {
        "opencti": {
            "url": opencti_spec["url"],
            "token": opencti_spec["token"],
            "ssl_verify": True,
        },
        "connector": {
            "id": connector_id,
            "type": "EXTERNAL_IMPORT",
            "name": connector_name,
            "scope": "kaspersky",
            "queue_protocol": os.getenv("LIVE_QUEUE_PROTOCOL", "api"),
            "confidence_level": 100,
            "threat_score_from_description": False,
            "threat_score": 100,
            "threat_score_high": 75,
            "threat_score_medium": 50,
            "label_format": "legacy",
            "description_mode": description_mode,
            "log_level": "info",
            "update_existing_data": update_existing_data,
            "run_and_terminate": True,
        },
        "kaspersky": {
            "api_root": taxii_api_root,
            "connection_timeout": manual_perf_sync.DEFAULT_TIMEOUT,
            "api_token": taxii_token,
            "ssl_verify": True,
            "initial_history": initial_history,
            "update_interval": 3600,
            "expand_objects": True,
            "create_indicators": True,
            "create_observables": True,
            "collections": [collection_name],
        },
    }


def _build_taxii_client(taxii_api_root: str, taxii_token: str, collection_name: str):
    return Taxii21Client(
        api_root=taxii_api_root,
        api_token=taxii_token,
        ssl_verify=True,
        collections=[collection_name],
        timeout=manual_perf_sync.DEFAULT_TIMEOUT,
        logger=None,
        label_format="legacy",
    )


def _build_connector(
    connector_id: str,
    connector_name: str,
    description_mode: str,
    dry_run: bool,
    update_existing_data: bool,
    opencti_spec: Dict[str, str],
    taxii_api_root: str,
    taxii_token: str,
    collection_name: str,
    initial_history: int,
):
    config = _build_helper_config(
        connector_id=connector_id,
        connector_name=connector_name,
        description_mode=description_mode,
        dry_run=dry_run,
        update_existing_data=update_existing_data,
        opencti_spec=opencti_spec,
        taxii_api_root=taxii_api_root,
        taxii_token=taxii_token,
        collection_name=collection_name,
        initial_history=initial_history,
    )
    helper = OpenCTIConnectorHelper(config=config)
    taxii_client = _build_taxii_client(
        taxii_api_root=taxii_api_root,
        taxii_token=taxii_token,
        collection_name=collection_name,
    )
    stix_provider = Stix21Transformer(
        source=taxii_client,
        expand_objects=True,
        create_indicators=True,
        create_observables=True,
    )
    connector = main.Connector(
        opencti_api=helper,
        stix_source=stix_provider,
        initial_history=initial_history,
        update_interval=3600,
        update_existing_data=update_existing_data,
        dry_run=dry_run,
        label_format="legacy",
        description_mode=description_mode,
    )
    return helper, connector


def _run_connector_once(
    connector_id: str,
    connector_name: str,
    description_mode: str,
    dry_run: bool,
    update_existing_data: bool,
    opencti_spec: Dict[str, str],
    taxii_api_root: str,
    taxii_token: str,
    collection_name: str,
    initial_history: int,
) -> Dict:
    helper, connector = _build_connector(
        connector_id=connector_id,
        connector_name=connector_name,
        description_mode=description_mode,
        dry_run=dry_run,
        update_existing_data=update_existing_data,
        opencti_spec=opencti_spec,
        taxii_api_root=taxii_api_root,
        taxii_token=taxii_token,
        collection_name=collection_name,
        initial_history=initial_history,
    )

    exit_code = 0
    captured_stdout = io.StringIO()
    try:
        with mock.patch.object(main.sys, "exit", side_effect=SystemExit(0)):
            try:
                if dry_run:
                    with redirect_stdout(captured_stdout):
                        connector.run()
                else:
                    connector.run()
            except SystemExit as exit_signal:
                exit_code = int(exit_signal.code or 0)
    finally:
        del helper

    return {
        "connector_id": connector_id,
        "exit_code": exit_code,
        "metrics": connector.get_last_run_metrics(),
        "stdout": captured_stdout.getvalue(),
    }


def _collect_candidate_source_ids(
    taxii_api_root: str, taxii_token: str, collection_name: str, initial_history: int
) -> List[str]:
    taxii_client = _build_taxii_client(
        taxii_api_root=taxii_api_root,
        taxii_token=taxii_token,
        collection_name=collection_name,
    )
    stix_provider = Stix21Transformer(
        source=taxii_client,
        expand_objects=True,
        create_indicators=True,
        create_observables=True,
    )
    added_after = datetime.now(timezone.utc) - timedelta(seconds=initial_history)

    source_ids = []
    for stix_object in stix_provider.enumerate(added_after=added_after):
        if stix_object.get("type") != "indicator":
            continue
        if not (stix_object.get("description") or stix_object.get("x_opencti_description")):
            continue
        source_ids.append(stix_object["id"])
        if len(source_ids) >= LIVE_DEFAULT_CANDIDATE_LIMIT:
            break

    if not source_ids:
        raise RuntimeError("Unable to find candidate indicators with description")

    return source_ids


def _query_indicator_by_source_stix_id(
    api_client: OpenCTIApiClient, source_stix_id: str
) -> Optional[Dict]:
    query = """
    query FindIndicatorBySourceId($filters: FilterGroup) {
      stixObjectOrStixRelationships(filters: $filters, first: 10) {
        edges {
          node {
            __typename
            ... on StixObject {
              id
              standard_id
              x_opencti_stix_ids
            }
            ... on Indicator {
              description
              pattern
            }
          }
        }
      }
    }
    """
    result = api_client.query(
        query,
        {
            "filters": {
                "mode": "and",
                "filterGroups": [],
                "filters": [
                    {"key": "ids", "mode": "or", "values": [source_stix_id]},
                    {"key": "entity_type", "operator": "eq", "values": ["Indicator"]},
                ],
            }
        },
    )

    for edge in result["data"]["stixObjectOrStixRelationships"]["edges"]:
        node = edge["node"]
        if node.get("__typename") == "Indicator":
            return node

    return None


def _find_existing_mismatched_indicator(
    api_client: OpenCTIApiClient, source_stix_ids: List[str]
) -> Optional[Dict]:
    for source_stix_id in source_stix_ids:
        candidate = _query_indicator_by_source_stix_id(api_client, source_stix_id)
        if candidate and candidate.get("standard_id") != source_stix_id:
            return {
                "source_stix_id": source_stix_id,
                "indicator": candidate,
            }
    return None


def _wait_for_connector_work(
    api_client: OpenCTIApiClient, connector_id: str, timeout_sec: int = LIVE_WORK_TIMEOUT_SEC
) -> Dict:
    deadline = time.time() + timeout_sec
    latest_work = None
    while time.time() < deadline:
        works = api_client.work.get_connector_works(connector_id)
        if works:
            latest_work = works[-1]
            tracking = latest_work.get("tracking") or {}
            expected = tracking.get("import_expected_number") or 0
            processed = tracking.get("import_processed_number") or 0
            if latest_work.get("status") == "complete" and processed >= expected:
                return latest_work
        time.sleep(LIVE_QUERY_RETRY_SEC)

    raise RuntimeError(
        f"Timed out waiting for connector work completion: connector_id={connector_id}, "
        f"last_work={json.dumps(latest_work, sort_keys=True) if latest_work else '<none>'}"
    )


def _update_indicator_description(
    api_client: OpenCTIApiClient, opencti_id: str, sentinel_description: str
) -> None:
    api_client.stix_domain_object.update_field(
        id=opencti_id,
        input=[{"key": "description", "value": [sentinel_description]}],
    )


def _find_printed_object(stdout_payload: str, source_stix_id: str) -> Dict:
    for line in stdout_payload.splitlines():
        line = line.strip()
        if not line:
            continue
        candidate = json.loads(line)
        if candidate.get("id") == source_stix_id:
            return candidate
    raise RuntimeError(f"Unable to find printed object for source STIX ID {source_stix_id}")


class LiveDescriptionModeIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.taxii_token = os.getenv("LIVE_TAXII_API_TOKEN")
        if not cls.taxii_token:
            raise unittest.SkipTest(
                "LIVE_TAXII_API_TOKEN is required for live integration tests"
            )

        cls.initial_history = _env_int(
            "LIVE_INITIAL_HISTORY", manual_perf_sync.DEFAULT_INITIAL_HISTORY
        )
        cls.opencti_spec = _resolve_live_opencti_spec()
        manual_perf_sync._ensure_opencti_ready(cls.opencti_spec, reset_state=True)

        cls.taxii_entrypoint = os.getenv("LIVE_TAXII_API_ROOT", LIVE_TAXII_API_ROOT)
        cls.api_root = manual_perf_sync._resolve_taxii_api_root(
            discovery_or_api_root=cls.taxii_entrypoint,
            api_token=cls.taxii_token,
            ssl_verify=True,
            timeout=manual_perf_sync.DEFAULT_TIMEOUT,
        )
        cls.selected_collection = manual_perf_sync._select_collection(
            cls.api_root,
            os.getenv("LIVE_COLLECTION"),
        )
        cls.collection_name = (
            cls.selected_collection.title or cls.selected_collection.id
        )
        cls.api_client = OpenCTIApiClient(
            cls.opencti_spec["url"], cls.opencti_spec["token"]
        )

        cls.candidate_source_ids = _collect_candidate_source_ids(
            taxii_api_root=cls.api_root.url,
            taxii_token=cls.taxii_token,
            collection_name=cls.collection_name,
            initial_history=cls.initial_history,
        )

        seed_connector_id = str(uuid.uuid4())
        cls.seed_run = _run_connector_once(
            connector_id=seed_connector_id,
            connector_name="Kaspersky Feeds Live Seed",
            description_mode="overwrite",
            dry_run=False,
            update_existing_data=False,
            opencti_spec=cls.opencti_spec,
            taxii_api_root=cls.api_root.url,
            taxii_token=cls.taxii_token,
            collection_name=cls.collection_name,
            initial_history=cls.initial_history,
        )
        if cls.seed_run["exit_code"] != 0:
            raise RuntimeError(f"Seed run failed with exit code {cls.seed_run['exit_code']}")
        _wait_for_connector_work(cls.api_client, seed_connector_id)

        candidate_match = _find_existing_mismatched_indicator(
            cls.api_client, cls.candidate_source_ids
        )
        if candidate_match is None:
            raise RuntimeError(
                "Unable to find imported indicator with standard_id != source STIX ID"
            )
        cls.source_stix_id = candidate_match["source_stix_id"]
        cls.candidate_indicator = candidate_match["indicator"]

        cls.sentinel_description = (
            f"sentinel-live-description-{uuid.uuid4()}"
        )
        _update_indicator_description(
            cls.api_client,
            cls.candidate_indicator["id"],
            cls.sentinel_description,
        )
        refreshed_indicator = _query_indicator_by_source_stix_id(
            cls.api_client, cls.source_stix_id
        )
        if refreshed_indicator is None:
            raise RuntimeError("Unable to reload candidate indicator after sentinel update")
        if refreshed_indicator.get("description") != cls.sentinel_description:
            raise RuntimeError("Failed to set sentinel description before create_only rerun")

        create_only_connector_id = str(uuid.uuid4())
        cls.create_only_run = _run_connector_once(
            connector_id=create_only_connector_id,
            connector_name="Kaspersky Feeds Live CreateOnly",
            description_mode="create_only",
            dry_run=False,
            update_existing_data=True,
            opencti_spec=cls.opencti_spec,
            taxii_api_root=cls.api_root.url,
            taxii_token=cls.taxii_token,
            collection_name=cls.collection_name,
            initial_history=cls.initial_history,
        )
        if cls.create_only_run["exit_code"] != 0:
            raise RuntimeError(
                f"create_only run failed with exit code {cls.create_only_run['exit_code']}"
            )
        _wait_for_connector_work(cls.api_client, create_only_connector_id)
        cls.post_create_only_indicator = _query_indicator_by_source_stix_id(
            cls.api_client, cls.source_stix_id
        )
        if cls.post_create_only_indicator is None:
            raise RuntimeError("Unable to load candidate indicator after create_only run")

    def test_create_only_preserves_existing_indicator_description(self):
        self.assertEqual(
            self.post_create_only_indicator["description"],
            self.sentinel_description,
        )
        self.assertNotEqual(
            self.post_create_only_indicator["standard_id"],
            self.source_stix_id,
        )
        self.assertIn(
            self.source_stix_id,
            self.post_create_only_indicator.get("x_opencti_stix_ids") or [],
        )

    def test_dry_run_honors_description_mode_and_does_not_create_work(self):
        current_source_ids = _collect_candidate_source_ids(
            taxii_api_root=self.api_root.url,
            taxii_token=self.taxii_token,
            collection_name=self.collection_name,
            initial_history=self.initial_history,
        )
        dry_run_candidate = _find_existing_mismatched_indicator(
            self.api_client, current_source_ids
        )
        if dry_run_candidate is None:
            self.fail(
                "Unable to find an existing mismatched indicator candidate for dry-run validation"
            )

        dry_run_source_stix_id = dry_run_candidate["source_stix_id"]
        mode_expectations = {
            "overwrite": True,
            "skip": False,
            "create_only": False,
        }

        for mode, expect_description in mode_expectations.items():
            connector_id = str(uuid.uuid4())
            result = _run_connector_once(
                connector_id=connector_id,
                connector_name=f"Kaspersky Feeds Live DryRun {mode}",
                description_mode=mode,
                dry_run=True,
                update_existing_data=True,
                opencti_spec=self.opencti_spec,
                taxii_api_root=self.api_root.url,
                taxii_token=self.taxii_token,
                collection_name=self.collection_name,
                initial_history=self.initial_history,
            )

            self.assertEqual(result["exit_code"], 0, msg=f"dry-run mode={mode} failed")
            printed_object = _find_printed_object(
                result["stdout"], dry_run_source_stix_id
            )
            has_description = any(
                field in printed_object
                for field in main.Connector.DESCRIPTION_FIELDS
            )
            self.assertEqual(
                has_description,
                expect_description,
                msg=f"Unexpected description presence for dry-run mode={mode}",
            )
            self.assertEqual(
                self.api_client.work.get_connector_works(connector_id),
                [],
                msg=f"dry-run mode={mode} unexpectedly created OpenCTI work",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
