import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import main
from kaspersky.taxii_client import processed_stix_object
from kaspersky.transforms.observable_transform import ObservableTransform


class FakeBatchLookupReader:
    def __init__(self, existing_ids=None, exception=None):
        self.existing_ids = set(existing_ids or [])
        self.exception = exception
        self.calls = []

    def list(self, **kwargs):
        self.calls.append(kwargs)
        if self.exception is not None:
            raise self.exception

        requested_ids = kwargs["filters"]["filters"][0]["values"]
        result = []
        for object_id in requested_ids:
            if object_id in self.existing_ids:
                result.append({"id": object_id})
        return result


class FakeApi:
    def __init__(self, batch_reader=None):
        self.opencti_stix_object_or_stix_relationship = (
            batch_reader or FakeBatchLookupReader()
        )


class FakeOpenCTIHelper:
    def __init__(self, label_format="legacy", description_mode="overwrite", api=None):
        self.api = api or FakeApi()
        self.connect_run_and_terminate = False
        self.connector_id = "connector--test"
        self.config = {
            "connector": {
                "confidence_level": 100,
                "threat_score_from_description": False,
                "threat_score": 100,
                "threat_score_high": 75,
                "threat_score_medium": 50,
                "label_format": label_format,
                "description_mode": description_mode,
            }
        }
        self.logged = {"warning": [], "info": [], "error": [], "debug": []}
        self.sent_bundles = []
        self._state = None

    def get_state(self):
        return self._state

    def set_state(self, state):
        self._state = state

    def force_ping(self):
        return None

    def send_stix2_bundle(self, bundle, **kwargs):
        self.sent_bundles.append((json.loads(bundle), kwargs))

    def log_warning(self, message):
        self.logged["warning"].append(message)

    def log_info(self, message):
        self.logged["info"].append(message)

    def log_error(self, message):
        self.logged["error"].append(message)

    def log_debug(self, message):
        self.logged["debug"].append(message)


class FakeSource:
    def enumerate(self, added_after=None):
        del added_after
        return iter(())


class RunOnceConnector(main.Connector):
    def __init__(self, *args, batches=None, **kwargs):
        helper = kwargs.get("opencti_api")
        if helper is not None:
            connector_config = helper.config["connector"]
            kwargs.setdefault("label_format", connector_config["label_format"])
            kwargs.setdefault("description_mode", connector_config["description_mode"])
        super().__init__(*args, **kwargs)
        self._batches = batches or []

    def _get_batches(self, stix_objects, size):
        del stix_objects
        del size
        for batch in self._batches:
            yield batch


def build_connector(helper, label_format=None, description_mode=None):
    connector_config = helper.config["connector"]
    return main.Connector(
        opencti_api=helper,
        stix_source=FakeSource(),
        update_interval=1,
        update_existing_data=False,
        dry_run=False,
        label_format=(
            connector_config["label_format"]
            if label_format is None
            else label_format
        ),
        description_mode=(
            connector_config["description_mode"]
            if description_mode is None
            else description_mode
        ),
    )


def make_taxii_indicator():
    return {
        "type": "indicator",
        "id": "indicator--taxii",
        "name": "URL",
        "pattern": "[url:value = 'https://example.com']",
        "description": "date_added=2026-04-21T10:00:00.000Z",
        "labels": ["malicious-activity", "keep-me"],
        "valid_until": "2100-01-01T00:00:00.000Z",
    }


def make_described_object(object_id, stix_type="indicator", description_field="description"):
    return {
        "type": stix_type,
        "id": object_id,
        description_field: f"date_added=2026-04-21T10:00:00.000Z;object_id={object_id}",
    }


class ConfigurationModesTest(unittest.TestCase):
    def test_configuration_defaults_keep_backward_compatible_modes(self):
        with mock.patch.dict(main.os.environ, {}, clear=True):
            with mock.patch.object(main.Configuration, "_read_file_config", return_value={}):
                config = main.Configuration()

        self.assertEqual(config.label_format, "legacy")
        self.assertEqual(config.description_mode, "overwrite")

    def test_configuration_accepts_environment_overrides(self):
        env = {
            "CONNECTOR_LABEL_FORMAT": "both",
            "CONNECTOR_DESCRIPTION_MODE": "create_only",
        }
        with mock.patch.dict(main.os.environ, env, clear=True):
            with mock.patch.object(main.Configuration, "_read_file_config", return_value={}):
                config = main.Configuration()

        self.assertEqual(config.label_format, "both")
        self.assertEqual(config.description_mode, "create_only")

    def test_configuration_rejects_invalid_modes(self):
        env = {
            "CONNECTOR_LABEL_FORMAT": "invalid",
            "CONNECTOR_DESCRIPTION_MODE": "invalid",
        }
        with mock.patch.dict(main.os.environ, env, clear=True):
            with mock.patch.object(main.Configuration, "_read_file_config", return_value={}):
                config = main.Configuration()
                with self.assertRaises(RuntimeError):
                    _ = config.label_format
                with self.assertRaises(RuntimeError):
                    _ = config.description_mode


class LabelFormatTest(unittest.TestCase):
    COLLECTION = "TAXII_Demo_IP_Reputation_Data_Feed"

    def test_legacy_label_format_keeps_current_labels(self):
        result = processed_stix_object(
            collection=self.COLLECTION,
            stix_object=make_taxii_indicator(),
            label_format="legacy",
        )

        self.assertEqual(
            result["labels"],
            [
                "malicious-activity:kaspersky",
                "keep-me",
                "demo_ip_reputation_data_feed",
            ],
        )
        self.assertNotIn("valid_until", result)

    def test_new_label_format_uses_only_prefixed_connector_labels(self):
        result = processed_stix_object(
            collection=self.COLLECTION,
            stix_object=make_taxii_indicator(),
            label_format="new",
        )

        self.assertEqual(
            result["labels"],
            [
                "kaspersky:malicious-activity",
                "keep-me",
                "kaspersky:demo_ip_reputation_data_feed",
            ],
        )

    def test_both_label_format_emits_legacy_then_new_without_duplicates(self):
        indicator = make_taxii_indicator()
        indicator["labels"] = [
            "malicious-activity",
            "kaspersky:malicious-activity",
            "demo_ip_reputation_data_feed",
        ]

        result = processed_stix_object(
            collection=self.COLLECTION,
            stix_object=indicator,
            label_format="both",
        )

        self.assertEqual(
            result["labels"],
            [
                "malicious-activity:kaspersky",
                "kaspersky:malicious-activity",
                "demo_ip_reputation_data_feed",
                "kaspersky:demo_ip_reputation_data_feed",
            ],
        )

    def test_observable_transform_inherits_processed_indicator_labels(self):
        indicator = processed_stix_object(
            collection=self.COLLECTION,
            stix_object=make_taxii_indicator(),
            label_format="new",
        )

        transform = ObservableTransform(author={"id": "identity--author"})
        observable = transform.build_objects(indicator, context={})[0]

        self.assertEqual(
            observable["x_opencti_labels"],
            [
                "kaspersky:malicious-activity",
                "keep-me",
                "kaspersky:demo_ip_reputation_data_feed",
            ],
        )


class ThreatScoreLabelFormatTest(unittest.TestCase):
    def test_indicator_uses_new_threat_score_label_format(self):
        helper = FakeOpenCTIHelper(label_format="new")
        connector = build_connector(helper)

        result = connector._update_score(
            {
                "type": "indicator",
                "id": "indicator--score",
                "description": "date_added=2026-04-21T10:00:00.000Z",
                "labels": [],
            }
        )

        self.assertEqual(result["labels"], ["kaspersky:threat_score:high"])

    def test_observable_payload_uses_both_threat_score_label_formats(self):
        helper = FakeOpenCTIHelper(label_format="both")
        connector = build_connector(helper)

        result = connector._update_score(
            {
                "type": "url",
                "id": "url--score",
                "x_opencti_description": "date_added=2026-04-21T10:00:00.000Z;threat_score=60",
                "x_opencti_labels": ["feed-label"],
            }
        )

        self.assertEqual(
            result["x_opencti_labels"],
            [
                "feed-label",
                "threat_score:kaspersky:medium",
                "kaspersky:threat_score:medium",
            ],
        )

    def test_connector_uses_injected_label_format_not_helper_runtime_config(self):
        helper = FakeOpenCTIHelper(label_format="legacy")
        connector = build_connector(helper, label_format="new")

        result = connector._update_score(
            {
                "type": "indicator",
                "id": "indicator--score-override",
                "description": "date_added=2026-04-21T10:00:00.000Z",
                "labels": [],
            }
        )

        self.assertEqual(result["labels"], ["kaspersky:threat_score:high"])


class DescriptionModeBatchTest(unittest.TestCase):
    def test_overwrite_preserves_description_fields_without_lookup(self):
        reader = FakeBatchLookupReader(existing_ids={"indicator--overwrite"})
        helper = FakeOpenCTIHelper(
            description_mode="overwrite",
            api=FakeApi(batch_reader=reader),
        )
        connector = build_connector(helper)
        batch = [
            {
                "type": "indicator",
                "id": "indicator--overwrite",
                "description": "hello",
                "x_opencti_description": "world",
            }
        ]

        connector._prepare_batch_for_send(batch)

        self.assertEqual(batch[0]["description"], "hello")
        self.assertEqual(batch[0]["x_opencti_description"], "world")
        self.assertEqual(reader.calls, [])
        self.assertEqual(connector._run_metrics["existence_lookup_calls"], 0)

    def test_skip_removes_description_fields_without_lookup(self):
        reader = FakeBatchLookupReader(existing_ids={"indicator--skip"})
        helper = FakeOpenCTIHelper(
            description_mode="skip",
            api=FakeApi(batch_reader=reader),
        )
        connector = build_connector(helper)
        batch = [
            {
                "type": "indicator",
                "id": "indicator--skip",
                "description": "hello",
                "x_opencti_description": "world",
            }
        ]

        connector._prepare_batch_for_send(batch)

        self.assertNotIn("description", batch[0])
        self.assertNotIn("x_opencti_description", batch[0])
        self.assertEqual(reader.calls, [])
        self.assertEqual(connector._run_metrics["descriptions_stripped_total"], 1)
        self.assertEqual(connector._run_metrics["existence_lookup_calls"], 0)

    def test_connector_uses_injected_description_mode_not_helper_runtime_config(self):
        reader = FakeBatchLookupReader(existing_ids={"indicator--skip"})
        helper = FakeOpenCTIHelper(
            description_mode="overwrite",
            api=FakeApi(batch_reader=reader),
        )
        connector = build_connector(helper, description_mode="skip")
        batch = [
            {
                "type": "indicator",
                "id": "indicator--skip",
                "description": "hello",
                "x_opencti_description": "world",
            }
        ]

        connector._prepare_batch_for_send(batch)

        self.assertNotIn("description", batch[0])
        self.assertNotIn("x_opencti_description", batch[0])
        self.assertEqual(reader.calls, [])
        self.assertEqual(connector._run_metrics["existence_lookup_calls"], 0)

    def test_create_only_keeps_description_for_new_objects_with_single_batch_lookup(self):
        reader = FakeBatchLookupReader(existing_ids=set())
        helper = FakeOpenCTIHelper(
            description_mode="create_only",
            api=FakeApi(batch_reader=reader),
        )
        connector = build_connector(helper)
        batch = [make_described_object("indicator--new")]

        connector._prepare_batch_for_send(batch)

        self.assertIn("description", batch[0])
        self.assertEqual(len(reader.calls), 1)
        self.assertEqual(
            reader.calls[0]["filters"]["filters"][0]["values"],
            ["indicator--new"],
        )
        self.assertEqual(connector._run_metrics["existence_lookup_calls"], 1)
        self.assertEqual(connector._run_metrics["existence_lookup_ids_total"], 1)

    def test_create_only_strips_description_for_existing_objects(self):
        reader = FakeBatchLookupReader(existing_ids={"url--existing"})
        helper = FakeOpenCTIHelper(
            description_mode="create_only",
            api=FakeApi(batch_reader=reader),
        )
        connector = build_connector(helper)
        batch = [
            make_described_object(
                "url--existing",
                stix_type="url",
                description_field="x_opencti_description",
            )
        ]

        connector._prepare_batch_for_send(batch)

        self.assertNotIn("x_opencti_description", batch[0])
        self.assertEqual(len(reader.calls), 1)
        self.assertEqual(connector._run_metrics["descriptions_stripped_total"], 1)

    def test_create_only_chunks_lookup_requests_by_200_ids(self):
        reader = FakeBatchLookupReader(existing_ids=set())
        helper = FakeOpenCTIHelper(
            description_mode="create_only",
            api=FakeApi(batch_reader=reader),
        )
        connector = build_connector(helper)
        batch = [
            make_described_object(f"indicator--{index}")
            for index in range(ConnectorConstants.CHUNK_TEST_SIZE)
        ]

        connector._prepare_batch_for_send(batch)

        chunk_sizes = [
            len(call["filters"]["filters"][0]["values"]) for call in reader.calls
        ]
        self.assertEqual(chunk_sizes, [200, 200, 1])
        self.assertEqual(connector._run_metrics["existence_lookup_calls"], 3)
        self.assertEqual(connector._run_metrics["existence_lookup_ids_total"], 401)

    def test_create_only_reuses_run_cache_across_batches(self):
        reader = FakeBatchLookupReader(existing_ids={"indicator--existing"})
        helper = FakeOpenCTIHelper(
            description_mode="create_only",
            api=FakeApi(batch_reader=reader),
        )
        connector = build_connector(helper)

        first_batch = [
            make_described_object("indicator--existing"),
            make_described_object("indicator--new-1"),
        ]
        second_batch = [
            make_described_object("indicator--existing"),
            make_described_object("indicator--new-1"),
            make_described_object("indicator--new-2"),
        ]

        connector._prepare_batch_for_send(first_batch)
        connector._prepare_batch_for_send(second_batch)

        requested_ids = [
            call["filters"]["filters"][0]["values"] for call in reader.calls
        ]
        self.assertEqual(requested_ids, [["indicator--existing", "indicator--new-1"], ["indicator--new-2"]])
        self.assertNotIn("description", first_batch[0])
        self.assertIn("description", first_batch[1])
        self.assertNotIn("description", second_batch[0])
        self.assertIn("description", second_batch[1])
        self.assertIn("description", second_batch[2])

    def test_create_only_deduplicates_same_id_within_batch(self):
        reader = FakeBatchLookupReader(existing_ids={"indicator--dup"})
        helper = FakeOpenCTIHelper(
            description_mode="create_only",
            api=FakeApi(batch_reader=reader),
        )
        connector = build_connector(helper)
        batch = [
            make_described_object("indicator--dup"),
            make_described_object("indicator--dup"),
        ]

        connector._prepare_batch_for_send(batch)

        self.assertEqual(len(reader.calls), 1)
        self.assertEqual(reader.calls[0]["filters"]["filters"][0]["values"], ["indicator--dup"])
        self.assertNotIn("description", batch[0])
        self.assertNotIn("description", batch[1])
        self.assertEqual(connector._run_metrics["descriptions_stripped_total"], 2)

    def test_create_only_strips_description_on_lookup_failure_and_logs_once(self):
        helper = FakeOpenCTIHelper(
            description_mode="create_only",
            api=FakeApi(batch_reader=FakeBatchLookupReader(exception=RuntimeError("lookup failed"))),
        )
        connector = build_connector(helper)
        batch = [
            make_described_object("indicator--lookup-fail-1"),
            make_described_object("indicator--lookup-fail-2"),
        ]

        connector._prepare_batch_for_send(batch)

        self.assertNotIn("description", batch[0])
        self.assertNotIn("description", batch[1])
        self.assertEqual(len(helper.logged["warning"]), 1)
        self.assertIn("skip descriptions mode=create_only count=2", helper.logged["warning"][0])
        self.assertIn("reason=lookup failed", helper.logged["warning"][0])
        self.assertIn("sample=indicator:indicator--lookup-fail-1", helper.logged["warning"][0])

    def test_create_only_strips_description_for_missing_id_and_logs_short_warning(self):
        reader = FakeBatchLookupReader(existing_ids=set())
        helper = FakeOpenCTIHelper(
            description_mode="create_only",
            api=FakeApi(batch_reader=reader),
        )
        connector = build_connector(helper)
        batch = [{"type": "indicator", "description": "hello"}]

        connector._prepare_batch_for_send(batch)

        self.assertNotIn("description", batch[0])
        self.assertEqual(reader.calls, [])
        self.assertEqual(len(helper.logged["warning"]), 1)
        self.assertEqual(
            helper.logged["warning"][0],
            "skip description mode=create_only type=indicator id=<missing> reason=missing-id",
        )


class WatermarkSafetyTest(unittest.TestCase):
    def test_state_progress_uses_batch_timestamp_even_when_description_is_stripped(self):
        helper = FakeOpenCTIHelper(description_mode="skip")
        helper.connect_run_and_terminate = True
        expected_ts = int(
            main.datetime.strptime(
                "2099-04-23T11:00:00.000Z", "%Y-%m-%dT%H:%M:%S.%fZ"
            )
            .replace(tzinfo=main.timezone.utc)
            .timestamp()
        )
        connector = RunOnceConnector(
            opencti_api=helper,
            stix_source=FakeSource(),
            update_interval=1,
            initial_history=60,
            update_existing_data=False,
            dry_run=False,
            batches=[
                [
                    {
                        "type": "indicator",
                        "id": "indicator--state",
                        "pattern": "[ipv4-addr:value = '1.1.1.1']",
                        "description": "date_added=2099-04-23T11:00:00.000Z;threat_score=80",
                        "labels": [],
                    }
                ]
            ],
        )

        with self.assertRaises(SystemExit):
            with mock.patch.object(main.sys, "exit", side_effect=SystemExit(0)):
                connector.run()

        self.assertEqual(helper.get_state()["last_added"], expected_ts)
        sent_object = helper.sent_bundles[0][0]["objects"][0]
        self.assertNotIn("description", sent_object)


class ConnectorConstants:
    CHUNK_TEST_SIZE = 401


if __name__ == "__main__":
    unittest.main()
