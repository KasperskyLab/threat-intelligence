import json
import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import main
from pycti import Indicator
from kaspersky.stix_source import Stix21Source
from kaspersky.stix_transformer import Stix21Transformer


class FakeOpenCTIHelper:
    def __init__(self):
        self.connect_run_and_terminate = False
        self.connector_id = "connector--test"
        self.config = {
            "connector": {
                "confidence_level": 100,
                "threat_score_from_description": False,
                "threat_score": 100,
                "threat_score_high": 75,
                "threat_score_medium": 50,
                "label_format": "legacy",
                "description_mode": "overwrite",
            }
        }

    def log_warning(self, message):
        del message

    def log_info(self, message):
        del message

    def log_error(self, message):
        del message

    def log_debug(self, message):
        del message


class FakeGraphQLApi:
    def __init__(self, works):
        self.works = works
        self.variables = None

    def query(self, _query, variables, *_args):
        self.variables = variables
        return {
            "data": {
                "works": {
                    "edges": [{"node": work} for work in self.works],
                }
            }
        }


class FailingGraphQLApi:
    def query(self, *_args):
        raise RuntimeError("query failed")


class FakeIndicatorSource(Stix21Source):
    def __init__(self, indicators):
        self._indicators = list(indicators)

    def enumerate(self, added_after=None):
        del added_after
        for indicator in self._indicators:
            yield indicator


class FakeBatchSource(Stix21Source):
    def __init__(self, batches):
        self._batches = list(batches)

    def enumerate_batches(self, added_after=None):
        del added_after
        for batch in self._batches:
            yield batch

    def enumerate(self, added_after=None):
        raise AssertionError("legacy enumerate should not be used")


def make_connector():
    return make_connector_with_source(FakeIndicatorSource([]))


def make_connector_with_source(stix_source):
    return main.Connector(
        opencti_api=FakeOpenCTIHelper(),
        stix_source=stix_source,
        update_interval=1,
        update_existing_data=False,
        dry_run=True,
        label_format="legacy",
        description_mode="overwrite",
        threat_score_from_description=False,
    )


def make_indicator(indicator_id, description, pattern="[ipv4-addr:value = '1.2.3.4']"):
    indicator_uuid = uuid.uuid5(uuid.NAMESPACE_URL, indicator_id)
    return {
        "type": "indicator",
        "id": f"indicator--{indicator_uuid}",
        "name": "IP",
        "pattern": pattern,
        "description": description,
        "labels": [],
        "valid_until": "2100-01-01T00:00:00.000Z",
    }


def standard_indicator_id(indicator):
    return Indicator.generate_id(indicator["pattern"])


class ClusterAwareBatchingTest(unittest.TestCase):
    def _make_cluster(self, cluster_id, entity_count, relationship_count):
        objects = []
        for index in range(entity_count):
            objects.append(
                {
                    "type": "indicator",
                    "id": f"indicator--{cluster_id}-{index}",
                    "pattern": "[ipv4-addr:value = '1.2.3.4']",
                    "name": "IP",
                    "description": "date_added=2026-04-21T10:00:00.000Z",
                    "labels": [],
                }
            )

        for index in range(relationship_count):
            objects.append(
                {
                    "type": "relationship",
                    "id": f"relationship--{cluster_id}-{index}",
                    "relationship_type": "based-on",
                    "source_ref": f"indicator--{cluster_id}-0",
                    "target_ref": f"indicator--{cluster_id}-{min(index, entity_count - 1)}",
                }
            )
        return objects

    def test_cluster_with_trailing_relationships_is_not_split(self):
        connector = make_connector()
        cluster_a = self._make_cluster("A", entity_count=2, relationship_count=2)
        cluster_b = self._make_cluster("B", entity_count=2, relationship_count=2)

        batches = list(connector._get_batches([cluster_a, cluster_b], size=5))

        self.assertEqual([len(batch) for batch in batches], [4, 4])
        for batch in batches:
            entity_ids = {obj["id"] for obj in batch if obj["type"] != "relationship"}
            relationships = [obj for obj in batch if obj["type"] == "relationship"]
            self.assertGreater(len(relationships), 0)
            for relationship in relationships:
                self.assertIn(relationship["source_ref"], entity_ids)
                self.assertIn(relationship["target_ref"], entity_ids)

    def test_oversized_cluster_is_emitted_as_single_batch(self):
        connector = make_connector()
        small_before = self._make_cluster("before", entity_count=1, relationship_count=1)
        oversized = self._make_cluster("oversized", entity_count=3, relationship_count=3)
        small_after = self._make_cluster("after", entity_count=1, relationship_count=1)

        batches = list(
            connector._get_batches([small_before, oversized, small_after], size=5)
        )

        self.assertEqual([len(batch) for batch in batches], [2, 6, 2])

    def test_connector_uses_ready_batches_without_rechunking(self):
        oversized_batch = self._make_cluster(
            "ready", entity_count=3, relationship_count=3
        )
        connector = make_connector_with_source(FakeBatchSource([oversized_batch]))

        batches = list(connector._enumerate_source_batches())

        self.assertEqual([len(batch) for batch in batches], [6])


class DependencyStagingTest(unittest.TestCase):
    def _make_staged_objects(self):
        author = {"type": "identity", "id": "identity--author"}
        indicator = {
            "type": "indicator",
            "id": "indicator--stage",
            "created_by_ref": author["id"],
        }
        actor = {
            "type": "threat-actor",
            "id": "threat-actor--stage",
            "created_by_ref": author["id"],
        }
        relationship = {
            "type": "relationship",
            "id": "relationship--stage",
            "created_by_ref": author["id"],
            "source_ref": indicator["id"],
            "target_ref": actor["id"],
        }
        report = {
            "type": "report",
            "id": "report--stage",
            "created_by_ref": author["id"],
            "object_refs": [indicator["id"], actor["id"]],
        }
        return author, indicator, actor, relationship, report

    def test_dependency_stages_order_refs_before_dependents(self):
        author, indicator, actor, relationship, report = self._make_staged_objects()
        connector = make_connector()

        stages = connector._build_dependency_stages(
            [relationship, report, actor, indicator, author]
        )
        stage_ids = [[stix_object["id"] for stix_object in stage] for stage in stages]

        self.assertEqual(stage_ids[0], [author["id"]])
        self.assertEqual(set(stage_ids[1]), {indicator["id"], actor["id"]})
        self.assertEqual(set(stage_ids[2]), {relationship["id"], report["id"]})

    def test_dependency_stages_fail_fast_on_unresolved_ref(self):
        author, indicator, actor, relationship, _ = self._make_staged_objects()
        relationship["target_ref"] = "threat-actor--missing"
        connector = make_connector()

        with self.assertRaisesRegex(RuntimeError, "Unresolved STIX reference"):
            connector._build_dependency_stages([author, indicator, actor, relationship])

    def test_prepare_and_print_batch_uses_dependency_stage_order(self):
        author, indicator, _, relationship, _ = self._make_staged_objects()
        relationship["target_ref"] = author["id"]
        connector = make_connector()

        with mock.patch("builtins.print") as mocked_print:
            connector._prepare_and_print_batch([relationship, indicator, author])

        printed_ids = [
            json.loads(call.args[0])["id"]
            for call in mocked_print.call_args_list
        ]
        self.assertEqual(
            printed_ids,
            [author["id"], indicator["id"], relationship["id"]],
        )

    def test_prepare_and_send_batch_waits_after_each_stage(self):
        author, indicator, _, relationship, _ = self._make_staged_objects()
        relationship["target_ref"] = author["id"]

        class StageRecordingConnector(main.Connector):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.sent_stage_ids = []
                self.waited_stage_indexes = []

            def _snapshot_stage_import_state(self, work_id):
                del work_id
                return {}

            def _send_objects(self, stix_objects, work_id=None):
                del work_id
                self.sent_stage_ids.append(
                    [stix_object["id"] for stix_object in stix_objects]
                )
                return [{"objects": list(stix_objects)}]

            def _wait_for_stage_import(
                self,
                work_id,
                snapshot,
                sent_bundles,
                fallback_expected_count,
                stage_index,
                stages_total,
            ):
                del work_id, snapshot, sent_bundles, fallback_expected_count
                del stages_total
                self.waited_stage_indexes.append(stage_index)

        connector = StageRecordingConnector(
            opencti_api=FakeOpenCTIHelper(),
            stix_source=FakeIndicatorSource([]),
            update_interval=1,
            update_existing_data=False,
            dry_run=False,
        )

        connector._prepare_and_send_batch([relationship, indicator, author])

        self.assertEqual(
            connector.sent_stage_ids,
            [[author["id"]], [indicator["id"]], [relationship["id"]]],
        )
        self.assertEqual(connector.waited_stage_indexes, [1, 2, 3])

    def test_complete_parent_work_is_not_treated_as_stage_cancel(self):
        connector = make_connector()

        with mock.patch.object(
            connector,
            "_get_work_state",
            return_value={"id": "work--1", "status": "complete"},
        ):
            connector._raise_if_parent_work_cancelled_or_failed(
                "work--1", stage_index=1, stages_total=1
            )

    def test_cancelled_parent_work_stops_stage_wait(self):
        connector = make_connector()

        with mock.patch.object(
            connector,
            "_get_work_state",
            return_value={"id": "work--1", "status": "cancelled"},
        ):
            with self.assertRaisesRegex(RuntimeError, "stopped during stage"):
                connector._raise_if_parent_work_cancelled_or_failed(
                    "work--1", stage_index=1, stages_total=1
                )

    def test_parent_work_wait_ignores_baseline_errors(self):
        connector = make_connector()
        work_state = {
            "id": "work--1",
            "status": "complete",
            "tracking": {"import_processed_number": 3},
            "errors": [{"message": "old error"}],
        }

        with mock.patch.object(connector, "_get_work_state", return_value=work_state):
            connector._wait_for_parent_work_progress(
                "work--1",
                baseline_processed=1,
                baseline_errors_count=1,
                expected_increment=2,
                stage_index=1,
                stages_total=1,
            )

    def test_parent_work_wait_fails_on_new_errors(self):
        connector = make_connector()
        work_state = {
            "id": "work--1",
            "status": "complete",
            "tracking": {"import_processed_number": 3},
            "errors": [{"message": "old error"}, {"message": "new error"}],
        }

        with mock.patch.object(connector, "_get_work_state", return_value=work_state):
            with self.assertRaisesRegex(RuntimeError, "strict import policy"):
                connector._wait_for_parent_work_progress(
                    "work--1",
                    baseline_processed=1,
                    baseline_errors_count=1,
                    expected_increment=2,
                    stage_index=1,
                    stages_total=1,
                )

    def test_stage_wait_uses_connector_listing_with_parent_progress_baseline(self):
        class WaitPathConnector(main.Connector):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.parent_wait_called = False
                self.connector_wait_called = False

            def _wait_for_parent_work_progress(self, **kwargs):
                self.parent_wait_called = True
                self.parent_wait_kwargs = kwargs

            def _wait_for_connector_stage_works(self, **kwargs):
                self.connector_wait_called = True
                self.connector_wait_kwargs = kwargs

        connector = WaitPathConnector(
            opencti_api=FakeOpenCTIHelper(),
            stix_source=FakeIndicatorSource([]),
            update_interval=1,
            update_existing_data=False,
            dry_run=False,
        )

        connector._wait_for_stage_import(
            work_id="work--parent",
            snapshot={
                "connector_work_ids": {"work--parent"},
                "parent_processed": 0,
                "parent_errors_count": 0,
            },
            sent_bundles=[{"objects": [{"id": "identity--author"}]}],
            fallback_expected_count=1,
            stage_index=1,
            stages_total=3,
        )

        self.assertFalse(connector.parent_wait_called)
        self.assertTrue(connector.connector_wait_called)
        self.assertEqual(connector.connector_wait_kwargs["parent_work_id"], "work--parent")
        self.assertEqual(connector.connector_wait_kwargs["baseline_processed"], 0)
        self.assertEqual(connector.connector_wait_kwargs["expected_increment"], 1)

    def test_stage_snapshot_uses_zero_parent_baseline_for_new_work(self):
        connector = make_connector()

        with mock.patch.object(
            connector,
            "_get_work_state",
            return_value={
                "id": "work--parent",
                "tracking": {"import_processed_number": None},
            },
        ):
            with mock.patch.object(
                connector,
                "_snapshot_connector_work_ids",
                return_value={"work--parent"},
            ):
                snapshot = connector._snapshot_stage_import_state("work--parent")

        self.assertEqual(snapshot["parent_processed"], 0)

    def test_connector_stage_wait_uses_parent_progress_when_no_internal_work_exists(self):
        connector = make_connector()
        work_states = [
            {"id": "work--parent", "status": "progress", "tracking": {"import_processed_number": 0}},
            {"id": "work--parent", "status": "progress", "tracking": {"import_processed_number": 0}},
            {"id": "work--parent", "status": "progress", "tracking": {"import_processed_number": 0}},
            {"id": "work--parent", "status": "progress", "tracking": {"import_processed_number": 1}},
        ]

        with mock.patch.object(
            connector,
            "_list_connector_works",
            return_value=[{"id": "work--parent", "status": "progress"}],
        ):
            with mock.patch.object(
                connector, "_get_work_state", side_effect=work_states
            ):
                with mock.patch("main.time.sleep"):
                    connector._wait_for_connector_stage_works(
                        before_work_ids={"work--parent"},
                        parent_work_id="work--parent",
                        baseline_processed=0,
                        baseline_errors_count=0,
                        expected_increment=1,
                        stage_index=1,
                        stages_total=1,
                    )

    def test_parent_progress_accepts_stage_local_expected_counter(self):
        connector = make_connector()

        self.assertTrue(
            connector._is_parent_progress_complete(
                {
                    "id": "work--parent",
                    "tracking": {
                        "import_expected_number": 12,
                        "import_processed_number": 12,
                    },
                },
                baseline_processed=1,
                expected_increment=12,
            )
        )

    def test_connector_stage_wait_does_not_hang_when_no_internal_work_is_created(self):
        helper = FakeOpenCTIHelper()
        helper.warnings = []
        helper.log_warning = helper.warnings.append
        connector = main.Connector(
            opencti_api=helper,
            stix_source=FakeIndicatorSource([]),
            update_interval=1,
            update_existing_data=False,
            dry_run=False,
        )

        with mock.patch.object(connector, "_list_connector_works", return_value=[]):
            with mock.patch("main.time.sleep"):
                connector._wait_for_connector_stage_works(
                    before_work_ids=set(),
                    parent_work_id=None,
                    baseline_processed=None,
                    baseline_errors_count=0,
                    expected_increment=1,
                    stage_index=1,
                    stages_total=1,
                )

        self.assertTrue(
            any("No OpenCTI internal work detected" in msg for msg in helper.warnings)
        )

    def test_connector_stage_wait_fails_when_work_listing_may_be_truncated(self):
        connector = make_connector()
        connector._connector_works_truncation_warned = True

        with mock.patch.object(connector, "_list_connector_works", return_value=[]):
            with mock.patch("main.time.sleep"):
                with self.assertRaisesRegex(RuntimeError, "may be truncated"):
                    connector._wait_for_connector_stage_works(
                        before_work_ids=set(),
                        parent_work_id=None,
                        baseline_processed=None,
                        baseline_errors_count=0,
                        expected_increment=1,
                        stage_index=1,
                        stages_total=1,
                    )

    def test_connector_work_listing_uses_explicit_query_limit(self):
        helper = FakeOpenCTIHelper()
        helper.debug = []
        helper.log_debug = helper.debug.append
        graph_api = FakeGraphQLApi(
            [
                {"id": "work--2", "timestamp": "2026-05-19T00:00:02.000Z"},
                {"id": "work--1", "timestamp": "2026-05-19T00:00:01.000Z"},
            ]
        )
        helper.api = SimpleNamespace(work=SimpleNamespace(api=graph_api))
        connector = main.Connector(
            opencti_api=helper,
            stix_source=FakeIndicatorSource([]),
            update_interval=1,
            update_existing_data=False,
            dry_run=False,
        )

        works = connector._list_connector_works()

        self.assertEqual([work["id"] for work in works], ["work--1", "work--2"])
        self.assertEqual(
            graph_api.variables["count"], main.Connector.CONNECTOR_WORKS_QUERY_LIMIT
        )
        self.assertEqual(graph_api.variables["orderBy"], "timestamp")
        self.assertEqual(graph_api.variables["orderMode"], "desc")

    def test_connector_work_listing_warns_at_explicit_query_limit(self):
        helper = FakeOpenCTIHelper()
        helper.warnings = []
        helper.log_warning = helper.warnings.append
        graph_api = FakeGraphQLApi(
            [
                {"id": f"work--{index}", "timestamp": f"{index:04d}"}
                for index in range(main.Connector.CONNECTOR_WORKS_QUERY_LIMIT)
            ]
        )
        helper.api = SimpleNamespace(work=SimpleNamespace(api=graph_api))
        connector = main.Connector(
            opencti_api=helper,
            stix_source=FakeIndicatorSource([]),
            update_interval=1,
            update_existing_data=False,
            dry_run=False,
        )

        connector._list_connector_works()

        self.assertTrue(connector._connector_works_truncation_warned)
        self.assertTrue(
            any("explicit query limit" in message for message in helper.warnings)
        )

    def test_connector_work_listing_marks_pycti_fallback_as_potentially_limited(self):
        helper = FakeOpenCTIHelper()
        helper.warnings = []
        helper.log_warning = helper.warnings.append
        helper.api = SimpleNamespace(
            work=SimpleNamespace(
                api=FailingGraphQLApi(),
                get_connector_works=lambda _connector_id: [
                    {"id": "work--fallback", "timestamp": "2026-05-19T00:00:00.000Z"}
                ],
            )
        )
        connector = main.Connector(
            opencti_api=helper,
            stix_source=FakeIndicatorSource([]),
            update_interval=1,
            update_existing_data=False,
            dry_run=False,
        )

        works = connector._list_connector_works()

        self.assertEqual([work["id"] for work in works], ["work--fallback"])
        self.assertTrue(connector._connector_works_truncation_warned)
        self.assertTrue(
            any("pycti fallback" in message for message in helper.warnings)
        )


class EnumerateBatchesTest(unittest.TestCase):
    def _entity_ids(self, bundle):
        return {obj["id"] for obj in bundle if obj["type"] != "relationship"}

    def _objects_by_type(self, bundle, object_type):
        return [obj for obj in bundle if obj["type"] == object_type]

    def _assert_bundle_refs_resolve(self, bundle):
        entity_ids = self._entity_ids(bundle)
        for stix_object in bundle:
            for key in ("created_by_ref", "x_opencti_created_by_ref"):
                if key in stix_object:
                    self.assertIn(stix_object[key], entity_ids)

            if stix_object["type"] == "relationship":
                self.assertIn(stix_object["source_ref"], entity_ids)
                self.assertIn(stix_object["target_ref"], entity_ids)

            for object_ref in stix_object.get("object_refs", []):
                self.assertIn(object_ref, entity_ids)

    def test_no_source_objects_emit_no_author_only_bundle(self):
        transformer = Stix21Transformer(
            source=FakeIndicatorSource([]),
            expand_objects=True,
            create_indicators=True,
            create_observables=True,
        )

        self.assertEqual(list(transformer.enumerate_batches()), [])

    def test_expand_objects_disabled_emits_author_and_indicator(self):
        transformer = Stix21Transformer(
            source=FakeIndicatorSource(
                [
                    make_indicator(
                        "indicator--no-expand",
                        "date_added=2026-04-21T10:00:00.000Z;actors=APT-Test",
                    )
                ]
            ),
            expand_objects=False,
            create_indicators=True,
            create_observables=True,
        )

        bundles = list(transformer.enumerate_batches())

        self.assertEqual(len(bundles), 1)
        self.assertEqual(
            [obj["type"] for obj in bundles[0]],
            ["identity", "indicator"],
        )
        self._assert_bundle_refs_resolve(bundles[0])

    def test_indicator_bundle_keeps_relationship_refs_with_entities(self):
        indicator = make_indicator(
            "indicator--cluster",
            "date_added=2026-04-21T10:00:00.000Z;actors=APT-Test",
        )
        transformer = Stix21Transformer(
            source=FakeIndicatorSource([indicator]),
            expand_objects=True,
            create_indicators=True,
            create_observables=True,
        )

        bundles = list(transformer.enumerate_batches(size=1))

        self.assertEqual(len(bundles), 1)
        self.assertGreater(len(self._objects_by_type(bundles[0], "relationship")), 0)
        self.assertIn(standard_indicator_id(indicator), self._entity_ids(bundles[0]))
        self._assert_bundle_refs_resolve(bundles[0])

    def test_indicator_refs_use_opencti_standard_indicator_id(self):
        indicator = make_indicator(
            "indicator--source-id",
            "date_added=2026-04-21T10:00:00.000Z;"
            "publication_name=Shared Report;"
            "detection_date=2026-04-21T10:00:00.000Z",
            pattern="[ipv4-addr:value = '95.164.17.24']",
        )
        transformer = Stix21Transformer(
            source=FakeIndicatorSource([indicator]),
            expand_objects=True,
            create_indicators=True,
            create_observables=True,
        )

        bundle = list(transformer.enumerate_batches(size=1))[0]
        original_id = indicator["x_opencti_stix_ids"][0]
        standard_id = standard_indicator_id(indicator)
        report = self._objects_by_type(bundle, "report")[0]
        relationships = self._objects_by_type(bundle, "relationship")

        self.assertNotEqual(original_id, standard_id)
        self.assertIn(standard_id, self._entity_ids(bundle))
        self.assertNotIn(original_id, self._entity_ids(bundle))
        self.assertIn(original_id, bundle[1]["x_opencti_stix_ids"])
        self.assertIn(standard_id, report["object_refs"])
        self.assertTrue(
            any(relationship["source_ref"] == standard_id for relationship in relationships)
        )
        self._assert_bundle_refs_resolve(bundle)

    def test_observable_mode_bundle_keeps_relationship_refs_with_entities(self):
        transformer = Stix21Transformer(
            source=FakeIndicatorSource(
                [
                    make_indicator(
                        "indicator--observable-cluster",
                        "date_added=2026-04-21T10:00:00.000Z;actors=APT-Test",
                    )
                ]
            ),
            expand_objects=True,
            create_indicators=False,
            create_observables=True,
        )

        bundles = list(transformer.enumerate_batches(size=1))
        entity_ids = self._entity_ids(bundles[0])

        self.assertEqual(len(bundles), 1)
        self.assertNotIn("indicator--observable-cluster", entity_ids)
        self.assertGreater(len(self._objects_by_type(bundles[0], "relationship")), 0)
        self._assert_bundle_refs_resolve(bundles[0])

    def test_shared_actor_is_repeated_in_each_dependent_bundle(self):
        transformer = Stix21Transformer(
            source=FakeIndicatorSource(
                [
                    make_indicator(
                        "indicator--shared-actor-1",
                        "date_added=2026-04-21T10:00:00.000Z;actors=APT-Shared",
                    ),
                    make_indicator(
                        "indicator--shared-actor-2",
                        "date_added=2026-04-21T10:05:00.000Z;actors=APT-Shared",
                    ),
                ]
            ),
            expand_objects=True,
            create_indicators=True,
            create_observables=True,
        )

        bundles = list(transformer.enumerate_batches(size=1))
        actor_ids = [
            {
                stix_object["id"]
                for stix_object in bundle
                if stix_object["type"] == "threat-actor"
            }
            for bundle in bundles
        ]

        self.assertEqual(len(bundles), 2)
        self.assertEqual(len(actor_ids[0].intersection(actor_ids[1])), 1)
        for bundle in bundles:
            self._assert_bundle_refs_resolve(bundle)

    def test_report_object_refs_are_batch_local(self):
        transformer = Stix21Transformer(
            source=FakeIndicatorSource(
                [
                    make_indicator(
                        "indicator--report-1",
                        "date_added=2026-04-21T10:00:00.000Z;"
                        "publication_name=Shared Report;"
                        "detection_date=2026-04-21T10:00:00.000Z",
                    ),
                    make_indicator(
                        "indicator--report-2",
                        "date_added=2026-04-21T10:05:00.000Z;"
                        "publication_name=Shared Report;"
                        "detection_date=2026-04-21T10:00:00.000Z",
                    ),
                ]
            ),
            expand_objects=True,
            create_indicators=True,
            create_observables=True,
        )

        bundles = list(transformer.enumerate_batches(size=1))
        reports = [self._objects_by_type(bundle, "report")[0] for bundle in bundles]

        self.assertEqual(len(bundles), 2)
        self.assertEqual(reports[0]["id"], reports[1]["id"])
        for bundle, report in zip(bundles, reports):
            self._assert_bundle_refs_resolve(bundle)
            self.assertGreater(len(report["object_refs"]), 0)
            self.assertTrue(
                set(report["object_refs"]).issubset(self._entity_ids(bundle))
            )

    def test_shared_report_in_one_source_batch_keeps_all_local_refs(self):
        indicators = [
            make_indicator(
                "indicator--same-batch-report-1",
                "date_added=2026-04-21T10:00:00.000Z;"
                "publication_name=Shared Report;"
                "detection_date=2026-04-21T10:00:00.000Z",
            ),
            make_indicator(
                "indicator--same-batch-report-2",
                "date_added=2026-04-21T10:05:00.000Z;"
                "publication_name=Shared Report;"
                "detection_date=2026-04-21T10:00:00.000Z",
            ),
        ]
        transformer = Stix21Transformer(
            source=FakeIndicatorSource(indicators),
            expand_objects=True,
            create_indicators=True,
            create_observables=True,
        )

        bundle = list(transformer.enumerate_batches(size=2))[0]
        report = self._objects_by_type(bundle, "report")[0]

        self.assertEqual(len(self._objects_by_type(bundle, "report")), 1)
        self.assertTrue(
            {standard_indicator_id(indicator) for indicator in indicators}.issubset(
                set(report["object_refs"])
            )
        )
        self._assert_bundle_refs_resolve(bundle)

    def test_report_refs_use_observables_when_indicators_are_disabled(self):
        transformer = Stix21Transformer(
            source=FakeIndicatorSource(
                [
                    make_indicator(
                        "indicator--observable-report",
                        "date_added=2026-04-21T10:00:00.000Z;"
                        "publication_name=Observable Report;"
                        "detection_date=2026-04-21T10:00:00.000Z",
                    )
                ]
            ),
            expand_objects=True,
            create_indicators=False,
            create_observables=True,
        )

        bundle = list(transformer.enumerate_batches(size=1))[0]
        report = self._objects_by_type(bundle, "report")[0]

        self.assertFalse(
            any(stix_object["type"] == "indicator" for stix_object in bundle)
        )
        self.assertGreater(len(report["object_refs"]), 0)
        self._assert_bundle_refs_resolve(bundle)

    def test_enumerate_flattens_batches_for_backward_compatibility(self):
        batch_transformer = Stix21Transformer(
            source=FakeIndicatorSource(
                [
                    make_indicator(
                        "indicator--flatten",
                        "date_added=2026-04-21T10:00:00.000Z;actors=APT-Test",
                    )
                ]
            ),
            expand_objects=True,
            create_indicators=True,
            create_observables=True,
        )
        enumerate_transformer = Stix21Transformer(
            source=FakeIndicatorSource(
                [
                    make_indicator(
                        "indicator--flatten",
                        "date_added=2026-04-21T10:00:00.000Z;actors=APT-Test",
                    )
                ]
            ),
            expand_objects=True,
            create_indicators=True,
            create_observables=True,
        )

        batches = list(batch_transformer.enumerate_batches())
        flattened_batches = [obj for batch in batches for obj in batch]
        flattened_enumerate = list(enumerate_transformer.enumerate())

        self.assertEqual(
            [obj["id"] for obj in flattened_enumerate],
            [obj["id"] for obj in flattened_batches],
        )


if __name__ == "__main__":
    unittest.main()
