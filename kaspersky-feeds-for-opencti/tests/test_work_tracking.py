import json
import os
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import main


class FakeWorkApi:
    def __init__(
        self,
        alive_sequence=None,
        initiate_exception=None,
        received_exception=None,
        processed_exception=None,
        alive_exception=None,
    ):
        self.alive_sequence = list(alive_sequence or [])
        self.initiate_exception = initiate_exception
        self.received_exception = received_exception
        self.processed_exception = processed_exception
        self.alive_exception = alive_exception
        self.initiated = []
        self.received = []
        self.processed = []

    def initiate_work(self, connector_id, friendly_name):
        if self.initiate_exception is not None:
            raise self.initiate_exception
        self.initiated.append((connector_id, friendly_name))
        return "work--1"

    def to_received(self, work_id, message):
        if self.received_exception is not None:
            raise self.received_exception
        self.received.append((work_id, message))

    def to_processed(self, work_id, message, in_error=False):
        if self.processed_exception is not None:
            raise self.processed_exception
        self.processed.append((work_id, message, in_error))

    def get_is_work_alive(self, work_id):
        if self.alive_exception is not None:
            raise self.alive_exception
        if self.alive_sequence:
            return self.alive_sequence.pop(0)
        return True


class FakeWorkApiFallback:
    def __init__(self, work_state=None, work_exception=None):
        self.work_state = work_state
        self.work_exception = work_exception

    def get_work(self, work_id):
        if self.work_exception is not None:
            raise self.work_exception
        if self.work_state is None:
            raise RuntimeError("Work not found")
        return {"id": work_id, **self.work_state}


class FakeApi:
    def __init__(self, work_api):
        self.work = work_api
        self.session_requests_timeout = 300


class FakeOpenCTIHelper:
    def __init__(self, work_api, initial_state=None, send_exception=None):
        self.api = FakeApi(work_api)
        self.connector_id = "connector--1"
        self.connect_run_and_terminate = True
        self._state = initial_state
        self._send_exception = send_exception
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
        self.logged = {"info": [], "warning": [], "error": [], "debug": []}
        self.sent_bundles = []
        self.state_updates = []
        self.force_ping_called = False

    def get_state(self):
        return self._state

    def set_state(self, state):
        self._state = state
        self.state_updates.append(state)

    def send_stix2_bundle(self, bundle, **kwargs):
        if self._send_exception is not None:
            raise self._send_exception
        self.sent_bundles.append((json.loads(bundle), kwargs))

    def force_ping(self):
        self.force_ping_called = True

    def log_info(self, message):
        self.logged["info"].append(message)

    def log_warning(self, message):
        self.logged["warning"].append(message)

    def log_error(self, message):
        self.logged["error"].append(message)

    def log_debug(self, message):
        self.logged["debug"].append(message)


class FakeStixSource:
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


class SignalBeforeNextBatchConnector(RunOnceConnector):
    def _get_batches(self, stix_objects, size):
        del stix_objects
        del size
        for index, batch in enumerate(self._batches):
            if index == 1:
                self._handle_stop_signal(main.signal.SIGTERM, None)
            yield batch


class SignalDuringBatchPreparationConnector(RunOnceConnector):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._signal_sent = False

    def _prepare_batch_for_send(self, stix_objects):
        if not self._signal_sent:
            self._signal_sent = True
            self._handle_stop_signal(main.signal.SIGTERM, None)
        return super()._prepare_batch_for_send(stix_objects)


class ReadyFileDuringBatchPreparationConnector(RunOnceConnector):
    def __init__(self, *args, ready_path=None, hold_seconds=5.0, **kwargs):
        super().__init__(*args, **kwargs)
        self._ready_path = Path(ready_path) if ready_path is not None else None
        self._hold_seconds = hold_seconds
        self._ready_written = False

    def _prepare_batch_for_send(self, stix_objects):
        if not self._ready_written and self._ready_path is not None:
            self._ready_path.write_text("ready", encoding="utf-8")
            self._ready_written = True
            deadline = time.time() + self._hold_seconds
            while time.time() < deadline:
                time.sleep(0.1)
        return super()._prepare_batch_for_send(stix_objects)


def make_indicator(date_added):
    description = f"date_added={date_added};threat_score=80"
    return {
        "type": "indicator",
        "id": "indicator--test",
        "pattern": "[ipv4-addr:value = '1.1.1.1']",
        "description": description,
        "labels": [],
    }


def _run_signal_delivery_child(result_path: str, ready_path: str) -> None:
    work_api = FakeWorkApi(alive_sequence=[True, True])
    helper = FakeOpenCTIHelper(work_api)
    connector = ReadyFileDuringBatchPreparationConnector(
        opencti_api=helper,
        stix_source=FakeStixSource(),
        update_interval=1,
        initial_history=60,
        update_existing_data=False,
        dry_run=False,
        ready_path=ready_path,
        batches=[[make_indicator("2099-04-09T10:00:00.000Z")]],
    )

    exit_code = 0
    try:
        connector.run()
    except SystemExit as exit_signal:
        exit_code = int(exit_signal.code or 0)

    Path(result_path).write_text(
        json.dumps(
            {
                "exit_code": exit_code,
                "processed": work_api.processed,
                "state_updates": helper.state_updates,
                "sent_bundles": len(helper.sent_bundles),
                "logged": helper.logged,
            }
        ),
        encoding="utf-8",
    )
    raise SystemExit(exit_code)


class ConnectorWorkTrackingTest(unittest.TestCase):
    def test_run_creates_work_and_forwards_work_id(self):
        work_api = FakeWorkApi(alive_sequence=[True])
        helper = FakeOpenCTIHelper(work_api)
        expected_ts = int(
            main.datetime.strptime(
                "2099-04-09T10:00:00.000Z", "%Y-%m-%dT%H:%M:%S.%fZ"
            )
            .replace(tzinfo=main.timezone.utc)
            .timestamp()
        )
        connector = RunOnceConnector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
            initial_history=60,
            update_existing_data=False,
            dry_run=False,
            batches=[[make_indicator("2099-04-09T10:00:00.000Z")]],
        )

        with self.assertRaises(SystemExit):
            with mock.patch.object(main.sys, "exit", side_effect=SystemExit(0)):
                connector.run()

        self.assertEqual(len(work_api.initiated), 1)
        self.assertEqual(len(work_api.received), 1)
        self.assertEqual(len(work_api.processed), 1)
        self.assertFalse(work_api.processed[0][2])
        self.assertEqual(len(helper.sent_bundles), 1)
        self.assertEqual(helper.sent_bundles[0][1]["work_id"], "work--1")
        self.assertEqual(len(helper.state_updates), 1)
        self.assertEqual(helper.state_updates[0]["last_added"], expected_ts)
        self.assertTrue(helper.force_ping_called)

    def test_run_stops_on_cancel_without_advancing_state(self):
        work_api = FakeWorkApi(alive_sequence=[True, False])
        helper = FakeOpenCTIHelper(work_api)
        connector = RunOnceConnector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
            initial_history=60,
            update_existing_data=False,
            dry_run=False,
            batches=[
                [make_indicator("2026-04-09T10:00:00.000Z")],
                [make_indicator("2026-04-09T10:05:00.000Z")],
            ],
        )

        with self.assertRaises(SystemExit):
            with mock.patch.object(main.sys, "exit", side_effect=SystemExit(0)):
                connector.run()

        self.assertEqual(len(helper.sent_bundles), 1)
        self.assertEqual(helper.state_updates, [])
        self.assertEqual(work_api.processed, [])
        self.assertTrue(
            any("no longer active" in message for message in helper.logged["info"])
        )

    def test_run_without_work_tracking_still_sends_bundle_and_updates_state(self):
        work_api = FakeWorkApi(
            alive_sequence=[True],
            initiate_exception=RuntimeError("work api unavailable"),
        )
        helper = FakeOpenCTIHelper(work_api)
        connector = RunOnceConnector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
            initial_history=60,
            update_existing_data=False,
            dry_run=False,
            batches=[[make_indicator("2099-04-09T10:00:00.000Z")]],
        )

        with self.assertRaises(SystemExit):
            with mock.patch.object(main.sys, "exit", side_effect=SystemExit(0)):
                connector.run()

        self.assertEqual(len(helper.sent_bundles), 1)
        self.assertIsNone(helper.sent_bundles[0][1]["work_id"])
        self.assertEqual(len(helper.state_updates), 1)
        self.assertEqual(work_api.received, [])
        self.assertEqual(work_api.processed, [])
        self.assertTrue(
            any("Unable to initiate OpenCTI work tracking" in message for message in helper.logged["warning"])
        )

    def test_run_marks_work_as_failed_when_send_fails(self):
        work_api = FakeWorkApi(alive_sequence=[True])
        helper = FakeOpenCTIHelper(
            work_api, send_exception=RuntimeError("bundle send failed")
        )
        connector = RunOnceConnector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
            initial_history=60,
            update_existing_data=False,
            dry_run=False,
            batches=[[make_indicator("2099-04-09T10:00:00.000Z")]],
        )

        with self.assertRaises(SystemExit):
            with mock.patch.object(main.sys, "exit", side_effect=SystemExit(0)):
                connector.run()

        self.assertEqual(helper.state_updates, [])
        self.assertEqual(len(work_api.processed), 1)
        self.assertTrue(work_api.processed[0][2])
        self.assertIn("bundle send failed", work_api.processed[0][1])
        self.assertTrue(
            any("bundle send failed" in message for message in helper.logged["error"])
        )

    def test_run_marks_work_as_interrupted_on_graceful_stop(self):
        work_api = FakeWorkApi(alive_sequence=[True, True])
        helper = FakeOpenCTIHelper(work_api)
        connector = SignalBeforeNextBatchConnector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
            initial_history=60,
            update_existing_data=False,
            dry_run=False,
            batches=[
                [make_indicator("2099-04-09T10:00:00.000Z")],
                [make_indicator("2099-04-09T10:05:00.000Z")],
            ],
        )

        with self.assertRaises(SystemExit) as stop_exit:
            connector.run()

        self.assertEqual(stop_exit.exception.code, 0)
        self.assertEqual(len(helper.sent_bundles), 1)
        self.assertEqual(helper.state_updates, [])
        self.assertEqual(len(work_api.processed), 1)
        self.assertTrue(work_api.processed[0][2])
        self.assertIn("interrupted by SIGTERM", work_api.processed[0][1])
        self.assertIn("after queueing 1 objects", work_api.processed[0][1])

    def test_run_graceful_stop_without_work_does_not_finalize_work(self):
        work_api = FakeWorkApi(
            alive_sequence=[True, True],
            initiate_exception=RuntimeError("work api unavailable"),
        )
        helper = FakeOpenCTIHelper(work_api)
        connector = SignalBeforeNextBatchConnector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
            initial_history=60,
            update_existing_data=False,
            dry_run=False,
            batches=[
                [make_indicator("2099-04-09T10:00:00.000Z")],
                [make_indicator("2099-04-09T10:05:00.000Z")],
            ],
        )

        with self.assertRaises(SystemExit) as stop_exit:
            connector.run()

        self.assertEqual(stop_exit.exception.code, 0)
        self.assertEqual(len(helper.sent_bundles), 1)
        self.assertEqual(helper.state_updates, [])
        self.assertEqual(work_api.processed, [])

    def test_graceful_stop_after_completed_run_does_not_finalize_work_twice(self):
        work_api = FakeWorkApi(alive_sequence=[True])
        helper = FakeOpenCTIHelper(work_api)
        helper.connect_run_and_terminate = False
        connector = RunOnceConnector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
            initial_history=60,
            update_existing_data=False,
            dry_run=False,
            batches=[[make_indicator("2099-04-09T10:00:00.000Z")]],
        )

        def interrupt_sleep(_seconds):
            connector._handle_stop_signal(main.signal.SIGTERM, None)

        with self.assertRaises(SystemExit) as stop_exit:
            with mock.patch.object(main.time, "sleep", side_effect=interrupt_sleep):
                connector.run()

        self.assertEqual(stop_exit.exception.code, 0)
        self.assertEqual(len(work_api.processed), 1)
        self.assertFalse(work_api.processed[0][2])
        self.assertTrue(
            any("SIGTERM" in message for message in helper.logged["info"])
        )

    def test_run_in_non_main_thread_skips_signal_handlers(self):
        work_api = FakeWorkApi(alive_sequence=[True])
        helper = FakeOpenCTIHelper(work_api)
        connector = RunOnceConnector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
            initial_history=60,
            update_existing_data=False,
            dry_run=False,
            batches=[[make_indicator("2099-04-09T10:00:00.000Z")]],
        )
        thread_result = {}

        def thread_target():
            try:
                with mock.patch.object(main.sys, "exit", side_effect=SystemExit(0)):
                    connector.run()
            except BaseException as exception:  # pylint: disable=broad-exception-caught
                thread_result["exception"] = exception

        runner = threading.Thread(target=thread_target)
        runner.start()
        runner.join(timeout=10)

        self.assertFalse(runner.is_alive())
        self.assertIsInstance(thread_result.get("exception"), SystemExit)
        self.assertTrue(
            any("main thread" in message for message in helper.logged["warning"])
        )

    def test_run_defers_signal_raised_during_batch_preparation(self):
        work_api = FakeWorkApi(alive_sequence=[True, True])
        helper = FakeOpenCTIHelper(work_api)
        connector = SignalDuringBatchPreparationConnector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
            initial_history=60,
            update_existing_data=False,
            dry_run=False,
            batches=[[make_indicator("2099-04-09T10:00:00.000Z")]],
        )

        with self.assertRaises(SystemExit) as stop_exit:
            connector.run()

        self.assertEqual(stop_exit.exception.code, 0)
        self.assertEqual(len(helper.sent_bundles), 1)
        self.assertEqual(helper.state_updates, [])
        self.assertEqual(len(work_api.processed), 1)
        self.assertTrue(work_api.processed[0][2])
        self.assertIn("after queueing 1 objects", work_api.processed[0][1])

    def test_repeated_signal_during_graceful_stop_is_ignored(self):
        work_api = FakeWorkApi(alive_sequence=[True])
        helper = FakeOpenCTIHelper(work_api)
        connector = main.Connector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
        )
        connector._active_work_id = "work--1"
        connector._shutdown_signal_name = "SIGTERM"

        def repeated_signal_then_continue(_work_id):
            connector._handle_stop_signal(main.signal.SIGINT, None)
            return True

        with mock.patch.object(
            connector, "_is_work_alive", side_effect=repeated_signal_then_continue
        ):
            connector._handle_graceful_stop(main.ConnectorStopRequested("SIGTERM"))

        self.assertEqual(connector._shutdown_signal_name, "SIGTERM")
        self.assertEqual(len(work_api.processed), 1)
        self.assertTrue(work_api.processed[0][2])

    def test_graceful_stop_restores_timeout_and_logs_failures(self):
        work_api = FakeWorkApi(
            alive_exception=RuntimeError("temporary timeout"),
            processed_exception=RuntimeError("completion timeout"),
        )
        helper = FakeOpenCTIHelper(work_api)
        connector = main.Connector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
        )
        connector._active_work_id = "work--1"
        connector._shutdown_signal_name = "SIGTERM"
        helper.api.session_requests_timeout = 300

        connector._handle_graceful_stop(main.ConnectorStopRequested("SIGTERM"))

        self.assertEqual(helper.api.session_requests_timeout, 300)
        self.assertTrue(
            any(
                "Unable to query OpenCTI work liveness" in message
                for message in helper.logged["warning"]
            )
        )
        self.assertTrue(
            any(
                "Unable to finalize OpenCTI work" in message
                for message in helper.logged["warning"]
            )
        )

    def test_subprocess_signal_delivery_gracefully_stops_connector(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            result_path = temp_path / "result.json"
            ready_path = temp_path / "ready"

            process = subprocess.Popen(
                [sys.executable, __file__, "--signal-child", str(result_path), str(ready_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.time() + 15
                while time.time() < deadline and not ready_path.exists():
                    if process.poll() is not None:
                        break
                    time.sleep(0.1)

                child_stdout = ""
                child_stderr = ""
                if not ready_path.exists() and process.poll() is not None:
                    child_stdout, child_stderr = process.communicate(timeout=1)
                self.assertTrue(
                    ready_path.exists(),
                    msg=(
                        "Child process did not reach the batch preparation checkpoint. "
                        f"stdout={child_stdout}\nstderr={child_stderr}"
                    ),
                )

                os.kill(process.pid, signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=20)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

            self.assertEqual(
                process.returncode,
                0,
                msg=f"stdout={stdout}\nstderr={stderr}",
            )
            payload = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["exit_code"], 0)
            self.assertEqual(payload["sent_bundles"], 1)
            self.assertEqual(payload["state_updates"], [])
            self.assertEqual(len(payload["processed"]), 1)
            self.assertTrue(payload["processed"][0][2])
            self.assertIn("interrupted by SIGTERM", payload["processed"][0][1])
            self.assertTrue(
                any(
                    "graceful shutdown" in message.lower()
                    for message in payload["logged"]["info"]
                )
            )

    def test_work_liveness_falls_back_to_non_terminal_work_status(self):
        helper = FakeOpenCTIHelper(
            FakeWorkApiFallback(work_state={"status": "received"})
        )
        connector = main.Connector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
        )
        self.assertTrue(connector._is_work_alive("work--1"))

    def test_work_liveness_falls_back_to_terminal_work_status(self):
        helper = FakeOpenCTIHelper(
            FakeWorkApiFallback(work_state={"status": "complete"})
        )
        connector = main.Connector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
        )
        self.assertFalse(connector._is_work_alive("work--1"))

    def test_work_liveness_missing_work_is_treated_as_stopped(self):
        helper_missing = FakeOpenCTIHelper(
            FakeWorkApiFallback(work_exception=RuntimeError("Work not found"))
        )
        connector_missing = main.Connector(
            opencti_api=helper_missing,
            stix_source=FakeStixSource(),
            update_interval=1,
        )
        self.assertFalse(connector_missing._is_work_alive("work--1"))
        self.assertTrue(
            any(
                "no longer available" in message
                for message in helper_missing.logged["info"]
            )
        )

    def test_work_liveness_errors_degrade_to_alive(self):
        helper = FakeOpenCTIHelper(
            FakeWorkApi(alive_exception=RuntimeError("temporary work api failure"))
        )
        connector = main.Connector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
        )

        self.assertTrue(connector._is_work_alive("work--1"))
        self.assertTrue(
            any(
                "Unable to query OpenCTI work liveness" in message
                for message in helper.logged["warning"]
            )
        )

    def test_work_liveness_fallback_errors_degrade_to_alive(self):
        helper = FakeOpenCTIHelper(
            FakeWorkApiFallback(
                work_exception=RuntimeError("temporary work api failure")
            )
        )
        connector = main.Connector(
            opencti_api=helper,
            stix_source=FakeStixSource(),
            update_interval=1,
        )

        self.assertTrue(connector._is_work_alive("work--1"))
        self.assertTrue(
            any(
                "Unable to query OpenCTI work liveness" in message
                for message in helper.logged["warning"]
            )
        )


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--signal-child":
        _run_signal_delivery_child(sys.argv[2], sys.argv[3])
    unittest.main()
