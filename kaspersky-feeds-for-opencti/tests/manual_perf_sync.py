#!/usr/bin/env python3
"""Manual performance benchmark for TAXII synchronization."""

import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, Iterable, List
from urllib.error import URLError
from urllib.parse import urlsplit, urlunsplit, urlencode
from urllib.request import urlopen
from unittest import mock

from taxii2client.v21 import ApiRoot, Server

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pycti import OpenCTIConnectorHelper

import main
from kaspersky import Stix21Transformer, Taxii21Client
from kaspersky.taxii_client import Taxii21Connection


DEFAULT_TAXII_API_ROOT = "https://taxii.tip.kaspersky.com/taxii2"
DEFAULT_OPENCTI_COMPOSE_DIR = "./opencti-6.4.11-local"
DEFAULT_TAXII_COLLECTION = "TAXII_Demo_IP_Reputation_Data_Feed"
DEFAULT_TIMEOUT = 60
DEFAULT_INITIAL_HISTORY = 604800
DEFAULT_PERF_MODES = ("overwrite", "skip", "create_only")


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


def _resolve_perf_modes() -> List[str]:
    raw_value = os.getenv("PERF_MODES")
    if raw_value is None or raw_value.strip() == "":
        return list(DEFAULT_PERF_MODES)

    modes = [mode.strip() for mode in raw_value.split(",") if mode.strip()]
    invalid_modes = [mode for mode in modes if mode not in DEFAULT_PERF_MODES]
    if invalid_modes:
        raise RuntimeError(
            "Unsupported PERF_MODES values: "
            + ", ".join(invalid_modes)
            + f". Supported values: {', '.join(DEFAULT_PERF_MODES)}"
        )
    return modes


def _load_env_file(path: Path) -> Dict[str, str]:
    if not path.is_file():
        raise RuntimeError(f"Unable to find env file at {path}")

    result = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def _run_compose(compose_dir: Path, *args: str) -> None:
    subprocess.run(
        ["docker", "compose", *args],
        cwd=str(compose_dir),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


def _wait_for_opencti(url: str, healthcheck_access_key: str, timeout_sec: int = 600) -> None:
    params = {}
    if healthcheck_access_key:
        params["health_access_key"] = healthcheck_access_key
    health_url = f"{url.rstrip('/')}/health"
    if params:
        health_url = f"{health_url}?{urlencode(params)}"

    deadline = time.time() + timeout_sec
    last_error = "OpenCTI health check did not return success"
    while time.time() < deadline:
        try:
            with urlopen(health_url, timeout=15) as response:
                payload = response.read().decode("utf-8")
                if response.status == 200:
                    if not payload:
                        return
                    parsed = json.loads(payload)
                    if parsed.get("status") in ("ok", "success"):
                        return
                    if parsed.get("alive") is True:
                        return
                    if "status" not in parsed and "alive" not in parsed:
                        return
        except (URLError, OSError, json.JSONDecodeError) as exception:
            last_error = str(exception)
        time.sleep(5)

    raise RuntimeError(f"Timed out waiting for OpenCTI at {url}: {last_error}")


def _resolve_opencti_spec() -> Dict[str, str]:
    opencti_url = os.getenv("PERF_OPENCTI_URL")
    opencti_token = os.getenv("PERF_OPENCTI_TOKEN")
    if opencti_url and opencti_token:
        return {
            "url": opencti_url.rstrip("/"),
            "token": opencti_token,
            "compose_dir": None,
            "healthcheck_access_key": "",
            "manage": False,
        }

    compose_dir = Path(
        os.getenv("PERF_OPENCTI_COMPOSE_DIR", DEFAULT_OPENCTI_COMPOSE_DIR)
    )
    env_data = _load_env_file(compose_dir / ".env")
    port = env_data.get("OPENCTI_PORT", "8080")

    return {
        "url": f"http://localhost:{port}",
        "token": env_data["OPENCTI_ADMIN_TOKEN"],
        "compose_dir": str(compose_dir),
        "healthcheck_access_key": env_data.get("OPENCTI_HEALTHCHECK_ACCESS_KEY", ""),
        "manage": _env_bool("PERF_MANAGE_OPENCTI", True),
    }


def _ensure_opencti_ready(opencti_spec: Dict[str, str], reset_state: bool) -> None:
    compose_dir = opencti_spec.get("compose_dir")
    if compose_dir is None:
        _wait_for_opencti(
            url=opencti_spec["url"],
            healthcheck_access_key=opencti_spec["healthcheck_access_key"],
        )
        return

    if reset_state and opencti_spec["manage"]:
        print("Resetting local OpenCTI Docker stack...", file=sys.stderr)
        _run_compose(Path(compose_dir), "down", "-v")
        _run_compose(Path(compose_dir), "up", "-d")
    elif opencti_spec["manage"]:
        _run_compose(Path(compose_dir), "up", "-d")

    _wait_for_opencti(
        url=opencti_spec["url"],
        healthcheck_access_key=opencti_spec["healthcheck_access_key"],
    )


def _build_taxii_connection(api_token: str, ssl_verify: bool, timeout: int) -> Taxii21Connection:
    return Taxii21Connection(
        user="taxii",
        password=api_token,
        ssl_verify=ssl_verify,
        timeout=timeout,
    )


def _resolve_taxii_api_root(
    discovery_or_api_root: str, api_token: str, ssl_verify: bool, timeout: int
) -> ApiRoot:
    connection = _build_taxii_connection(api_token, ssl_verify, timeout)
    try:
        api_root = ApiRoot(url=discovery_or_api_root, conn=connection)
        api_root.refresh()
        return api_root
    except Exception:
        direct_v2_url = _derive_v2_api_root(discovery_or_api_root)
        if direct_v2_url is not None:
            api_root = ApiRoot(url=direct_v2_url, conn=connection)
            api_root.refresh()
            return api_root

        server = Server(url=discovery_or_api_root, conn=connection)
        server.refresh()

        api_roots = getattr(server, "api_roots", [])
        if isinstance(api_roots, dict):
            candidates = list(api_roots.values())
        else:
            candidates = list(api_roots)

        api_root = getattr(server, "default", None)
        if api_root is None:
            if not candidates:
                raise RuntimeError(
                    f"Unable to resolve TAXII API Root from {discovery_or_api_root}"
                )
            api_root = candidates[0]

        api_root.refresh()
        return api_root


def _derive_v2_api_root(discovery_url: str) -> str:
    parsed_url = urlsplit(discovery_url.rstrip("/"))
    if not parsed_url.path.endswith("/taxii2"):
        return None

    new_path = parsed_url.path[: -len("/taxii2")] + "/v2"
    return urlunsplit(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            new_path,
            parsed_url.query,
            parsed_url.fragment,
        )
    )


def _filter_readable_collections(collections: Iterable) -> List:
    return sorted(
        [
            collection
            for collection in collections
            if getattr(collection, "can_read", True)
        ],
        key=lambda collection: (collection.title or collection.id, collection.id),
    )


def _select_collection(api_root: ApiRoot, requested_collection: str = None):
    readable_collections = _filter_readable_collections(api_root.collections)
    if not readable_collections:
        raise RuntimeError("No readable TAXII collections are available")

    if requested_collection:
        for collection in readable_collections:
            if collection.id == requested_collection or collection.title == requested_collection:
                return collection
        raise RuntimeError(
            f"Unable to find readable TAXII collection '{requested_collection}'"
        )

    for collection in readable_collections:
        if collection.title == DEFAULT_TAXII_COLLECTION:
            return collection

    for collection in readable_collections:
        if (collection.title or "").endswith("_Data_Feed"):
            return collection

    return readable_collections[0]


def _build_helper_config(
    mode: str,
    opencti_spec: Dict[str, str],
    taxii_api_root: str,
    taxii_token: str,
    collection_name: str,
    initial_history: int,
) -> Dict:
    return {
        "opencti": {
            "url": opencti_spec["url"],
            "token": opencti_spec["token"],
            "ssl_verify": True,
        },
        "connector": {
            "id": str(uuid.uuid4()),
            "type": "EXTERNAL_IMPORT",
            "name": f"Kaspersky Feeds Perf {mode}",
            "scope": "kaspersky",
            "queue_protocol": os.getenv("PERF_QUEUE_PROTOCOL", "api"),
            "confidence_level": 100,
            "threat_score_from_description": False,
            "threat_score": 100,
            "threat_score_high": 75,
            "threat_score_medium": 50,
            "label_format": "legacy",
            "description_mode": mode,
            "log_level": "info",
            "update_existing_data": False,
            "run_and_terminate": True,
        },
        "kaspersky": {
            "api_root": taxii_api_root,
            "connection_timeout": DEFAULT_TIMEOUT,
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


def _run_single_mode(
    mode: str,
    opencti_spec: Dict[str, str],
    taxii_api_root: str,
    taxii_token: str,
    collection_name: str,
    initial_history: int,
) -> Dict:
    exit_code = 0
    config = _build_helper_config(
        mode=mode,
        opencti_spec=opencti_spec,
        taxii_api_root=taxii_api_root,
        taxii_token=taxii_token,
        collection_name=collection_name,
        initial_history=initial_history,
    )
    helper = OpenCTIConnectorHelper(config=config)
    taxii_client = Taxii21Client(
        api_root=taxii_api_root,
        api_token=taxii_token,
        ssl_verify=True,
        collections=[collection_name],
        timeout=DEFAULT_TIMEOUT,
        logger=helper,
        label_format="legacy",
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
        update_existing_data=False,
        dry_run=False,
        label_format="legacy",
        description_mode=mode,
    )

    try:
        with mock.patch.object(main.sys, "exit", side_effect=SystemExit(0)):
            try:
                connector.run()
            except SystemExit as exit_signal:
                exit_code = int(exit_signal.code or 0)

        result = connector.get_last_run_metrics()
        result["exit_code"] = exit_code
        return result
    finally:
        del helper


def main_cli() -> int:
    taxii_token = os.getenv("PERF_TAXII_API_TOKEN")
    if not taxii_token:
        raise RuntimeError("PERF_TAXII_API_TOKEN environment variable is required")

    taxii_entrypoint = os.getenv("PERF_TAXII_API_ROOT", DEFAULT_TAXII_API_ROOT)
    requested_collection = os.getenv("PERF_COLLECTION")
    perf_modes = _resolve_perf_modes()
    initial_history = _env_int("PERF_INITIAL_HISTORY", DEFAULT_INITIAL_HISTORY)
    opencti_spec = _resolve_opencti_spec()

    api_root = _resolve_taxii_api_root(
        discovery_or_api_root=taxii_entrypoint,
        api_token=taxii_token,
        ssl_verify=True,
        timeout=DEFAULT_TIMEOUT,
    )
    selected_collection = _select_collection(api_root, requested_collection)
    collection_name = selected_collection.title or selected_collection.id

    results = {
        "taxii_input": taxii_entrypoint,
        "resolved_taxii_api_root": api_root.url,
        "collection": {
            "id": selected_collection.id,
            "title": selected_collection.title,
        },
        "opencti_url": opencti_spec["url"],
        "modes": {},
    }

    results["initial_history"] = initial_history

    for mode in perf_modes:
        print(f"Running manual perf benchmark for mode={mode}...", file=sys.stderr)
        _ensure_opencti_ready(opencti_spec, reset_state=True)
        results["modes"][mode] = _run_single_mode(
            mode=mode,
            opencti_spec=opencti_spec,
            taxii_api_root=api_root.url,
            taxii_token=taxii_token,
            collection_name=collection_name,
            initial_history=initial_history,
        )
        print(
            "Completed mode="
            f"{mode} objects={results['modes'][mode]['objects_total']} "
            f"lookups={results['modes'][mode]['existence_lookup_calls']} "
            f"wall={results['modes'][mode]['sync_wall_time_sec']:.2f}s",
            file=sys.stderr,
        )

    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main_cli())
