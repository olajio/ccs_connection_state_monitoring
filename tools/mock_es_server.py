#!/usr/bin/env python3
"""
mock_es_server.py — a tiny stand-in Elasticsearch for testing the collector.

It serves just enough of the API surface this project uses so that the whole
pipeline — probe, evaluate, index, verify — can be exercised end to end without
touching a real cluster. Use it to rehearse the runbook, to demo an induced
failure, and in CI.

Implemented endpoints:
    GET  /                        cluster info banner
    GET  /_remote/info            the scenario's remote state
    POST /<target>/_bulk          accepts documents, keeps them in memory
    PUT  /_index_template/<name>  accepted and recorded
    PUT  /_ilm/policy/<name>      accepted and recorded
    PUT  /_data_stream/<name>     create a data stream
    GET  /_data_stream/<name>     describe it (404 when absent)
    PUT  /<index>                 create a plain index
    GET  /<index>                 describe it (404 when absent)
    PUT  /_security/role/<name>   accepted and recorded
    GET  /_mock/docs              everything written so far (test helper)
    GET  /_mock/state             templates/policies/roles recorded (test helper)
    DELETE /_mock/docs            reset the captured documents (test helper)

Scenario file: a JSON object mapping a scenario name to a `_remote/info` body,
plus optional per-scenario failure injection. See tools/scenarios.json.

Usage:
    python3 tools/mock_es_server.py --port 9250 --scenario healthy
    python3 tools/mock_es_server.py --port 9250 --scenario prod_remote_down \
        --scenarios tools/scenarios.json
    python3 tools/mock_es_server.py --port 9250 --fail-with 503   # unreachable-cluster drill
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List

DEFAULT_SCENARIOS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scenarios.json")

STATE_LOCK = threading.Lock()
STATE: Dict[str, Any] = {
    "remote_info": {},
    "documents": [],
    "index_templates": {},
    "ilm_policies": {},
    "data_streams": {},
    "indices": {},
    "roles": {},
    "fail_with": None,
    "require_auth": True,
}


class MockESHandler(BaseHTTPRequestHandler):
    server_version = "MockElasticsearch/8.14.0"

    # -- plumbing ---------------------------------------------------------- #

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("MOCK_ES_VERBOSE"):
            sys.stderr.write("[mock-es] " + (fmt % args) + "\n")

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _authorized(self) -> bool:
        with STATE_LOCK:
            if not STATE["require_auth"]:
                return True
        header = self.headers.get("Authorization", "")
        return header.startswith(("ApiKey ", "Basic "))

    def _guard(self) -> bool:
        """Apply injected failures and auth. Returns True when the request may proceed."""
        with STATE_LOCK:
            fail_with = STATE["fail_with"]
        if fail_with:
            self._send(int(fail_with), {"error": {"type": "injected_failure", "reason": "mock failure"}})
            return False
        if not self._authorized():
            self._send(401, {"error": {"type": "security_exception", "reason": "missing credentials"}})
            return False
        return True

    # -- routes ------------------------------------------------------------ #

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?")[0].rstrip("/") or "/"

        if path == "/_mock/docs":  # test helper: never guarded
            with STATE_LOCK:
                self._send(200, {"count": len(STATE["documents"]), "documents": STATE["documents"]})
            return
        if path == "/_mock/state":
            with STATE_LOCK:
                self._send(200, {
                    "index_templates": list(STATE["index_templates"]),
                    "ilm_policies": list(STATE["ilm_policies"]),
                    "data_streams": list(STATE["data_streams"]),
                    "indices": list(STATE["indices"]),
                    "roles": list(STATE["roles"]),
                    "documents": len(STATE["documents"]),
                })
            return

        if not self._guard():
            return

        if path == "/":
            self._send(200, {
                "name": "mock-node-1",
                "cluster_name": "mock-cluster",
                "version": {"number": "8.14.0"},
                "tagline": "You Know, for Testing",
            })
            return

        if path == "/_remote/info":
            with STATE_LOCK:
                self._send(200, dict(STATE["remote_info"]))
            return

        if path.startswith("/_data_stream/"):
            name = path[len("/_data_stream/"):]
            with STATE_LOCK:
                stream = STATE["data_streams"].get(name)
            if not stream:
                self._send(404, {"error": {"type": "index_not_found_exception", "reason": name}})
                return
            self._send(200, {"data_streams": [stream]})
            return

        if path.startswith("/_index_template/"):
            name = path[len("/_index_template/"):]
            with STATE_LOCK:
                template = STATE["index_templates"].get(name)
            if template is None:
                self._send(404, {"error": {"type": "resource_not_found_exception", "reason": name}})
                return
            self._send(200, {"index_templates": [{"name": name, "index_template": template}]})
            return

        if path.startswith("/_ilm/policy/"):
            name = path[len("/_ilm/policy/"):]
            with STATE_LOCK:
                policy = STATE["ilm_policies"].get(name)
            if policy is None:
                self._send(404, {"error": {"type": "resource_not_found_exception", "reason": name}})
                return
            self._send(200, {name: {"policy": policy}})
            return

        # Treat anything else as an index / alias lookup.
        name = path.lstrip("/")
        with STATE_LOCK:
            index = STATE["indices"].get(name)
            if index is None:
                # A write alias resolves to its backing index.
                for index_name, meta in STATE["indices"].items():
                    if name in (meta.get("aliases") or {}):
                        self._send(200, {index_name: meta})
                        return
        if index is None:
            self._send(404, {"error": {"type": "index_not_found_exception", "reason": name}})
            return
        self._send(200, {name: index})

    def do_PUT(self) -> None:  # noqa: N802
        if not self._guard():
            return
        path = self.path.split("?")[0].rstrip("/")
        raw = self._read_body()
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            self._send(400, {"error": {"type": "parse_exception", "reason": "invalid JSON body"}})
            return

        with STATE_LOCK:
            if path.startswith("/_index_template/"):
                STATE["index_templates"][path[len("/_index_template/"):]] = payload
            elif path.startswith("/_ilm/policy/"):
                STATE["ilm_policies"][path[len("/_ilm/policy/"):]] = payload.get("policy", payload)
            elif path.startswith("/_data_stream/"):
                name = path[len("/_data_stream/"):]
                if name in STATE["data_streams"]:
                    # Match Elasticsearch: re-creating a data stream is a 400.
                    self._send(400, {"error": {
                        "type": "resource_already_exists_exception",
                        "reason": f"data_stream [{name}] already exists",
                    }})
                    return
                STATE["data_streams"][name] = {
                    "name": name,
                    "indices": [{"index_name": f".ds-{name}-000001"}],
                    "lifecycle": {"data_retention": "90d", "enabled": True},
                }
            elif path.startswith("/_security/role/"):
                STATE["roles"][path[len("/_security/role/"):]] = payload
            else:
                name = path.lstrip("/")
                if name in STATE["indices"]:
                    self._send(400, {"error": {
                        "type": "resource_already_exists_exception",
                        "reason": f"index [{name}] already exists",
                    }})
                    return
                STATE["indices"][name] = {
                    "aliases": payload.get("aliases", {}),
                    "mappings": payload.get("mappings", {}),
                    "settings": payload.get("settings", {}),
                }
        self._send(200, {"acknowledged": True})

    def do_POST(self) -> None:  # noqa: N802
        if not self._guard():
            return
        path = self.path.split("?")[0].rstrip("/")
        raw = self._read_body().decode("utf-8")

        if path.endswith("/_bulk") or path == "/_bulk":
            target = path[1:-len("/_bulk")] if path != "/_bulk" else None
            items: List[Dict[str, Any]] = []
            stored: List[Dict[str, Any]] = []
            lines = [line for line in raw.split("\n") if line.strip()]
            action_name = "index"
            for i, line in enumerate(lines):
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    self._send(400, {"error": {"type": "parse_exception", "reason": f"line {i}"}})
                    return
                if i % 2 == 0:
                    action_name = next(iter(parsed), "index")
                    continue
                stored.append({"_target": target, "_action": action_name, "_source": parsed})
                items.append({action_name: {
                    "_index": target or "unknown",
                    "_id": f"mock-{i}",
                    "result": "created",
                    "status": 201,
                }})

            with STATE_LOCK:
                STATE["documents"].extend(stored)
            self._send(200, {"took": 3, "errors": False, "items": items})
            return

        if path == "/_security/api_key":
            self._send(200, {
                "id": "mock_api_key_id",
                "name": "mock",
                "api_key": "mock_api_key_secret",
                "encoded": "bW9ja19hcGlfa2V5X2lkOm1vY2tfYXBpX2tleV9zZWNyZXQ=",
            })
            return

        self._send(404, {"error": {"type": "not_found", "reason": path}})

    def do_DELETE(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/_mock/docs":
            with STATE_LOCK:
                STATE["documents"] = []
            self._send(200, {"acknowledged": True})
            return
        self._send(404, {"error": {"type": "not_found", "reason": self.path}})


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #

def load_scenarios(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def apply_scenario(scenarios: Dict[str, Any], name: str) -> None:
    if name not in scenarios:
        available = ", ".join(k for k in scenarios if not k.startswith("_"))
        raise SystemExit(f"Unknown scenario '{name}'. Available: {available}")
    scenario = scenarios[name]
    with STATE_LOCK:
        STATE["remote_info"] = scenario.get("remote_info", {})
        STATE["fail_with"] = scenario.get("fail_with")


def serve(host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), MockESHandler)
    return server


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Mock Elasticsearch for CCS collector testing.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9250)
    parser.add_argument("--scenarios", default=DEFAULT_SCENARIOS_PATH)
    parser.add_argument("--scenario", default="healthy")
    parser.add_argument("--fail-with", type=int, default=None,
                        help="Return this HTTP status for every request (unreachable-cluster drill).")
    parser.add_argument("--no-auth", action="store_true",
                        help="Accept unauthenticated requests (default: require an Authorization header).")
    args = parser.parse_args(argv)

    scenarios = load_scenarios(args.scenarios)
    apply_scenario(scenarios, args.scenario)
    with STATE_LOCK:
        STATE["require_auth"] = not args.no_auth
        if args.fail_with:
            STATE["fail_with"] = args.fail_with

    server = serve(args.host, args.port)
    sys.stderr.write(
        f"[mock-es] scenario '{args.scenario}' on http://{args.host}:{args.port} "
        f"(Ctrl-C to stop)\n"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[mock-es] stopped\n")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
