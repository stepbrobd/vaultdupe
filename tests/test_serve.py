"""Tests for vaultdupe.serve, the bw serve HTTP client.

Exercised against a real local stub HTTP server, no mocks of our own code.
"""

import http.server
import json
import threading

import pytest

from vaultdupe.bw import BwError
from vaultdupe.serve import BwServeClient


class StubHandler(http.server.BaseHTTPRequestHandler):
    deleted: list = []
    fail_ids: set = set()
    status_payloads: list = []  # queue of (code, body) for /status

    def log_message(self, *a):  # keep test output pristine
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/status":
            if StubHandler.status_payloads:
                code, obj = StubHandler.status_payloads.pop(0)
            else:
                code, obj = 200, {
                    "success": True,
                    "data": {"template": {"status": "unlocked"}},
                }
            self._send(code, obj)
        else:
            self._send(404, {"success": False})

    def do_DELETE(self):
        item_id = self.path.rsplit("/", 1)[-1]
        if item_id in StubHandler.fail_ids:
            self._send(400, {"success": False, "message": "Not found."})
        else:
            StubHandler.deleted.append(item_id)
            self._send(200, {"success": True})


@pytest.fixture
def stub():
    StubHandler.deleted = []
    StubHandler.fail_ids = set()
    StubHandler.status_payloads = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), StubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


class TestBwServeClient:
    def test_delete_item_hits_object_item_endpoint(self, stub):
        client = BwServeClient(stub)
        client.delete_item("abc-123")
        assert StubHandler.deleted == ["abc-123"]

    def test_failed_delete_raises_bwerror_with_message(self, stub):
        client = BwServeClient(stub)
        StubHandler.fail_ids = {"bad-id"}
        with pytest.raises(BwError, match="bad-id"):
            client.delete_item("bad-id")

    def test_status_returns_vault_state(self, stub):
        assert BwServeClient(stub).status() == "unlocked"

    def test_wait_ready_retries_until_server_responds(self, stub):
        StubHandler.status_payloads = [
            (500, {"success": False}),
            (500, {"success": False}),
        ]
        client = BwServeClient(stub)
        client.wait_ready(timeout=5)  # two failures, then the default 200

    def test_wait_ready_times_out(self):
        client = BwServeClient("http://127.0.0.1:1")  # nothing listens here
        with pytest.raises(BwError, match="did not become ready"):
            client.wait_ready(timeout=0.5)
