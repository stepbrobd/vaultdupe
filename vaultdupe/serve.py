"""Bulk operations via `bw serve`, the CLI's local REST API.

Spawning bw once and issuing HTTP calls avoids the roughly one second of
Node startup per deletion, which is the difference between about an hour
and a few minutes for thousands of items. DELETE /object/item/{id} has the
same soft-delete semantics as `bw delete item`. The server binds 127.0.0.1
on an ephemeral port and lives only for the duration of the operation.
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
import urllib.error
import urllib.request
from contextlib import contextmanager

from .bw import BwError


class BwServeClient:
    """HTTP half of the serve integration, testable against any stub server."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def _request(self, method: str, path: str, timeout: float = 30):
        req = urllib.request.Request(self.base_url + path, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")[:200]
            raise BwError(f"bw serve {method} {path} -> HTTP {e.code}: {body}")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            raise BwError(f"bw serve unreachable ({method} {path}): {e}")

    def delete_item(self, item_id: str) -> None:
        payload = self._request("DELETE", f"/object/item/{item_id}")
        if payload.get("success") is False:
            raise BwError(f"delete {item_id} refused: {payload.get('message')}")

    def status(self) -> str:
        payload = self._request("GET", "/status")
        try:
            return payload["data"]["template"]["status"]
        except (KeyError, TypeError):
            raise BwError(f"unexpected bw serve status payload: {str(payload)[:200]}")

    def wait_ready(self, timeout: float = 30) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self.status()
                return
            except BwError:
                time.sleep(0.25)
        raise BwError(f"bw serve did not become ready within {timeout}s")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def bw_serve():
    """Run `bw serve` for the duration of the context. Yields a BwServeClient."""
    port = _free_port()
    proc = subprocess.Popen(
        ["bw", "serve", "--hostname", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    client = BwServeClient(f"http://127.0.0.1:{port}")
    try:
        client.wait_ready()
        state = client.status()
        if state != "unlocked":
            raise BwError(
                f"bw serve reports vault '{state}'. Export BW_SESSION and retry."
            )
        yield client
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
