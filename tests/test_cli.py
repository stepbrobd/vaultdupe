"""Tests for the pure decision logic behind the CLI.

Covers status assessment, revision freshness filtering, key and dataset
storage, and the argument parser. Subprocess calls to bw are thin wrappers
and are not unit tested.
"""

import os

from vaultdupe.bw import assess_status, filter_deletions
from vaultdupe.cli import build_parser
from vaultdupe.sanitize import Hasher, SanitizedItem
from vaultdupe.store import (
    ensure_key,
    load_dataset,
    load_plan,
    save_dataset,
    save_plan,
    shred_work,
)

SERVER = "https://vault.example.com"


class TestAssessStatus:
    def test_unlocked_matching_server_is_ok(self):
        assert assess_status({"serverUrl": SERVER, "status": "unlocked"}, SERVER) is None

    def test_trailing_slash_is_ignored(self):
        assert assess_status({"serverUrl": SERVER + "/", "status": "unlocked"}, SERVER) is None

    def test_no_expected_server_skips_url_check(self):
        assert assess_status({"serverUrl": "https://other.example", "status": "unlocked"}) is None

    def test_no_expected_server_still_requires_unlocked(self):
        msg = assess_status({"serverUrl": SERVER, "status": "locked"})
        assert "bw unlock" in msg

    def test_locked_tells_user_to_unlock(self):
        msg = assess_status({"serverUrl": SERVER, "status": "locked"}, SERVER)
        assert "bw unlock" in msg and "BW_SESSION" in msg

    def test_unauthenticated_tells_user_to_login(self):
        msg = assess_status({"serverUrl": None, "status": "unauthenticated"})
        assert "bw login" in msg

    def test_wrong_server_names_expected_url(self):
        msg = assess_status(
            {"serverUrl": "https://bitwarden.com", "status": "unlocked"}, SERVER
        )
        assert SERVER in msg and "bw config server" in msg


class TestFilterDeletions:
    PLAN = [
        {"id": "a", "name": "A", "revision": "2025-01-01T00:00:00.000Z"},
        {"id": "b", "name": "B", "revision": "2025-01-01T00:00:00.000Z"},
        {"id": "c", "name": "C", "revision": "2025-01-01T00:00:00.000Z"},
    ]

    def test_partitions_by_current_vault_state(self):
        current = {
            "a": "2025-01-01T00:00:00.000Z",  # unchanged, delete
            "b": "2025-06-06T06:06:06.000Z",  # edited since plan, skip
            # c missing entirely, skip
        }
        todo, skipped = filter_deletions(self.PLAN, current)
        assert [d["id"] for d in todo] == ["a"]
        reasons = {s["id"]: s["skip_reason"] for s in skipped}
        assert "changed" in reasons["b"]
        assert "found" in reasons["c"] or "missing" in reasons["c"]


class TestStore:
    def test_ensure_key_creates_0600_32_bytes_and_is_stable(self, tmp_path):
        work = tmp_path / "work"
        k1 = ensure_key(work)
        k2 = ensure_key(work)
        assert k1 == k2 and len(k1) == 32
        key_file = work / ".hmac-key"
        assert (os.stat(key_file).st_mode & 0o777) == 0o600
        assert (os.stat(work).st_mode & 0o777) == 0o700

    def test_dataset_round_trip(self, tmp_path):
        h = Hasher(b"\x01" * 32)
        items = [SanitizedItem(id="x", type="login", name="N", revision="r",
                               password_digest=h.digest("password", "pw"))]
        p = tmp_path / "vault.json"
        save_dataset(p, items, meta={"server": SERVER, "folders": {"f1": "Work"}})
        data = load_dataset(p)
        assert data["meta"]["server"] == SERVER
        assert data["items"][0] == items[0]

    def test_plan_round_trip(self, tmp_path):
        p = tmp_path / "plan.json"
        save_plan(p, deletions=[{"id": "a"}], stats={"deletions": 1},
                  meta={"server": SERVER})
        plan = load_plan(p)
        assert plan["deletions"] == [{"id": "a"}]
        assert plan["stats"]["deletions"] == 1

    def test_shred_removes_work_dir_contents(self, tmp_path):
        work = tmp_path / "work"
        ensure_key(work)
        (work / "vault.json").write_text('{"secret-adjacent": true}')
        shredded = shred_work(work)
        assert not work.exists()
        assert shredded >= 2


class TestParser:
    def test_subcommands_and_no_baked_in_server(self):
        p = build_parser()
        ns = p.parse_args(["fetch"])
        assert ns.cmd == "fetch"
        assert ns.server is None
        ns = p.parse_args(["fetch", "--server", SERVER])
        assert ns.server == SERVER
        ns = p.parse_args(["diff-apple", "export.csv", "--shred-csv"])
        assert ns.cmd == "diff-apple"
        assert ns.csv == "export.csv"
        assert ns.shred_csv is True
        ns = p.parse_args(["apply", "--yes"])
        assert ns.yes is True
        ns = p.parse_args(["export-apple", "--no-notes"])
        assert ns.cmd == "export-apple"
        assert ns.no_notes is True
        assert ns.server is None
