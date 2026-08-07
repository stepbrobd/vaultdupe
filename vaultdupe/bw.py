"""Thin wrapper around the Bitwarden CLI.

Raw `bw list items` output exists only in process memory. It is parsed,
sanitized, and discarded, never written to disk. Deletes are always soft
(`bw delete item` without --permanent), so deleted items stay recoverable
in the web vault trash.
"""

from __future__ import annotations

import json
import subprocess


class BwError(RuntimeError):
    pass


def _norm_url(url: str | None) -> str:
    return (url or "").strip().rstrip("/").lower()


def assess_status(status: dict, expected_server: str | None = None) -> str | None:
    """Pure check of `bw status` output.

    Returns an actionable error message, or None when bw is unlocked and,
    when expected_server is given, pointed at that server.
    """
    server = _norm_url(status.get("serverUrl"))
    expected = _norm_url(expected_server)
    if expected and server and server != expected:
        return (
            f"bw is pointed at {status.get('serverUrl')}, expected {expected_server}.\n"
            f"Fix:  bw logout; bw config server {expected_server}; bw login"
        )
    state = status.get("status")
    if state == "unauthenticated":
        hint = expected_server or "<your-server-url>"
        return (
            "Not logged in. Run:\n"
            f"  bw config server {hint}\n"
            "  bw login\n"
            '  export BW_SESSION="$(bw unlock --raw)"'
        )
    if state != "unlocked":
        return 'Vault is locked. Run:  export BW_SESSION="$(bw unlock --raw)"  and retry.'
    return None


def filter_deletions(deletions: list, current_revisions: dict) -> tuple[list, list]:
    """Partition planned deletions against the current vault state.

    Anything edited or removed since the plan was generated is skipped,
    never deleted.
    """
    todo, skipped = [], []
    for d in deletions:
        rev = current_revisions.get(d["id"])
        if rev is None:
            skipped.append({**d, "skip_reason": "not found in vault (already deleted?)"})
        elif rev != d["revision"]:
            skipped.append({**d, "skip_reason": f"changed since plan ({d['revision']} -> {rev})"})
        else:
            todo.append(d)
    return todo, skipped


# subprocess layer, kept trivially thin and not unit tested

def run_bw(args: list, timeout: int = 300) -> str:
    try:
        proc = subprocess.run(
            ["bw", "--nointeraction", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise BwError("bw CLI not found, run inside nix-shell (see shell.nix)")
    if proc.returncode != 0:
        raise BwError(f"bw {' '.join(args[:2])} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout


def bw_status() -> dict:
    return json.loads(run_bw(["status"]))


def sync() -> None:
    run_bw(["sync"])


def list_items_raw() -> list:
    # full decrypted items, memory only
    # callers must sanitize and drop the reference
    return json.loads(run_bw(["list", "items"]))


def list_folders() -> dict:
    return {f["id"]: f["name"] for f in json.loads(run_bw(["list", "folders"])) if f.get("id")}


def delete_item(item_id: str) -> None:
    # soft delete, item moves to trash
    run_bw(["delete", "item", item_id])
