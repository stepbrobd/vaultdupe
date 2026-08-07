"""Command line interface: fetch, dedupe, apply, diff-apple, export-apple, shred."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import bw, serve
from .apple import read_apple_csv
from .apple_export import export_rows, render_apple_csv
from .dedupe import plan_dedupe
from .diff import diff_vault_vs_apple
from .report import render_dedupe_report, render_diff_report
from .sanitize import Hasher, sanitize_vault
from .store import (
    ensure_key,
    load_dataset,
    load_plan,
    save_dataset,
    save_plan,
    shred_file,
    shred_work,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _die(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(2)


def _ready(expected: str | None = None) -> str:
    """Verify bw is unlocked and return the server URL in effect.

    When expected is None the server configured in bw is adopted, so the
    tool carries no baked-in server address.
    """
    status = bw.bw_status()
    err = bw.assess_status(status, expected)
    if err:
        _die(err)
    server = (expected or status.get("serverUrl") or "").rstrip("/")
    if not server:
        _die("bw has no configured server. Run: bw config server <url>")
    return server


def _load_vault(work: Path) -> dict:
    path = work / "vault.json"
    if not path.exists():
        _die("No vault snapshot found. Run `fetch` first.")
    return load_dataset(path)


def cmd_fetch(ns) -> None:
    work = Path(ns.work)
    hasher = Hasher(ensure_key(work))
    server = _ready(ns.server)
    print(f"Syncing with {server} ...")
    bw.sync()
    raw = bw.list_items_raw()  # plaintext, memory only
    items = sanitize_vault(raw, hasher)
    folders = bw.list_folders()
    del raw
    save_dataset(
        work / "vault.json",
        items,
        meta={"server": server, "fetched_at": _now(), "folders": folders},
    )
    by_type: dict = {}
    for it in items:
        by_type[it.type] = by_type.get(it.type, 0) + 1
    n_totp = sum(1 for i in items if i.totp)
    n_passkeys = sum(len(i.passkeys) for i in items)
    print(f"Sanitized snapshot: {len(items)} items -> {work / 'vault.json'}")
    print(f"  by type: {by_type}")
    print(f"  TOTP seeds: {n_totp}   passkeys: {n_passkeys}")
    print("No plaintext secret was written to disk. Next: `dedupe`.")


def cmd_dedupe(ns) -> None:
    work = Path(ns.work)
    data = _load_vault(work)
    result = plan_dedupe(data["items"])
    (work / "dedupe-report.md").write_text(
        f"_Generated {_now()} from snapshot {data['meta']['fetched_at']}_\n\n"
        + render_dedupe_report(result)
    )
    save_plan(
        work / "plan.json",
        deletions=result.deletions,
        stats=result.stats,
        meta={
            "server": data["meta"]["server"],
            "fetched_at": data["meta"]["fetched_at"],
            "created_at": _now(),
        },
    )
    s = result.stats
    print(f"Scanned {s['items']} items: {s['multi_item_groups']} duplicate groups.")
    print(f"  safe deletions planned : {s['deletions']}")
    print(f"  items needing review   : {s['conflict_items']} (in {s['conflict_groups']} groups)")
    print(f"Report: {work / 'dedupe-report.md'}")
    print(f"Plan:   {work / 'plan.json'}")
    if s["deletions"]:
        print("Review the report, then run `apply` to soft-delete the planned items.")


def cmd_apply(ns) -> None:
    work = Path(ns.work)
    plan_path = work / "plan.json"
    if not plan_path.exists():
        _die("No plan.json. Run `dedupe` first.")
    plan = load_plan(plan_path)
    deletions = plan["deletions"]
    if not deletions:
        print("Plan contains no deletions. Nothing to do.")
        return
    server = _ready(plan["meta"].get("server"))
    print("Re-syncing to verify nothing changed since the plan ...")
    bw.sync()
    current = {i["id"]: i.get("revisionDate") for i in bw.list_items_raw()}
    todo, skipped = bw.filter_deletions(deletions, current)
    for s in skipped:
        print(f"  SKIP {s['name']} ({s['id']}): {s['skip_reason']}")
    if not todo:
        print("Nothing left to delete (all items skipped or already gone).")
        return
    print(f"About to SOFT-delete {len(todo)} items to trash on {server}.")
    print("They remain recoverable in the web vault trash.")
    if not ns.yes:
        answer = input(f"Proceed with {len(todo)} deletions? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted. Nothing deleted.")
            return
    log_path = work / "apply-log.jsonl"
    ok = failed = 0
    started = time.monotonic()
    interrupted = False
    print("Starting bw serve (one process for all deletions) ...")
    with serve.bw_serve() as client, open(log_path, "a") as log:
        try:
            for i, d in enumerate(todo, 1):
                entry = {"ts": _now(), "id": d["id"], "name": d["name"],
                         "keeper_id": d["keeper_id"], "action": "soft-delete"}
                try:
                    client.delete_item(d["id"])
                    entry["ok"] = True
                    ok += 1
                except bw.BwError as e:
                    entry.update(ok=False, error=str(e))
                    failed += 1
                    print(f"  FAILED {d['name']} ({d['id']}): {e}")
                log.write(json.dumps(entry) + "\n")
                if ok == 1 and i == 1:
                    # canary, prove the serve DELETE was a soft delete
                    # before touching the rest of the plan
                    trash_ids = {t["id"] for t in json.loads(bw.run_bw(["list", "items", "--trash"]))}
                    if d["id"] not in trash_ids:
                        _die(f"ABORT: first deleted item {d['id']} is not in trash. "
                             "serve delete may be permanent. Nothing further was deleted.")
                    print("  canary ok: first deleted item confirmed in trash")
                if i % 100 == 0 or i == len(todo) or i == 20:
                    rate = i / max(time.monotonic() - started, 0.001)
                    eta = (len(todo) - i) / max(rate, 0.001)
                    print(f"  ... {i}/{len(todo)}  ({rate:.1f}/s, ~{eta / 60:.0f} min left)")
        except KeyboardInterrupt:
            interrupted = True
    if interrupted:
        print(f"\nInterrupted: {ok} soft-deleted so far, {failed} failed.")
        print("Safe to resume any time. Re-run `apply`, finished items are skipped.")
    else:
        print(f"Done: {ok} soft-deleted, {failed} failed, {len(skipped)} skipped "
              f"in {(time.monotonic() - started) / 60:.1f} min.")
        print("Tip: re-run `fetch` + `dedupe`. The new report should show 0 planned deletions.")
    print(f"Log: {log_path}")


def cmd_diff_apple(ns) -> None:
    work = Path(ns.work)
    data = _load_vault(work)
    hasher = Hasher(ensure_key(work))
    csv_path = Path(ns.csv)
    if not csv_path.exists():
        _die(f"CSV not found: {csv_path}")
    apple = read_apple_csv(csv_path, hasher)
    save_dataset(
        work / "apple.json",
        apple,
        meta={"source": str(csv_path), "ingested_at": _now()},
    )
    vault_logins = sum(1 for i in data["items"] if i.type == "login")
    d = diff_vault_vs_apple(data["items"], apple)
    (work / "diff-report.md").write_text(
        f"_Generated {_now()}, vault snapshot {data['meta']['fetched_at']}, "
        f"Apple CSV {csv_path.name}_\n\n"
        + render_diff_report(d, vault_login_count=vault_logins, apple_count=len(apple))
    )
    print(f"Compared {vault_logins} Vaultwarden logins vs {len(apple)} Apple entries:")
    print(f"  identical: {len(d.identical)}   password conflicts: {len(d.password_conflicts)}")
    print(f"  TOTP mismatches: {len(d.totp_mismatches)}   notes differ: {len(d.notes_differ)}")
    print(f"  Apple-only: {len(d.apple_only)}   Vaultwarden-only: {len(d.vault_only)}")
    print(f"  Apple-internal duplicates: {d.apple_internal_dupes}")
    print(f"Report: {work / 'diff-report.md'}")
    if ns.shred_csv:
        shred_file(csv_path)
        print(f"Shredded plaintext CSV: {csv_path}")
    else:
        print(f"REMINDER: {csv_path} still holds plaintext passwords. "
              f"Delete it once you are done, or re-run with --shred-csv.")


def cmd_export_apple(ns) -> None:
    work = Path(ns.work)
    ensure_key(work)  # enforces the 0700 work dir, the key itself is unused here
    server = _ready(ns.server)
    print(f"Syncing with {server} ...")
    bw.sync()
    raw = bw.list_items_raw()  # plaintext, memory only
    rows, skipped = export_rows(raw)
    if ns.no_notes:
        rows = [{**r, "Notes": ""} for r in rows]
    text = render_apple_csv(rows)
    del raw
    path = work / "apple-import.csv"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    with_otp = sum(1 for r in rows if r["OTPAuth"])
    print(f"Wrote {len(rows)} rows ({with_otp} with TOTP seeds) -> {path}  [chmod 600]")
    if skipped:
        print(f"Skipped {len(skipped)} logins Apple's CSV cannot represent:")
        for name, reason in skipped:
            print(f"  - {name}: {reason}")
    print("\nNext steps:")
    print("  1. Passwords.app -> File -> Import Passwords... -> select the file above.")
    print("     Import is an upsert: identical entries no-op, missing ones are added,")
    print("     TOTP seeds attach to their entries. Passkeys are unaffected.")
    print("  2. THE FILE HOLDS PLAINTEXT PASSWORDS. When the import is done, run:")
    print("     python3 -m vaultdupe shred   (or delete the file securely yourself)")


def cmd_shred(ns) -> None:
    work = Path(ns.work)
    if not ns.yes:
        answer = input(f"Shred everything under {work}/ (incl. HMAC key)? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted.")
            return
    n = shred_work(work)
    print(f"Shredded {n} files and removed {work}/.")
    print("Note: on APFS/SSD, FileVault is what protects deleted data.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vd",
        description="Vaultwarden dedupe and Apple Passwords diff. Secrets are "
        "HMAC-hashed at ingest, plaintext never touches disk.",
    )
    p.add_argument("--work", default="work", help="work directory (default: ./work)")
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="pull vault via bw CLI -> sanitized snapshot")
    f.add_argument("--server", default=None,
                   help="expected server URL, defaults to bw's configured server")

    sub.add_parser("dedupe", help="plan duplicate removal -> report + plan.json")

    a = sub.add_parser("apply", help="soft-delete planned duplicates (with re-verify)")
    a.add_argument("--yes", action="store_true", help="skip confirmation prompt")

    da = sub.add_parser("diff-apple", help="compare snapshot vs Apple Passwords CSV")
    da.add_argument("csv", help="path to Apple Passwords export CSV")
    da.add_argument("--shred-csv", action="store_true",
                    help="overwrite and delete the CSV after ingest")

    ea = sub.add_parser(
        "export-apple",
        help="generate Apple-format import CSV from the vault (incl. OTPAuth)",
    )
    ea.add_argument("--server", default=None,
                    help="expected server URL, defaults to bw's configured server")
    ea.add_argument("--no-notes", action="store_true",
                    help="leave the Notes column empty")

    s = sub.add_parser("shred", help="shred the work directory")
    s.add_argument("--yes", action="store_true")
    return p


def main(argv=None) -> None:
    ns = build_parser().parse_args(argv)
    try:
        {
            "fetch": cmd_fetch,
            "dedupe": cmd_dedupe,
            "apply": cmd_apply,
            "diff-apple": cmd_diff_apple,
            "export-apple": cmd_export_apple,
            "shred": cmd_shred,
        }[ns.cmd](ns)
    except bw.BwError as e:
        _die(str(e))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
