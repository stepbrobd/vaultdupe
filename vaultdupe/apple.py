"""Apple Passwords CSV ingest.

Rows are sanitized at read time with the same HMAC key as the Vaultwarden
side, so equal secrets produce equal digests across managers and the
plaintext CSV content never propagates past this function. Apple's export
carries no passkeys and no timestamps.
"""

from __future__ import annotations

import csv

from .normalize import norm_username, parse_totp, registrable_domain
from .sanitize import Hasher, SanitizedItem

# apple has used slightly different header spellings over the years
# matching is case-insensitive on these canonical names
_COLUMNS = ("title", "url", "username", "password", "notes", "otpauth")


def read_apple_csv(path: str, hasher: Hasher) -> list:
    entries = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            lowered = {
                (k or "").strip().lower(): (v or "").strip()
                for k, v in row.items()
            }
            get = lambda col: lowered.get(col, "")
            if not any(get(c) for c in _COLUMNS):
                continue

            url, password, notes = get("url"), get("password"), get("notes")
            domain = registrable_domain(url)
            totp = parse_totp(get("otpauth"))
            entries.append(
                SanitizedItem(
                    id=f"apple:{len(entries) + 1:04d}",
                    type="login",
                    name=get("title") or domain or "",
                    revision="",
                    username=norm_username(get("username")),
                    domains=[domain] if domain else [],
                    uri_count=1 if url else 0,
                    password_digest=hasher.digest("password", password),
                    password_len=len(password),
                    notes_digest=hasher.digest("note", notes),
                    notes_len=len(notes),
                    totp={
                        "digest": hasher.digest("totp", totp.canonical()),
                        "kind": totp.kind,
                        "params": f"{totp.kind}/{totp.algorithm}/{totp.digits}/{totp.period}",
                    }
                    if totp
                    else None,
                )
            )
    return entries
