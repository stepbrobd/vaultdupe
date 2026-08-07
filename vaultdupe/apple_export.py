"""Bitwarden to Apple Passwords import CSV.

The one module besides sanitize that touches plaintext. It renders the file
Apple's importer consumes (Title,URL,Username,Password,Notes,OTPAuth).
Apple's import is an upsert keyed by (site, username), so importing this
file is idempotent. Identical entries no-op, missing entries are added, and
OTPAuth plants TOTP seeds onto existing entries. Passkeys cannot ride along.
"""

from __future__ import annotations

import csv
import io
from urllib.parse import quote

from .normalize import parse_totp

HEADER = ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"]


def render_otpauth(totp_value: str | None, *, account: str, issuer: str) -> str | None:
    """Render Bitwarden's totp field as the otpauth URI Apple imports.

    Bitwarden stores either a bare seed or a full URI. URIs pass through
    untouched.
    """
    if totp_value is None:
        return None
    s = totp_value.strip()
    if not s:
        return None
    if s.lower().startswith(("otpauth://", "steam://")):
        return s
    t = parse_totp(s)
    if t is None:
        return None
    label = quote(f"{issuer}:{account}" if issuer else account, safe=":")
    params = [f"secret={t.secret}"]
    if issuer:
        params.append(f"issuer={quote(issuer, safe='')}")
    if t.algorithm != "SHA1":
        params.append(f"algorithm={t.algorithm}")
    if t.digits != 6:
        params.append(f"digits={t.digits}")
    if t.period != 30:
        params.append(f"period={t.period}")
    return f"otpauth://totp/{label}?{'&'.join(params)}"


def _first_web_uri(uris) -> str | None:
    # one URL per row, the first http(s) URI wins
    # app-scheme URIs mean nothing to apple
    # deliberately not one row per URI, that would recreate subdomain
    # spread on the apple side
    for u in uris or []:
        uri = (u.get("uri") or "").strip()
        if uri.lower().startswith(("http://", "https://")):
            return uri
    for u in uris or []:
        uri = (u.get("uri") or "").strip()
        if uri and "://" not in uri:
            return uri
    return None


def login_to_row(raw: dict) -> dict | None:
    login = raw.get("login") or {}
    url = _first_web_uri(login.get("uris"))
    if not url:
        return None
    username = login.get("username") or ""
    password = login.get("password") or ""
    otpauth = render_otpauth(
        login.get("totp"), account=username, issuer=raw.get("name") or ""
    )
    if not password and not otpauth:
        return None  # passkey-only or empty item, the CSV has nothing to carry
    return {
        "Title": raw.get("name") or "",
        "URL": url,
        "Username": username,
        "Password": password,
        "Notes": raw.get("notes") or "",
        "OTPAuth": otpauth or "",
    }


def export_rows(raw_items: list) -> tuple[list, list]:
    """Return (rows, skipped) where skipped is [(name, reason)].

    Non-login types are out of scope for Apple Passwords and are not
    reported as skipped.
    """
    rows, skipped = [], []
    for raw in raw_items:
        if raw.get("type") != 1 or raw.get("deletedDate"):
            continue
        row = login_to_row(raw)
        if row is not None:
            rows.append(row)
            continue
        login = raw.get("login") or {}
        if not _first_web_uri(login.get("uris")):
            skipped.append((raw.get("name") or raw.get("id"),
                            "no usable URL, Apple import needs one"))
        else:
            skipped.append((raw.get("name") or raw.get("id"),
                            "no password or TOTP (passkey-only?), CSV cannot carry it"))
    return rows, skipped


def render_apple_csv(rows: list) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=HEADER, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()
