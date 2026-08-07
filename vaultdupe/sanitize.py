"""The plaintext to digest boundary.

This is the only module in the pipeline that reads secret values. It maps
raw Bitwarden items (and, via apple.py, Apple CSV rows) into SanitizedItem
records whose secrets are keyed HMAC-SHA256 digests. Everything downstream
consumes SanitizedItem only, so no plaintext secret can reach disk, a
report, or a terminal.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass, field

from .normalize import norm_name, norm_username, parse_totp, registrable_domain


class Hasher:
    """Keyed, domain-separated fingerprints.

    Digest = HMAC-SHA256(key, kind || 0x00 || value), truncated to 16 hex
    chars. Domain separation ("password" vs "note" vs "totp") prevents equal
    plaintext in different roles from producing cross-linkable digests.
    64 bits is far beyond collision risk at personal-vault scale.
    """

    def __init__(self, key: bytes):
        if len(key) < 16:
            raise ValueError("hasher key must be at least 16 bytes")
        self._key = key

    def digest(self, kind: str, value: str | None) -> str | None:
        if value is None:
            return None
        v = value.strip() if isinstance(value, str) else str(value)
        if not v:
            return None
        msg = kind.encode() + b"\x00" + v.encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()[:16]


@dataclass
class SanitizedItem:
    id: str
    type: str  # login, note, card, or identity
    name: str
    revision: str
    created: str | None = None
    folder_id: str | None = None
    org_id: str | None = None
    favorite: bool = False
    notes_digest: str | None = None
    notes_len: int = 0
    history_count: int = 0  # password history entries, metadata only
    fields: list = field(default_factory=list)  # {name, type, value_digest}
    attachments: list = field(default_factory=list)  # filenames
    # login
    username: str = ""
    domains: list = field(default_factory=list)
    uri_count: int = 0
    password_digest: str | None = None
    password_len: int = 0
    totp: dict | None = None  # {digest, kind, params}
    passkeys: list = field(default_factory=list)  # {credential_id, rp_id, user_name, created}
    # card
    card: dict | None = None  # {holder, brand, last4, exp, number_digest, code_digest}
    # identity
    identity_digest: str | None = None

    def keys(self) -> set[tuple]:
        """Grouping keys this item contributes (see dedupe union-find)."""
        if self.type == "login":
            if self.domains:
                return {("login", d, self.username) for d in self.domains}
            return {("login:name", norm_name(self.name), self.username)}
        if self.type == "note":
            return {("note", norm_name(self.name))}
        if self.type == "card":
            if self.card and self.card.get("number_digest"):
                return {("card", self.card["number_digest"])}
            return {("card:name", norm_name(self.name))}
        return {("identity:name", norm_name(self.name))}

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "SanitizedItem":
        return cls(**d)


_TYPE_NAMES = {1: "login", 2: "note", 3: "card", 4: "identity"}


def sanitize_item(raw: dict, hasher: Hasher) -> SanitizedItem:
    type_name = _TYPE_NAMES[raw["type"]]
    notes = raw.get("notes")
    item = SanitizedItem(
        id=raw["id"],
        type=type_name,
        name=raw.get("name") or "",
        revision=raw.get("revisionDate") or "",
        created=raw.get("creationDate"),
        folder_id=raw.get("folderId"),
        org_id=raw.get("organizationId"),
        favorite=bool(raw.get("favorite")),
        notes_digest=hasher.digest("note", notes),
        notes_len=len(notes) if notes else 0,
        history_count=len(raw.get("passwordHistory") or []),
        fields=[
            {
                "name": f.get("name") or "",
                "type": f.get("type"),
                "value_digest": hasher.digest("field", f.get("value")),
            }
            for f in (raw.get("fields") or [])
        ],
        attachments=[a.get("fileName") or a.get("id") for a in (raw.get("attachments") or [])],
    )

    if type_name == "login":
        login = raw.get("login") or {}
        uris = [u.get("uri") for u in (login.get("uris") or []) if u and u.get("uri")]
        domains = {d for d in (registrable_domain(u) for u in uris) if d}
        item.username = norm_username(login.get("username"))
        item.domains = sorted(domains)
        item.uri_count = len(uris)
        password = login.get("password")
        item.password_digest = hasher.digest("password", password)
        item.password_len = len(password) if password else 0
        totp = parse_totp(login.get("totp"))
        if totp:
            item.totp = {
                "digest": hasher.digest("totp", totp.canonical()),
                "kind": totp.kind,
                "params": f"{totp.kind}/{totp.algorithm}/{totp.digits}/{totp.period}",
            }
        item.passkeys = sorted(
            (
                {
                    "credential_id": c.get("credentialId"),
                    "rp_id": c.get("rpId"),
                    "user_name": c.get("userName"),
                    "created": c.get("creationDate"),
                }
                for c in (login.get("fido2Credentials") or [])
            ),
            key=lambda c: c["credential_id"] or "",
        )
    elif type_name == "card":
        card = raw.get("card") or {}
        digits = re.sub(r"\D", "", card.get("number") or "")
        exp_month, exp_year = card.get("expMonth"), card.get("expYear")
        item.card = {
            "holder": card.get("cardholderName"),
            "brand": card.get("brand"),
            "last4": digits[-4:] if digits else None,
            "exp": f"{exp_month}/{exp_year}" if exp_month or exp_year else None,
            "number_digest": hasher.digest("card", digits),
            "code_digest": hasher.digest("card-code", card.get("code")),
        }
    elif type_name == "identity":
        identity = raw.get("identity") or {}
        canonical = {
            k.lower(): str(v).strip()
            for k, v in identity.items()
            if v is not None and str(v).strip()
        }
        item.identity_digest = hasher.digest(
            "identity", json.dumps(canonical, sort_keys=True)
        )

    return item


def sanitize_vault(raw_items: list, hasher: Hasher) -> list:
    """Sanitize a full `bw list items` payload.

    Trashed and unknown-type items are skipped. bw excludes trash already,
    the check here is defense in depth.
    """
    out = []
    for raw in raw_items:
        if raw.get("deletedDate"):
            continue
        if raw.get("type") not in _TYPE_NAMES:
            continue
        out.append(sanitize_item(raw, hasher))
    return out
