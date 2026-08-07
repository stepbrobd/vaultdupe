"""Canonicalization rules for site, account, and TOTP equality.

Every equality decision in the pipeline flows through these functions, so
they are small, pure, and heavily tested.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

import tldextract

# suffix_list_urls=() pins tldextract to its bundled public suffix list
# so runs are offline and deterministic
_extract = tldextract.TLDExtract(suffix_list_urls=())

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_WEB_SCHEMES = {"http", "https", "ftp", "ftps"}
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HOSTISH_RE = re.compile(r"^[a-z0-9._-]+(:\d+)?$", re.IGNORECASE)


def registrable_domain(uri: str | None) -> str | None:
    """Reduce a stored URI to a stable grouping key.

    Web URLs collapse to their registrable domain (eTLD+1), so
    accounts.google.com and mail.google.com group together while foo.co.uk
    and bar.co.uk stay apart. Non-web schemes such as androidapp://, IP
    addresses, and single-label hosts are kept verbatim. Unparseable values
    fall back to the lowered, trimmed string so identical garbage still
    groups.
    """
    if uri is None:
        return None
    s = uri.strip()
    if not s:
        return None
    lowered = s.lower()

    if _SCHEME_RE.match(lowered):
        scheme = lowered.split("://", 1)[0]
        if scheme not in _WEB_SCHEMES:
            return lowered.rstrip("/")
        host = urlsplit(lowered).hostname
        return _reduce_host(host) if host else lowered

    if _HOSTISH_RE.match(lowered):
        host = urlsplit("//" + lowered).hostname or lowered
        return _reduce_host(host)

    return lowered


def _reduce_host(host: str) -> str:
    if _IPV4_RE.match(host) or ":" in host or "." not in host:
        return host
    ext = _extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


def norm_username(username: str | None) -> str:
    return (username or "").strip().lower()


def norm_name(name: str | None) -> str:
    return re.sub(r"\s+", " ", (name or "").strip()).lower()


@dataclass(frozen=True)
class Totp:
    kind: str  # totp, hotp, or steam
    secret: str  # normalized base32, uppercase, no whitespace or padding
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30

    def canonical(self) -> str:
        """Equality-defining string, the input to the downstream HMAC."""
        return f"{self.kind}:{self.secret}:{self.algorithm}:{self.digits}:{self.period}"


def _norm_secret(raw: str) -> str:
    return re.sub(r"[\s=]", "", raw).upper()


def parse_totp(value: str | None) -> Totp | None:
    """Parse Bitwarden's totp field or Apple's OTPAuth column.

    Accepts a bare base32 seed, an otpauth:// URI, or steam://. A bare seed
    and a URI carrying the same seed with default parameters compare equal.
    """
    if value is None:
        return None
    s = value.strip()
    if not s:
        return None

    low = s.lower()
    if low.startswith("otpauth://"):
        parts = urlsplit(s)
        q = {k.lower(): v for k, v in parse_qs(parts.query).items()}
        secret = _norm_secret(q.get("secret", [""])[0])
        if not secret:
            return None
        return Totp(
            kind=(parts.netloc or "totp").lower(),
            secret=secret,
            algorithm=q.get("algorithm", ["SHA1"])[0].upper().replace("-", ""),
            digits=int(q.get("digits", ["6"])[0]),
            period=int(q.get("period", ["30"])[0]),
        )
    if low.startswith("steam://"):
        return Totp(kind="steam", secret=_norm_secret(s[len("steam://"):]), digits=5)
    return Totp(kind="totp", secret=_norm_secret(s))


def login_keys(uris, username, name) -> set[tuple]:
    """Keys a login item contributes to grouping, one per distinct domain.

    Items sharing any key end up in the same candidate group (union-find),
    which is how a one-URI copy and a three-URI copy of the same login meet.
    """
    user = norm_username(username)
    keys = set()
    for u in uris or []:
        domain = registrable_domain(u)
        if domain:
            keys.add(("login", domain, user))
    if not keys:
        keys.add(("login:name", norm_name(name), user))
    return keys
