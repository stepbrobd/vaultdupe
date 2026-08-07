"""Tests for vaultdupe.report, markdown rendering and the redaction invariant.

The critical property: reports are built from sanitized items that were
produced from sentinel plaintext, and no sentinel may appear in the
rendered markdown. Digests, names, domains, and usernames may.
"""

from vaultdupe.dedupe import plan_dedupe
from vaultdupe.diff import diff_vault_vs_apple
from vaultdupe.report import render_dedupe_report, render_diff_report
from vaultdupe.sanitize import Hasher, sanitize_item

H = Hasher(b"\x09" * 32)

PW_A = "Plain-Password-AAA-XYZZY"
PW_B = "Plain-Password-BBB-XYZZY"
SEED = "JBSWY3DPEHPK3PXPQQQQ"
NOTE = "recovery codes XYZZY 111 222"


def raw_login(id, name, password, *, totp=None, notes=None, uri="https://site.com",
              revision="2025-01-01T00:00:00.000Z"):
    return {
        "id": id, "type": 1, "name": name, "notes": notes,
        "login": {
            "uris": [{"uri": uri}], "username": "user@site.com",
            "password": password, "totp": totp,
        },
        "revisionDate": revision,
    }


def build_items():
    return [
        sanitize_item(raw_login("id-keep", "Site", PW_A, totp=SEED, notes=NOTE), H),
        sanitize_item(raw_login("id-dup", "Site (old)", PW_A,
                                revision="2024-01-01T00:00:00.000Z"), H),
        sanitize_item(raw_login("id-conf", "Site (other pw)", PW_B), H),
    ]


class TestDedupeReport:
    def test_mentions_deletions_and_conflicts(self):
        md = render_dedupe_report(plan_dedupe(build_items()))
        assert "Site (old)" in md          # deletion listed
        assert "id-dup" in md
        assert "Site (other pw)" in md     # conflict listed
        assert "password differs" in md

    def test_redaction_invariant(self):
        md = render_dedupe_report(plan_dedupe(build_items()))
        for sentinel in (PW_A, PW_B, SEED, NOTE):
            assert sentinel not in md

    def test_digests_shown_short_with_hash_prefix(self):
        md = render_dedupe_report(plan_dedupe(build_items()))
        d = H.digest("password", PW_A)
        assert f"#{d[:8]}" in md
        assert d not in md  # full digest never shown, only the 8-char prefix


class TestDiffReport:
    def test_sections_and_redaction(self):
        vault = [sanitize_item(raw_login("v1", "Site", PW_A, totp=SEED), H)]
        from vaultdupe.sanitize import SanitizedItem

        apple = [
            SanitizedItem(
                id="apple:0001", type="login", name="site.com", revision="",
                username="user@site.com", domains=["site.com"], uri_count=1,
                password_digest=H.digest("password", PW_B), password_len=len(PW_B),
            )
        ]
        d = diff_vault_vs_apple(vault, apple)
        md = render_diff_report(d, vault_login_count=1, apple_count=1)
        assert "Password conflicts" in md
        assert "Apple-only" in md
        assert "Passkey" in md
        for sentinel in (PW_A, PW_B, SEED):
            assert sentinel not in md
