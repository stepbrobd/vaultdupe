"""Tests for vaultdupe.apple_export, the Bitwarden to Apple-format CSV.

This module produces the plaintext file Apple's importer reads, so tests
assert correct placement of sentinel values. The round-trip test proves the
generated CSV re-ingests to identical digests, so importing it gives Apple
exactly what the vault holds.
"""

from vaultdupe.apple import read_apple_csv
from vaultdupe.apple_export import export_rows, login_to_row, render_apple_csv, render_otpauth
from vaultdupe.normalize import parse_totp
from vaultdupe.sanitize import Hasher, sanitize_item

PW = "Export-S3cret-XYZZY"
SEED = "JBSWY3DPEHPK3PXP"


def raw_login(**over):
    item = {
        "id": "x1", "type": 1, "name": "GitHub", "notes": "a note, with comma",
        "login": {
            "uris": [{"uri": "https://github.com/login"}],
            "username": "user", "password": PW, "totp": SEED,
        },
        "revisionDate": "2025-01-01T00:00:00.000Z",
    }
    item.update(over)
    return item


class TestRenderOtpauth:
    def test_raw_seed_becomes_otpauth_uri(self):
        uri = render_otpauth("jbsw y3dp ehpk 3pxp", account="user", issuer="GitHub")
        assert uri.startswith("otpauth://totp/")
        assert "secret=JBSWY3DPEHPK3PXP" in uri
        assert "issuer=GitHub" in uri

    def test_existing_otpauth_uri_passes_through_unchanged(self):
        orig = f"otpauth://totp/GitHub:user?secret={SEED}&digits=8"
        assert render_otpauth(orig, account="a", issuer="b") == orig

    def test_steam_uri_passes_through(self):
        assert render_otpauth("steam://KEY", account="a", issuer="b") == "steam://KEY"

    def test_special_chars_in_labels_are_url_encoded(self):
        uri = render_otpauth(SEED, account="a user@example.com", issuer="My Site")
        assert " " not in uri

    def test_non_default_params_preserved_for_raw_uri_input(self):
        uri = render_otpauth(
            f"otpauth://totp/X?secret={SEED}&algorithm=SHA256&digits=8&period=60",
            account="a", issuer="b",
        )
        assert "SHA256" in uri and "digits=8" in uri

    def test_empty_returns_none(self):
        assert render_otpauth(None, account="a", issuer="b") is None
        assert render_otpauth("  ", account="a", issuer="b") is None


class TestLoginToRow:
    def test_maps_all_columns(self):
        row = login_to_row(raw_login())
        assert row["Title"] == "GitHub"
        assert row["URL"] == "https://github.com/login"
        assert row["Username"] == "user"
        assert row["Password"] == PW
        assert row["Notes"] == "a note, with comma"
        assert "secret=" + SEED in row["OTPAuth"]

    def test_first_web_uri_wins_android_skipped(self):
        raw = raw_login()
        raw["login"]["uris"] = [
            {"uri": "androidapp://com.github.android"},
            {"uri": "https://github.com"},
        ]
        assert login_to_row(raw)["URL"] == "https://github.com"

    def test_item_without_uri_is_skipped(self):
        raw = raw_login()
        raw["login"]["uris"] = []
        assert login_to_row(raw) is None

    def test_item_with_neither_password_nor_totp_is_skipped(self):
        raw = raw_login()
        raw["login"]["password"] = None
        raw["login"]["totp"] = None
        assert login_to_row(raw) is None

    def test_totp_only_item_is_kept(self):
        raw = raw_login()
        raw["login"]["password"] = None
        row = login_to_row(raw)
        assert row["Password"] == ""
        assert row["OTPAuth"]


class TestExportRows:
    def test_partitions_rows_and_skips_with_reasons(self):
        items = [
            raw_login(),
            raw_login(id="x2", name="No URI", login={"uris": [], "username": "u",
                                                    "password": "p", "totp": None}),
            {"id": "n1", "type": 2, "name": "Note", "notes": "x",
             "revisionDate": "2025-01-01T00:00:00.000Z"},
        ]
        rows, skipped = export_rows(items)
        assert len(rows) == 1
        # non-login types are out of scope rather than skipped
        assert [(name, "no usable URL" in reason) for name, reason in skipped] == [
            ("No URI", True)
        ]

    def test_csv_render_has_exact_apple_header(self):
        rows, _ = export_rows([raw_login()])
        text = render_apple_csv(rows)
        assert text.splitlines()[0] == "Title,URL,Username,Password,Notes,OTPAuth"
        assert PW in text  # plaintext by design, this is the import file

    def test_round_trip_digest_equivalence(self):
        # ingesting the generated CSV must yield the same password and TOTP
        # digests as the vault item it came from, so importing the file
        # gives apple exactly what the vault holds
        h = Hasher(b"\x0c" * 32)
        raw = raw_login()
        vault_side = sanitize_item(raw, h)

        rows, _ = export_rows([raw])
        text = render_apple_csv(rows)
        import pathlib, tempfile
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "apple-import.csv"
            p.write_text(text, encoding="utf-8")
            (apple_side,) = read_apple_csv(str(p), h)

        assert apple_side.password_digest == vault_side.password_digest
        assert apple_side.totp["digest"] == vault_side.totp["digest"]
        assert apple_side.username == vault_side.username
        assert apple_side.domains == vault_side.domains
