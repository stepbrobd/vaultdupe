"""Tests for vaultdupe.apple, the Apple Passwords CSV ingest."""

import json

from vaultdupe.apple import read_apple_csv
from vaultdupe.sanitize import Hasher

KEY = b"\x03" * 32
H = Hasher(KEY)

PW = "Apple-S3cret-XYZZY"
SEED = "JBSWY3DPEHPK3PXP"


def write_csv(tmp_path, text, name="apple.csv"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


BASIC = (
    "\ufeffTitle,URL,Username,Password,Notes,OTPAuth\n"
    f'github.com,https://github.com/login,User,{PW},"note body",'
    f"otpauth://totp/GitHub:user?secret={SEED}&issuer=GitHub\n"
)


class TestReadAppleCsv:
    def test_basic_row(self, tmp_path):
        (e,) = read_apple_csv(write_csv(tmp_path, BASIC), H)
        assert e.type == "login"
        assert e.name == "github.com"
        assert e.username == "user"
        assert e.domains == ["github.com"]
        assert e.password_digest == H.digest("password", PW)
        assert e.password_len == len(PW)
        assert e.notes_digest == H.digest("note", "note body")

    def test_totp_digest_matches_vault_side_canonical_form(self, tmp_path):
        # the same seed stored as a bare secret in vaultwarden and as an
        # otpauth URI in apple must produce the same digest
        from vaultdupe.normalize import parse_totp

        vault_side = H.digest("totp", parse_totp(SEED).canonical())
        (e,) = read_apple_csv(write_csv(tmp_path, BASIC), H)
        assert e.totp["digest"] == vault_side

    def test_ids_are_stable_and_unique(self, tmp_path):
        text = BASIC + f"example.com,https://example.com,u2,{PW},,\n"
        entries = read_apple_csv(write_csv(tmp_path, text), H)
        assert [e.id for e in entries] == ["apple:0001", "apple:0002"]

    def test_header_case_and_missing_optional_columns_tolerated(self, tmp_path):
        text = "title,url,USERNAME,password\nX,https://x.co.uk,U,pw\n"
        (e,) = read_apple_csv(write_csv(tmp_path, text), H)
        assert e.username == "u"
        assert e.domains == ["x.co.uk"]
        assert e.totp is None
        assert e.notes_digest is None

    def test_blank_rows_skipped(self, tmp_path):
        text = BASIC + ",,,,,\n"
        assert len(read_apple_csv(write_csv(tmp_path, text), H)) == 1

    def test_no_plaintext_survives(self, tmp_path):
        entries = read_apple_csv(write_csv(tmp_path, BASIC), H)
        blob = json.dumps([e.to_dict() for e in entries])
        assert PW not in blob
        assert SEED not in blob
        assert "note body" not in blob

    def test_row_without_url_uses_title_for_name_key(self, tmp_path):
        text = "Title,URL,Username,Password\nMy Router,,admin,pw\n"
        (e,) = read_apple_csv(write_csv(tmp_path, text), H)
        assert e.domains == []
        assert e.keys() == {("login:name", "my router", "admin")}
