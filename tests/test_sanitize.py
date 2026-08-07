"""Tests for vaultdupe.sanitize, the plaintext to digest security boundary."""

import json

import pytest

from vaultdupe.sanitize import Hasher, SanitizedItem, sanitize_item, sanitize_vault

KEY = b"\x01" * 32
H = Hasher(KEY)

# sentinel secrets, none of these strings may appear in sanitized output
PW = "S3cr3t!Password-XYZZY"
SEED = "JBSWY3DPEHPK3PXP"
NOTE_BODY = "my secret recovery codes XYZZY-1 XYZZY-2"
CARD_NUMBER = "4111 1111 1111 1234"
CARD_CODE = "987"
FIELD_SECRET = "hidden-field-value-XYZZY"
SSN = "078-05-1120"


def raw_login(**over):
    item = {
        "id": "11111111-aaaa-bbbb-cccc-000000000001",
        "organizationId": None,
        "folderId": "fold-1",
        "type": 1,
        "name": "GitHub",
        "notes": NOTE_BODY,
        "favorite": False,
        "fields": [{"name": "backup-pin", "value": FIELD_SECRET, "type": 1}],
        "login": {
            "uris": [
                {"match": None, "uri": "https://github.com/login"},
                {"match": None, "uri": "https://Gist.GitHub.com"},
            ],
            "username": "User",
            "password": PW,
            "totp": SEED,
            "fido2Credentials": [
                {
                    "credentialId": "cred-abc",
                    "rpId": "github.com",
                    "userName": "user",
                    "creationDate": "2025-06-01T00:00:00.000Z",
                }
            ],
        },
        "attachments": [{"id": "att1", "fileName": "codes.txt", "size": "42"}],
        "revisionDate": "2025-07-01T10:00:00.000Z",
        "creationDate": "2024-01-01T00:00:00.000Z",
        "deletedDate": None,
    }
    item.update(over)
    return item


class TestHasher:
    def test_same_input_same_digest(self):
        assert H.digest("password", PW) == H.digest("password", PW)

    def test_domain_separation_by_kind(self):
        assert H.digest("password", PW) != H.digest("note", PW)

    def test_different_key_different_digest(self):
        other = Hasher(b"\x02" * 32)
        assert H.digest("password", PW) != other.digest("password", PW)

    def test_empty_and_none_digest_to_none(self):
        assert H.digest("password", "") is None
        assert H.digest("password", None) is None
        assert H.digest("password", "   ") is None

    def test_digest_is_short_hex(self):
        d = H.digest("password", PW)
        assert len(d) == 16
        int(d, 16)  # must be valid hex


class TestSanitizeLogin:
    def test_maps_metadata_and_digests_secrets(self):
        s = sanitize_item(raw_login(), H)
        assert s.type == "login"
        assert s.name == "GitHub"
        assert s.username == "user"
        assert s.domains == ["github.com"]  # both URIs collapse to one domain
        assert s.uri_count == 2
        assert s.password_digest == H.digest("password", PW)
        assert s.password_len == len(PW)
        assert s.notes_digest == H.digest("note", NOTE_BODY)
        assert s.attachments == ["codes.txt"]
        assert s.fields == [
            {"name": "backup-pin", "type": 1, "value_digest": H.digest("field", FIELD_SECRET)}
        ]

    def test_totp_digest_matches_for_raw_seed_and_otpauth_uri(self):
        a = sanitize_item(raw_login(), H)
        b_raw = raw_login()
        b_raw["login"]["totp"] = f"otpauth://totp/GitHub:user?secret={SEED.lower()}&issuer=GitHub"
        b = sanitize_item(b_raw, H)
        assert a.totp["digest"] == b.totp["digest"]
        assert a.totp["params"] == "totp/SHA1/6/30"

    def test_passkeys_kept_by_reference_not_value(self):
        s = sanitize_item(raw_login(), H)
        assert s.passkeys == [
            {
                "credential_id": "cred-abc",
                "rp_id": "github.com",
                "user_name": "user",
                "created": "2025-06-01T00:00:00.000Z",
            }
        ]

    def test_no_sentinel_secret_survives_serialization(self):
        s = sanitize_item(raw_login(), H)
        blob = json.dumps(s.to_dict())
        for sentinel in (PW, SEED, NOTE_BODY, FIELD_SECRET):
            assert sentinel not in blob

    def test_password_history_count_captured(self):
        raw = raw_login()
        raw["passwordHistory"] = [
            {"lastUsedDate": "2024-01-01T00:00:00.000Z", "password": "Hist0ric-XYZZY-1"},
            {"lastUsedDate": "2023-01-01T00:00:00.000Z", "password": "Hist0ric-XYZZY-2"},
        ]
        s = sanitize_item(raw, H)
        assert s.history_count == 2
        assert "Hist0ric-XYZZY" not in json.dumps(s.to_dict())

    def test_missing_login_subfields_tolerated(self):
        raw = raw_login()
        raw["login"] = {"uris": None, "username": None, "password": None, "totp": None}
        raw["fields"] = None
        raw["attachments"] = None
        raw["notes"] = None
        s = sanitize_item(raw, H)
        assert s.password_digest is None
        assert s.totp is None
        assert s.passkeys == []
        assert s.domains == []


class TestSanitizeOtherTypes:
    def test_secure_note(self):
        raw = {
            "id": "n1", "type": 2, "name": "WiFi", "notes": NOTE_BODY,
            "secureNote": {"type": 0}, "revisionDate": "2025-01-01T00:00:00.000Z",
        }
        s = sanitize_item(raw, H)
        assert s.type == "note"
        assert s.notes_digest == H.digest("note", NOTE_BODY)
        assert NOTE_BODY not in json.dumps(s.to_dict())

    def test_card_digests_number_and_code_keeps_last4(self):
        raw = {
            "id": "c1", "type": 3, "name": "Visa", "notes": None,
            "card": {
                "cardholderName": "A User", "brand": "Visa",
                "number": CARD_NUMBER, "expMonth": "4", "expYear": "2030",
                "code": CARD_CODE,
            },
            "revisionDate": "2025-01-01T00:00:00.000Z",
        }
        s = sanitize_item(raw, H)
        assert s.card["last4"] == "1234"
        assert s.card["brand"] == "Visa"
        # digest is over digits only, so formatting differences do not matter
        assert s.card["number_digest"] == H.digest("card", "4111111111111234")
        blob = json.dumps(s.to_dict())
        assert CARD_NUMBER not in blob
        assert "4111111111111234" not in blob
        assert CARD_CODE not in blob

    def test_identity_collapses_to_single_digest(self):
        raw = {
            "id": "i1", "type": 4, "name": "Me", "notes": None,
            "identity": {"firstName": "A", "lastName": "User", "ssn": SSN,
                         "email": "user@example.com"},
            "revisionDate": "2025-01-01T00:00:00.000Z",
        }
        s = sanitize_item(raw, H)
        assert s.identity_digest is not None
        assert SSN not in json.dumps(s.to_dict())

    def test_identity_digest_ignores_empty_fields(self):
        base = {"firstName": "A", "lastName": "User"}
        a = sanitize_item({"id": "i1", "type": 4, "name": "Me", "identity": dict(base),
                           "revisionDate": "2025-01-01T00:00:00.000Z"}, H)
        b = sanitize_item({"id": "i2", "type": 4, "name": "Me",
                           "identity": {**base, "ssn": None, "email": ""},
                           "revisionDate": "2025-01-01T00:00:00.000Z"}, H)
        assert a.identity_digest == b.identity_digest


class TestGroupingKeys:
    def test_login_keys_one_per_domain(self):
        raw = raw_login()
        raw["login"]["uris"].append({"match": None, "uri": "https://sso.github.io"})
        s = sanitize_item(raw, H)
        assert s.keys() == {
            ("login", "github.com", "user"),
            ("login", "github.io", "user"),
        }

    def test_login_without_uris_uses_name(self):
        raw = raw_login()
        raw["login"]["uris"] = []
        s = sanitize_item(raw, H)
        assert s.keys() == {("login:name", "github", "user")}

    def test_note_keys_by_normalized_name(self):
        raw = {"id": "n1", "type": 2, "name": "  WiFi  Home ", "notes": "x",
               "revisionDate": "2025-01-01T00:00:00.000Z"}
        assert sanitize_item(raw, H).keys() == {("note", "wifi home")}

    def test_card_keys_by_number_digest(self):
        raw = {"id": "c1", "type": 3, "name": "Visa",
               "card": {"number": CARD_NUMBER}, "revisionDate": "2025-01-01T00:00:00.000Z"}
        s = sanitize_item(raw, H)
        assert s.keys() == {("card", H.digest("card", "4111111111111234"))}

    def test_identity_keys_by_name(self):
        raw = {"id": "i1", "type": 4, "name": "Me", "identity": {"firstName": "A"},
               "revisionDate": "2025-01-01T00:00:00.000Z"}
        assert sanitize_item(raw, H).keys() == {("identity:name", "me")}


class TestSanitizeVault:
    def test_round_trips_through_dict(self):
        s = sanitize_item(raw_login(), H)
        assert SanitizedItem.from_dict(s.to_dict()) == s

    def test_skips_trashed_items(self):
        items = [raw_login(), raw_login(id="dead", deletedDate="2025-01-01T00:00:00.000Z")]
        out = sanitize_vault(items, H)
        assert [i.id for i in out] == ["11111111-aaaa-bbbb-cccc-000000000001"]

    def test_unknown_type_is_skipped_not_fatal(self):
        items = [raw_login(), {"id": "x", "type": 99, "name": "?",
                               "revisionDate": "2025-01-01T00:00:00.000Z"}]
        assert len(sanitize_vault(items, H)) == 1
