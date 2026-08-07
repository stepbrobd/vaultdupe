"""Tests for vaultdupe.diff, the Vaultwarden vs Apple Passwords comparison."""

from vaultdupe.apple import read_apple_csv
from vaultdupe.diff import diff_vault_vs_apple
from vaultdupe.sanitize import Hasher, SanitizedItem

H = Hasher(b"\x05" * 32)


def vault_login(id, *, name="Item", domains=("example.com",), username="u",
                password="pw", totp=None, notes=None, passkeys=(),
                revision="2025-01-01T00:00:00.000Z"):
    return SanitizedItem(
        id=id, type="login", name=name, revision=revision,
        username=username, domains=sorted(domains),
        uri_count=len(domains),
        password_digest=H.digest("password", password),
        password_len=len(password) if password else 0,
        totp={"digest": H.digest("totp", totp), "kind": "totp",
              "params": "totp/SHA1/6/30"} if totp else None,
        notes_digest=H.digest("note", notes),
        notes_len=len(notes) if notes else 0,
        passkeys=[{"credential_id": c, "rp_id": sorted(domains)[0],
                   "user_name": username, "created": None} for c in passkeys],
    )


def apple_login(n, *, name="Item", domain="example.com", username="u",
                password="pw", totp=None, notes=None):
    return SanitizedItem(
        id=f"apple:{n:04d}", type="login", name=name, revision="",
        username=username, domains=[domain] if domain else [],
        uri_count=1 if domain else 0,
        password_digest=H.digest("password", password),
        password_len=len(password) if password else 0,
        totp={"digest": H.digest("totp", totp), "kind": "totp",
              "params": "totp/SHA1/6/30"} if totp else None,
        notes_digest=H.digest("note", notes),
        notes_len=len(notes) if notes else 0,
    )


class TestMatching:
    def test_identical_account_lands_in_identical(self):
        d = diff_vault_vs_apple([vault_login("v1")], [apple_login(1)])
        assert [(m["vault_id"], m["apple_id"]) for m in d.identical] == [("v1", "apple:0001")]
        assert d.password_conflicts == []
        assert d.apple_only == [] and d.vault_only == []

    def test_subdomain_and_registrable_domain_still_match(self):
        v = vault_login("v1", domains=("google.com",))
        a = apple_login(1, domain="google.com")
        d = diff_vault_vs_apple([v], [a])
        assert len(d.identical) == 1

    def test_different_password_is_conflict_with_both_digests(self):
        v = vault_login("v1", password="old")
        a = apple_login(1, password="new")
        d = diff_vault_vs_apple([v], [a])
        (c,) = d.password_conflicts
        assert c["vault_digest"] == H.digest("password", "old")
        assert c["apple_digest"] == H.digest("password", "new")
        assert d.identical == []

    def test_unmatched_entries_split_into_only_lists(self):
        v = vault_login("v1", domains=("vaultonly.com",))
        a = apple_login(1, domain="appleonly.com")
        d = diff_vault_vs_apple([v], [a])
        assert [e["id"] for e in d.apple_only] == ["apple:0001"]
        assert [e["id"] for e in d.vault_only] == ["v1"]

    def test_name_fallback_matching_without_urls(self):
        v = vault_login("v1", name="My Router", domains=(), username="admin")
        a = apple_login(1, name="My Router", domain=None, username="admin")
        d = diff_vault_vs_apple([v], [a])
        assert len(d.identical) == 1

    def test_prefers_same_password_vault_item_when_multiple_match(self):
        v_old = vault_login("v-old", password="old")
        v_new = vault_login("v-new", password="new")
        a = apple_login(1, password="new")
        d = diff_vault_vs_apple([v_old, v_new], [a])
        assert [(m["vault_id"], m["apple_id"]) for m in d.identical] == [("v-new", "apple:0001")]
        # the other vault copy is matched-by-account, so it is NOT vault_only
        assert d.vault_only == []


class TestTotpAndNotes:
    def test_same_seed_is_not_a_mismatch(self):
        d = diff_vault_vs_apple([vault_login("v1", totp="S")], [apple_login(1, totp="S")])
        assert d.totp_mismatches == []

    def test_seed_only_on_one_side_is_mismatch(self):
        d = diff_vault_vs_apple([vault_login("v1", totp="S")], [apple_login(1)])
        (m,) = d.totp_mismatches
        assert m["vault_totp"] and not m["apple_totp"]

    def test_different_seeds_is_mismatch(self):
        d = diff_vault_vs_apple([vault_login("v1", totp="A")], [apple_login(1, totp="B")])
        assert len(d.totp_mismatches) == 1

    def test_notes_differ_only_when_passwords_match(self):
        d = diff_vault_vs_apple(
            [vault_login("v1", notes="vault note")], [apple_login(1, notes="apple note")]
        )
        assert len(d.notes_differ) == 1
        d2 = diff_vault_vs_apple(
            [vault_login("v1", password="x", notes="a")],
            [apple_login(1, password="y", notes="b")],
        )
        assert d2.notes_differ == []  # password conflict dominates


class TestInventory:
    def test_passkey_inventory_lists_vault_passkeys(self):
        v = vault_login("v1", passkeys=("c1", "c2"))
        d = diff_vault_vs_apple([v], [])
        assert len(d.passkey_inventory) == 2
        assert {p["rp_id"] for p in d.passkey_inventory} == {"example.com"}

    def test_apple_internal_duplicates_detected(self):
        a1 = apple_login(1)
        a2 = apple_login(2)  # same account, same password: a true Apple-side dup
        d = diff_vault_vs_apple([], [a1, a2])
        assert d.apple_internal_dupes >= 1

    def test_non_login_vault_items_are_ignored(self):
        note = SanitizedItem(id="n1", type="note", name="WiFi",
                             revision="2025-01-01T00:00:00.000Z",
                             notes_digest=H.digest("note", "x"), notes_len=1)
        d = diff_vault_vs_apple([note], [])
        assert d.vault_only == []
