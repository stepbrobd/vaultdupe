"""Tests for vaultdupe.dedupe: grouping, keeper choice, deletion safety.

The invariant under test: an item is only ever queued for deletion when a
kept item carries a superset of its information (the adds-nothing rule),
and guarded items (attachments, org-owned) are flagged instead of deleted.
"""

from vaultdupe.dedupe import plan_dedupe, richness_score
from vaultdupe.sanitize import Hasher, SanitizedItem

H = Hasher(b"\x07" * 32)


def item(
    id,
    *,
    type="login",
    name="Site",
    domains=("example.com",),
    username="u",
    password="pw1",
    totp=None,
    passkeys=(),
    notes=None,
    fields=(),
    attachments=(),
    org=None,
    favorite=False,
    revision="2025-01-01T00:00:00.000Z",
    uri_count=None,
):
    return SanitizedItem(
        id=id,
        type=type,
        name=name,
        revision=revision,
        org_id=org,
        favorite=favorite,
        notes_digest=H.digest("note", notes),
        notes_len=len(notes) if notes else 0,
        fields=[{"name": n, "type": 1, "value_digest": H.digest("field", v)} for n, v in fields],
        attachments=list(attachments),
        username=username,
        domains=sorted(domains),
        uri_count=uri_count if uri_count is not None else len(domains),
        password_digest=H.digest("password", password),
        password_len=len(password) if password else 0,
        totp={"digest": H.digest("totp", totp), "kind": "totp", "params": "totp/SHA1/6/30"}
        if totp
        else None,
        passkeys=[
            {"credential_id": c, "rp_id": "example.com", "user_name": username, "created": None}
            for c in passkeys
        ],
    )


def note(id, name, body, **kw):
    return item(id, type="note", name=name, domains=(), username="", password=None,
                notes=body, **kw)


def deleted_ids(result):
    return {d["id"] for d in result.deletions}


def conflict_ids(result):
    return {cid for g in result.groups for cid in g.conflicts}


class TestExactDuplicates:
    def test_richer_copy_kept_poorer_deleted(self):
        a = item("a", totp="SEED")  # richer, has TOTP
        b = item("b")
        r = plan_dedupe([a, b])
        assert deleted_ids(r) == {"b"}
        assert r.groups[0].keepers == ["a"]

    def test_on_equal_richness_newest_revision_wins(self):
        a = item("a", revision="2024-01-01T00:00:00.000Z")
        b = item("b", revision="2025-06-01T00:00:00.000Z")
        r = plan_dedupe([a, b])
        assert deleted_ids(r) == {"a"}

    def test_exact_duplicate_reason_recorded(self):
        a, b = item("a"), item("b", revision="2024-01-01T00:00:00.000Z")
        r = plan_dedupe([a, b])
        (d,) = r.deletions
        assert d["keeper_id"] == "a"
        assert "duplicate" in d["reason"]

    def test_three_way_duplicates_single_keeper(self):
        r = plan_dedupe([item("a", totp="S"), item("b"), item("c")])
        assert deleted_ids(r) == {"b", "c"}


class TestSubsetRule:
    def test_copy_without_totp_superseded_by_copy_with_totp(self):
        r = plan_dedupe([item("rich", totp="S", notes="hi"), item("poor")])
        assert deleted_ids(r) == {"poor"}

    def test_copy_with_unique_totp_is_conflict_not_deletion(self):
        # rich scores higher, but poor's seed differs
        # deleting poor would destroy a working seed
        rich = item("rich", totp="SEED-A", notes="x", fields=(("f", "v"),))
        poor = item("poor", totp="SEED-B")
        r = plan_dedupe([rich, poor])
        assert deleted_ids(r) == set()
        assert conflict_ids(r) == {"poor"} or set(r.groups[0].keepers) == {"rich", "poor"}

    def test_missing_password_superseded_by_full_copy(self):
        r = plan_dedupe([item("full"), item("empty", password=None)])
        assert deleted_ids(r) == {"empty"}

    def test_domain_not_covered_by_keeper_blocks_deletion(self):
        wide = item("wide", domains=("example.com", "other.com"))
        rich = item("rich", domains=("example.com",), totp="S")
        r = plan_dedupe([wide, rich])
        assert deleted_ids(r) == set()
        assert len(r.groups[0].keepers) == 2

    def test_narrow_domain_copy_superseded_by_wide_copy(self):
        wide = item("wide", domains=("example.com", "other.com"))
        narrow = item("narrow", domains=("example.com",))
        r = plan_dedupe([wide, narrow])
        assert deleted_ids(r) == {"narrow"}
        assert r.groups[0].keepers == ["wide"]

    def test_notes_differing_blocks_deletion(self):
        r = plan_dedupe([item("a", notes="alpha"), item("b", notes="beta")])
        assert deleted_ids(r) == set()

    def test_unique_field_blocks_deletion(self):
        a = item("a", totp="S")
        b = item("b", fields=(("recovery", "codes"),))
        r = plan_dedupe([a, b])
        assert deleted_ids(r) == set()


class TestPasswordConflicts:
    def test_different_password_same_account_is_conflict(self):
        r = plan_dedupe([item("a", password="one"), item("b", password="two")])
        assert deleted_ids(r) == set()
        g = r.groups[0]
        assert set(g.keepers) == {"a", "b"}
        assert g.has_conflict

    def test_true_dup_still_deleted_inside_conflicted_group(self):
        # a and b share a password while c has a different one
        # b is a's exact dup and must still be deleted
        # a vs c stays for human review
        a = item("a", password="one", totp="S")
        b = item("b", password="one")
        c = item("c", password="two", totp="S", notes="n", fields=(("x", "y"),))
        r = plan_dedupe([a, b, c])
        assert deleted_ids(r) == {"b"}
        assert set(r.groups[0].keepers) == {"c", "a"}


class TestPasskeys:
    def test_same_credential_id_set_is_duplicate(self):
        r = plan_dedupe([item("a", passkeys=("c1",), totp="S"), item("b", passkeys=("c1",))])
        assert deleted_ids(r) == {"b"}

    def test_unique_passkey_blocks_deletion(self):
        # different credentialIds are different real passkeys even for the
        # same site and user, both must survive
        r = plan_dedupe([item("a", passkeys=("c1",), totp="S"), item("b", passkeys=("c2",))])
        assert deleted_ids(r) == set()

    def test_item_without_passkey_superseded_by_item_with(self):
        r = plan_dedupe([item("a", passkeys=("c1",)), item("b")])
        assert deleted_ids(r) == {"b"}


class TestGuardrails:
    def test_attachments_never_auto_deleted(self):
        dup = item("dup", attachments=("backup.txt",))
        keeper = item("keeper", totp="S")
        r = plan_dedupe([keeper, dup])
        assert deleted_ids(r) == set()
        assert "dup" in conflict_ids(r)
        assert "attachment" in r.groups[0].conflict_reasons["dup"].lower()

    def test_org_items_never_auto_deleted(self):
        dup = item("dup", org="org-1")
        keeper = item("keeper", totp="S")
        r = plan_dedupe([keeper, dup])
        assert deleted_ids(r) == set()
        assert "dup" in conflict_ids(r)


class TestGrouping:
    def test_different_usernames_never_group(self):
        r = plan_dedupe([item("a", username="u1"), item("b", username="u2")])
        assert r.groups == []
        assert deleted_ids(r) == set()

    def test_different_domains_never_group(self):
        r = plan_dedupe([item("a", domains=("x.com",)), item("b", domains=("y.com",))])
        assert r.groups == []

    def test_multi_uri_item_bridges_groups(self):
        # b lists both domains and must pull a and c into one group
        a = item("a", domains=("x.com",))
        b = item("b", domains=("x.com", "y.com"), totp="S")
        c = item("c", domains=("y.com",))
        r = plan_dedupe([a, b, c])
        assert len(r.groups) == 1
        assert deleted_ids(r) == {"a", "c"}

    def test_singletons_produce_no_groups(self):
        r = plan_dedupe([item("a")])
        assert r.groups == []
        assert r.stats["multi_item_groups"] == 0


class TestNotesCardsIdentities:
    def test_identical_notes_deduped_newest_kept(self):
        r = plan_dedupe([
            note("old", "WiFi", "pass123", revision="2024-01-01T00:00:00.000Z"),
            note("new", "WiFi", "pass123", revision="2025-01-01T00:00:00.000Z"),
        ])
        assert deleted_ids(r) == {"old"}

    def test_same_name_different_content_is_conflict(self):
        r = plan_dedupe([note("a", "WiFi", "pass123"), note("b", "WiFi", "pass456")])
        assert deleted_ids(r) == set()
        assert r.groups[0].has_conflict

    def test_cards_with_same_number_dedupe(self):
        a = SanitizedItem(id="a", type="card", name="Visa", revision="2025-01-01T00:00:00.000Z",
                          card={"number_digest": H.digest("card", "4111"), "code_digest": H.digest("card-code", "987"),
                                "last4": "4111", "brand": "Visa", "exp": "4/2030", "holder": None})
        b = SanitizedItem(id="b", type="card", name="Visa spare", revision="2024-01-01T00:00:00.000Z",
                          card={"number_digest": H.digest("card", "4111"), "code_digest": H.digest("card-code", "987"),
                                "last4": "4111", "brand": "Visa", "exp": "4/2030", "holder": None})
        r = plan_dedupe([a, b])
        assert deleted_ids(r) == {"b"}

    def test_cards_with_different_cvv_conflict(self):
        a = SanitizedItem(id="a", type="card", name="Visa", revision="2025-01-01T00:00:00.000Z",
                          card={"number_digest": H.digest("card", "4111"), "code_digest": H.digest("card-code", "111"),
                                "last4": "4111", "brand": None, "exp": None, "holder": None})
        b = SanitizedItem(id="b", type="card", name="Visa", revision="2024-01-01T00:00:00.000Z",
                          card={"number_digest": H.digest("card", "4111"), "code_digest": H.digest("card-code", "222"),
                                "last4": "4111", "brand": None, "exp": None, "holder": None})
        r = plan_dedupe([a, b])
        assert deleted_ids(r) == set()


class TestImportFlood:
    def test_original_with_password_history_beats_newer_identical_import(self):
        # the apple-to-bitwarden import scenario
        # the imported copy is identical in content but has the newest
        # revision and no password history
        # the original with its history must win keeper selection
        original = item("orig", revision="2025-01-01T00:00:00.000Z")
        original.history_count = 4
        imported = item("imp", revision="2026-08-08T00:00:00.000Z")
        r = plan_dedupe([original, imported])
        assert deleted_ids(r) == {"imp"}
        assert r.groups[0].keepers == ["orig"]

    def test_without_history_newest_still_wins(self):
        a = item("a", revision="2024-01-01T00:00:00.000Z")
        b = item("b", revision="2025-06-01T00:00:00.000Z")
        assert deleted_ids(plan_dedupe([a, b])) == {"a"}


class TestRichnessScore:
    def test_passkey_outweighs_totp_outweighs_notes(self):
        assert richness_score(item("p", passkeys=("c1",))) > richness_score(item("t", totp="S"))
        assert richness_score(item("t", totp="S")) > richness_score(item("n", notes="x"))

    def test_favorite_breaks_ties(self):
        assert richness_score(item("f", favorite=True)) > richness_score(item("g"))
