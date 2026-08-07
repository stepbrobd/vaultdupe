"""Tests for vaultdupe.normalize, the URL, username, and TOTP rules.

These functions define what "the same site, the same account, the same
TOTP seed" mean for the whole pipeline, so every rule is pinned here.
"""

import pytest

from vaultdupe.normalize import (
    login_keys,
    norm_name,
    norm_username,
    parse_totp,
    registrable_domain,
)


class TestRegistrableDomain:
    def test_subdomain_collapses_to_registrable_domain(self):
        assert registrable_domain("https://accounts.google.com/signin") == "google.com"

    def test_www_prefix_collapses(self):
        assert registrable_domain("http://www.example.com") == "example.com"

    def test_multi_part_public_suffix_is_respected(self):
        # co.uk is a public suffix, so amazon.co.uk is the registrable
        # domain and two different co.uk sites must not collapse together
        assert registrable_domain("http://www.amazon.co.uk/gp") == "amazon.co.uk"
        assert registrable_domain("https://sub.foo.co.uk") == "foo.co.uk"
        assert registrable_domain("https://bar.co.uk") != registrable_domain(
            "https://foo.co.uk"
        )

    def test_bare_host_without_scheme(self):
        assert registrable_domain("google.com") == "google.com"
        assert registrable_domain("sub.foo.co.uk") == "foo.co.uk"

    def test_ipv4_host_kept_verbatim_with_port_stripped(self):
        assert registrable_domain("https://192.168.1.10:8080/admin") == "192.168.1.10"

    def test_localhost_and_single_label_hosts_kept(self):
        assert registrable_domain("http://localhost:3000") == "localhost"
        assert registrable_domain("http://nas") == "nas"

    def test_android_app_uri_kept_as_scheme_qualified_key(self):
        assert (
            registrable_domain("androidapp://com.netflix.mediaclient")
            == "androidapp://com.netflix.mediaclient"
        )

    def test_case_is_normalized(self):
        assert registrable_domain("HTTPS://Accounts.GOOGLE.com") == "google.com"

    def test_empty_and_none_return_none(self):
        assert registrable_domain("") is None
        assert registrable_domain(None) is None
        assert registrable_domain("   ") is None

    def test_unparseable_value_falls_back_to_lowered_trimmed_string(self):
        # garbage must still produce a stable key so identical garbage groups
        assert registrable_domain("  My NAS Box  ") == "my nas box"


class TestNormUsername:
    def test_lowercases_and_strips(self):
        assert norm_username("  User@Example.COM ") == "user@example.com"

    def test_none_becomes_empty(self):
        assert norm_username(None) == ""


class TestNormName:
    def test_collapses_whitespace_and_lowercases(self):
        assert norm_name("  GitHub   (old) ") == "github (old)"

    def test_none_becomes_empty(self):
        assert norm_name(None) == ""


class TestParseTotp:
    def test_raw_base32_secret_gets_defaults(self):
        t = parse_totp("jbswy3dpehpk3pxp")
        assert t.secret == "JBSWY3DPEHPK3PXP"
        assert t.algorithm == "SHA1"
        assert t.digits == 6
        assert t.period == 30
        assert t.kind == "totp"

    def test_spaces_and_padding_are_stripped_from_secret(self):
        a = parse_totp("jbsw y3dp ehpk 3pxp")
        b = parse_totp("JBSWY3DPEHPK3PXP======")
        assert a.secret == b.secret == "JBSWY3DPEHPK3PXP"

    def test_full_otpauth_uri(self):
        t = parse_totp(
            "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
        )
        assert t.secret == "JBSWY3DPEHPK3PXP"
        assert (t.algorithm, t.digits, t.period) == ("SHA1", 6, 30)

    def test_otpauth_uri_with_explicit_params(self):
        t = parse_totp(
            "otpauth://totp/X?secret=ABCDEFGH&algorithm=SHA256&digits=8&period=60"
        )
        assert (t.algorithm, t.digits, t.period) == ("SHA256", 8, 60)

    def test_raw_secret_and_uri_with_same_seed_are_canonically_equal(self):
        raw = parse_totp("JBSWY3DPEHPK3PXP")
        uri = parse_totp("otpauth://totp/GitHub:user?secret=jbswy3dpehpk3pxp")
        assert raw.canonical() == uri.canonical()

    def test_different_params_are_not_canonically_equal(self):
        a = parse_totp("otpauth://totp/X?secret=ABCDEFGH&digits=6")
        b = parse_totp("otpauth://totp/X?secret=ABCDEFGH&digits=8")
        assert a.canonical() != b.canonical()

    def test_steam_uri(self):
        t = parse_totp("steam://STEAMKEY123")
        assert t.kind == "steam"
        assert t.secret == "STEAMKEY123"

    def test_empty_and_none_return_none(self):
        assert parse_totp(None) is None
        assert parse_totp("") is None
        assert parse_totp("   ") is None


class TestLoginKeys:
    def test_one_key_per_distinct_domain(self):
        keys = login_keys(
            uris=["https://accounts.google.com", "https://mail.google.com",
                  "https://github.com/login"],
            username="User",
            name="whatever",
        )
        assert keys == {
            ("login", "google.com", "user"),
            ("login", "github.com", "user"),
        }

    def test_no_uris_falls_back_to_item_name(self):
        keys = login_keys(uris=[], username="root", name="  My NAS  ")
        assert keys == {("login:name", "my nas", "root")}

    def test_blank_uris_are_ignored(self):
        keys = login_keys(uris=["", "  "], username="u", name="Fallback")
        assert keys == {("login:name", "fallback", "u")}
