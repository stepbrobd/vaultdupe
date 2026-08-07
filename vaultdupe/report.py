"""Markdown report rendering.

Reports carry names, domains, usernames, and 8-char digest prefixes, never
plaintext secrets and never full digests. They are safe to read in a
terminal, an editor, or a chat window.
"""

from __future__ import annotations


def _short(digest: str | None) -> str:
    return f"#{digest[:8]}" if digest else "-"


def _table(headers: list, rows: list) -> str:
    if not rows:
        return "_none_\n"
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(c) if c not in (None, "") else "-" for c in row) + " |")
    return "\n".join(lines) + "\n"


def _flags(item) -> str:
    marks = []
    if item.passkeys:
        marks.append(f"passkey x{len(item.passkeys)}")
    if item.totp:
        marks.append("totp")
    if item.attachments:
        marks.append(f"attach x{len(item.attachments)}")
    if item.notes_digest:
        marks.append(f"notes({item.notes_len})")
    if item.fields:
        marks.append(f"fields x{len(item.fields)}")
    return " ".join(marks) or "-"


def render_dedupe_report(result) -> str:
    s = result.stats
    md = ["# Vaultwarden dedupe report", ""]
    md.append(_table(
        ["metric", "value"],
        [
            ["items scanned", s["items"]],
            ["duplicate groups", s["multi_item_groups"]],
            ["planned deletions (safe)", s["deletions"]],
            ["groups needing review", s["conflict_groups"]],
            ["items flagged for review", s["conflict_items"]],
        ],
    ))

    md.append(f"\n## Planned deletions ({len(result.deletions)})\n")
    md.append(
        "Soft-deleted to trash (recoverable in the web vault). Each row is fully\n"
        "covered by its keeper: same password, TOTP, and passkeys, or a strict subset.\n"
    )
    md.append(_table(
        ["name", "type", "reason", "keeper", "last modified", "id"],
        [
            [d["name"], d["type"], d["reason"], d["keeper_name"], d["revision"], f"`{d['id']}`"]
            for d in result.deletions
        ],
    ))

    conflicted = [g for g in result.groups if g.has_conflict]
    plural = "s" if len(conflicted) != 1 else ""
    md.append(f"\n## Conflicts to review ({len(conflicted)} group{plural})\n")
    if not conflicted:
        md.append("_none_\n")
    for g in conflicted:
        md.append(f"\n### `{g.label}`\n")
        for item_id, reason in g.conflict_reasons.items():
            name = result.items[item_id].name
            md.append(f"- **{name}** (`{item_id}`): {reason}")
        md.append("")
        rows = []
        for item_id in g.item_ids:
            it = result.items[item_id]
            role = (
                "KEEP" if item_id == g.keepers[0]
                else "keep (diverged)" if item_id in g.keepers
                else "delete" if item_id in g.deletions
                else "review"
            )
            rows.append([
                role, it.name, _short(it.password_digest),
                f"len {it.password_len}" if it.password_len else "-",
                _flags(it), ", ".join(it.domains) or "-",
                it.revision, f"`{it.id}`",
            ])
        md.append(_table(
            ["role", "name", "password", "pw len", "extras", "domains", "modified", "id"],
            rows,
        ))
    return "\n".join(md)


def render_diff_report(diff, *, vault_login_count: int, apple_count: int) -> str:
    md = ["# Vaultwarden vs Apple Passwords", ""]
    md.append(_table(
        ["metric", "value"],
        [
            ["Vaultwarden logins", vault_login_count],
            ["Apple entries (CSV)", apple_count],
            ["identical accounts", len(diff.identical)],
            ["password conflicts", len(diff.password_conflicts)],
            ["TOTP mismatches", len(diff.totp_mismatches)],
            ["Apple-only entries", len(diff.apple_only)],
            ["Vaultwarden-only logins", len(diff.vault_only)],
            ["Apple-internal duplicates", diff.apple_internal_dupes],
        ],
    ))

    md.append(f"\n## Password conflicts ({len(diff.password_conflicts)})\n")
    md.append("Same account, different stored password. Decide per row which side is current.\n")
    md.append(_table(
        ["account", "vault item", "vault pw", "apple pw", "vault modified"],
        [
            [c["account"], c["vault_name"],
             f"{_short(c['vault_digest'])} (len {c['vault_len']})",
             f"{_short(c['apple_digest'])} (len {c['apple_len']})",
             c.get("vault_revision") or "-"]
            for c in diff.password_conflicts
        ],
    ))

    md.append(f"\n## TOTP mismatches ({len(diff.totp_mismatches)})\n")
    md.append(_table(
        ["account", "vault TOTP", "apple TOTP"],
        [[m["account"], m["vault_totp"] or "missing", m["apple_totp"] or "missing"]
         for m in diff.totp_mismatches],
    ))

    md.append(f"\n## Apple-only entries ({len(diff.apple_only)})\n")
    md.append("In Apple Passwords and absent from Vaultwarden.\n")
    md.append(_table(
        ["title", "domain", "username", "totp", "notes chars"],
        [[e["name"], e["domain"], e["username"],
          "yes" if e["has_totp"] else "-", e["notes_len"] or "-"]
         for e in diff.apple_only],
    ))

    md.append(f"\n## Vaultwarden-only logins ({len(diff.vault_only)})\n")
    md.append(_table(
        ["name", "domains", "username", "totp", "passkeys"],
        [[e["name"], ", ".join(e["domains"]) or "-", e["username"],
          "yes" if e["has_totp"] else "-", "yes" if e["has_passkeys"] else "-"]
         for e in diff.vault_only],
    ))

    md.append(f"\n## Notes differences ({len(diff.notes_differ)})\n")
    md.append(
        "Accounts where Apple holds note text that Vaultwarden lacks or differs\n"
        "from (only checked where passwords already match).\n"
    )
    md.append(_table(
        ["account", "vault item", "vault notes chars", "apple notes chars"],
        [[n["account"], n["vault_name"], n["vault_notes_len"] or "-", n["apple_notes_len"]]
         for n in diff.notes_differ],
    ))

    md.append(f"\n## Passkey inventory, Vaultwarden side ({len(diff.passkey_inventory)})\n")
    md.append(
        "Apple's CSV export cannot include passkeys, so Apple-side passkeys are\n"
        "invisible here. Compare this list against Passwords.app manually, and use\n"
        "Apple's app-to-app credential exchange (FIDO CXF) to migrate passkeys.\n"
    )
    md.append(_table(
        ["relying party", "user", "item", "created"],
        [[p["rp_id"], p["user_name"], p["item_name"], p["created"] or "-"]
         for p in diff.passkey_inventory],
    ))

    md.append(f"\n## Apple-internal duplicates ({diff.apple_internal_dupes})\n")
    if diff.apple_dupe_groups:
        md.append("Duplicate accounts inside Apple Passwords itself:\n")
        for label in diff.apple_dupe_groups:
            md.append(f"- `{label}`")
        md.append("")
    else:
        md.append("_none_\n")
    return "\n".join(md)
