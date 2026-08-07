"""Cross-manager comparison of sanitized Vaultwarden logins vs Apple CSV rows.

Both sides were digested with the same HMAC key, so same password or seed
means digest equality. Comparison is read only. The output is a worksheet,
never a mutation plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .dedupe import plan_dedupe


@dataclass
class DiffResult:
    identical: list = field(default_factory=list)
    password_conflicts: list = field(default_factory=list)
    totp_mismatches: list = field(default_factory=list)
    notes_differ: list = field(default_factory=list)
    apple_only: list = field(default_factory=list)
    vault_only: list = field(default_factory=list)
    passkey_inventory: list = field(default_factory=list)
    apple_internal_dupes: int = 0
    apple_dupe_groups: list = field(default_factory=list)


def _account_label(item) -> str:
    where = item.domains[0] if item.domains else item.name
    return f"{where} ({item.username})" if item.username else str(where)


def diff_vault_vs_apple(vault_items: list, apple_items: list) -> DiffResult:
    out = DiffResult()
    vault_logins = [i for i in vault_items if i.type == "login"]

    index = {}
    for v in vault_logins:
        for k in v.keys():
            index.setdefault(k, []).append(v)

    matched_vault_ids = set()
    for a in apple_items:
        seen, candidates = set(), []
        for k in a.keys():
            for v in index.get(k, []):
                if v.id not in seen:
                    seen.add(v.id)
                    candidates.append(v)

        if not candidates:
            out.apple_only.append(
                {
                    "id": a.id,
                    "name": a.name,
                    "domain": a.domains[0] if a.domains else None,
                    "username": a.username,
                    "has_totp": bool(a.totp),
                    "notes_len": a.notes_len,
                }
            )
            continue

        # every vault copy sharing the account key is accounted for
        # it must not resurface in vault_only because a sibling matched
        matched_vault_ids.update(v.id for v in candidates)
        v = next(
            (c for c in candidates if c.password_digest == a.password_digest),
            candidates[0],
        )
        account = _account_label(v)
        base = {"account": account, "vault_id": v.id, "vault_name": v.name, "apple_id": a.id}

        if v.password_digest == a.password_digest:
            out.identical.append(dict(base))
            if a.notes_digest and a.notes_digest != v.notes_digest:
                out.notes_differ.append(
                    dict(base, apple_notes_len=a.notes_len, vault_notes_len=v.notes_len)
                )
        else:
            out.password_conflicts.append(
                dict(
                    base,
                    vault_digest=v.password_digest,
                    apple_digest=a.password_digest,
                    vault_len=v.password_len,
                    apple_len=a.password_len,
                    vault_revision=v.revision,
                )
            )

        v_totp = v.totp["digest"] if v.totp else None
        a_totp = a.totp["digest"] if a.totp else None
        if v_totp != a_totp:
            out.totp_mismatches.append(
                dict(
                    base,
                    vault_totp=v.totp["params"] if v.totp else None,
                    apple_totp=a.totp["params"] if a.totp else None,
                )
            )

    for v in vault_logins:
        if v.id not in matched_vault_ids:
            out.vault_only.append(
                {
                    "id": v.id,
                    "name": v.name,
                    "domains": v.domains,
                    "username": v.username,
                    "has_totp": bool(v.totp),
                    "has_passkeys": bool(v.passkeys),
                }
            )

    for v in vault_logins:
        for p in v.passkeys:
            out.passkey_inventory.append(
                {
                    "rp_id": p.get("rp_id"),
                    "user_name": p.get("user_name"),
                    "item_id": v.id,
                    "item_name": v.name,
                    "created": p.get("created"),
                }
            )

    apple_plan = plan_dedupe(apple_items)
    out.apple_internal_dupes = (
        apple_plan.stats["deletions"] + apple_plan.stats["conflict_items"]
    )
    out.apple_dupe_groups = [g.label for g in apple_plan.groups]

    for lst, key in (
        (out.identical, "account"),
        (out.password_conflicts, "account"),
        (out.totp_mismatches, "account"),
        (out.notes_differ, "account"),
        (out.apple_only, "name"),
        (out.vault_only, "name"),
        (out.passkey_inventory, "rp_id"),
    ):
        lst.sort(key=lambda e: str(e.get(key) or ""))
    return out
