"""Duplicate detection and deletion planning over sanitized items.

Safety invariant: an item is queued for deletion only when some kept item
carries a superset of its information (the adds-nothing rule), and never
when it has attachments or belongs to an organization. Those cases are
flagged as conflicts for human review instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


def richness_score(item) -> int:
    """Rank which copy of a duplicate is worth keeping.

    Passkeys cannot be re-exported, so they weigh most, then TOTP seeds,
    then attachments.
    """
    return (
        len(item.passkeys) * 8
        + (4 if item.totp else 0)
        + len(item.attachments) * 3
        + (2 if item.password_digest else 0)
        + (2 if item.notes_digest else 0)
        + len(item.fields)
        + (1 if item.favorite else 0)
        + item.uri_count
        # capped so history preference cannot override a content difference
        # while an original still beats its freshly imported history-less twin
        + min(item.history_count, 3)
    )


def _ts(iso: str) -> float:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return 0.0


def _fieldset(item) -> set:
    return {(f["name"], f["value_digest"]) for f in item.fields}


def _credset(item) -> set:
    return {p["credential_id"] for p in item.passkeys}


def covered_by(d, k) -> tuple[bool, str]:
    """Does keeper k carry everything d has? Returns (ok, reason_if_not).

    A None or absent value on d never blocks coverage, absence adds
    nothing. Attachments and org ownership are deliberately not part of
    coverage. They are guardrails handled by the caller.
    """
    if d.username != k.username:
        return False, "username differs"

    if d.type == "login":
        if d.password_digest and d.password_digest != k.password_digest:
            return False, "password differs"
        if d.passkeys and not _credset(d) <= _credset(k):
            return False, "has passkey(s) the keeper lacks"
        if d.totp and (k.totp is None or d.totp["digest"] != k.totp["digest"]):
            return False, "has a TOTP seed the keeper lacks or differs from"
        if d.domains and not set(d.domains) <= set(k.domains):
            return False, "matches domains the keeper does not cover"
    elif d.type == "card":
        dc, kc = d.card or {}, k.card or {}
        for key, label in (
            ("number_digest", "card number"),
            ("code_digest", "security code"),
            ("exp", "expiry"),
            ("holder", "cardholder"),
        ):
            dv, kv = dc.get(key), kc.get(key)
            if isinstance(dv, str) and isinstance(kv, str) and key == "holder":
                dv, kv = dv.strip().lower(), kv.strip().lower()
            if dv and dv != kv:
                return False, f"{label} differs"
    elif d.type == "identity":
        if d.identity_digest and d.identity_digest != k.identity_digest:
            return False, "identity content differs"

    if d.notes_digest and d.notes_digest != k.notes_digest:
        return False, "note content differs"
    if d.fields and not _fieldset(d) <= _fieldset(k):
        return False, "has custom fields the keeper lacks"
    return True, ""


@dataclass
class GroupDecision:
    label: str
    item_ids: list
    keepers: list
    deletions: list  # ids
    conflicts: list  # ids needing human review
    conflict_reasons: dict  # id -> reason
    has_conflict: bool = False


@dataclass
class DedupeResult:
    groups: list  # GroupDecision, multi-item groups only
    deletions: list  # flat dicts, ready for plan.json
    items: dict  # id -> SanitizedItem, for report rendering
    stats: dict = field(default_factory=dict)


def _union_groups(items) -> list:
    parent = list(range(len(items)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    seen = {}
    for i, it in enumerate(items):
        for key in it.keys():
            if key in seen:
                union(seen[key], i)
            else:
                seen[key] = i

    groups = {}
    for i in range(len(items)):
        groups.setdefault(find(i), []).append(items[i])
    return [g for g in groups.values() if len(g) > 1]


def plan_dedupe(items: list) -> DedupeResult:
    groups_out, deletions_flat = [], []

    for members in _union_groups(items):
        ordered = sorted(
            members,
            key=lambda it: (-richness_score(it), -_ts(it.revision), -it.uri_count, it.id),
        )
        keepers, deletions, conflicts, reasons = [], [], [], {}

        for it in ordered:
            keeper, blocked_reason = None, ""
            for k in keepers:
                ok, why = covered_by(it, k)
                if ok:
                    keeper = k
                    break
                if not blocked_reason:
                    blocked_reason = why
            if keeper is None:
                if keepers:  # an extra keeper is genuine divergence to review
                    conflicts.append(it.id)
                    reasons[it.id] = f"{blocked_reason}, review vs kept item '{keepers[0].name}'"
                keepers.append(it)
                continue

            if it.attachments:
                conflicts.append(it.id)
                reasons[it.id] = (
                    f"duplicate of '{keeper.name}' with attachment(s) "
                    f"{it.attachments}, move them manually before deleting"
                )
            elif it.org_id:
                conflicts.append(it.id)
                reasons[it.id] = (
                    f"duplicate of '{keeper.name}', org-owned, not auto-deleted"
                )
            else:
                mutual, _ = covered_by(keeper, it)
                reason = (
                    f"exact duplicate of '{keeper.name}'"
                    if mutual
                    else f"adds nothing beyond richer copy '{keeper.name}'"
                )
                deletions.append(it.id)
                deletions_flat.append(
                    {
                        "id": it.id,
                        "name": it.name,
                        "type": it.type,
                        "revision": it.revision,
                        "keeper_id": keeper.id,
                        "keeper_name": keeper.name,
                        "reason": reason,
                    }
                )

        primary_key = sorted(keepers[0].keys())[0]
        label = "/".join(str(p) for p in primary_key)
        groups_out.append(
            GroupDecision(
                label=label,
                item_ids=[it.id for it in ordered],
                keepers=[k.id for k in keepers],
                deletions=deletions,
                conflicts=conflicts,
                conflict_reasons=reasons,
                has_conflict=bool(conflicts) or len(keepers) > 1,
            )
        )

    groups_out.sort(key=lambda g: g.label)
    deletions_flat.sort(key=lambda d: (d["type"], d["name"], d["id"]))
    return DedupeResult(
        groups=groups_out,
        deletions=deletions_flat,
        items={it.id: it for it in items},
        stats={
            "items": len(items),
            "multi_item_groups": len(groups_out),
            "deletions": len(deletions_flat),
            "conflict_groups": sum(1 for g in groups_out if g.has_conflict),
            "conflict_items": sum(len(g.conflicts) for g in groups_out),
        },
    )
