"""Work directory storage: HMAC key, sanitized datasets, plans, shredding.

Everything in work/ is either the HMAC key (0600, never leaves the machine)
or hash-only sanitized data. shred_work still overwrites before unlinking
as defense in depth, with the caveat that on APFS/SSD real erasure comes
from FileVault rather than overwrites.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .sanitize import SanitizedItem


def ensure_key(work: Path | str) -> bytes:
    work = Path(work)
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(work, 0o700)  # mkdir mode is umask-filtered, force it
    key_file = work / ".hmac-key"
    if key_file.exists():
        key = key_file.read_bytes()
        if len(key) >= 16:
            return key
    key = os.urandom(32)
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    os.chmod(key_file, 0o600)
    return key


def save_dataset(path: Path | str, items: list, meta: dict) -> None:
    payload = {"meta": meta, "items": [i.to_dict() for i in items]}
    Path(path).write_text(json.dumps(payload, indent=1))


def load_dataset(path: Path | str) -> dict:
    payload = json.loads(Path(path).read_text())
    payload["items"] = [SanitizedItem.from_dict(d) for d in payload["items"]]
    return payload


def save_plan(path: Path | str, *, deletions: list, stats: dict, meta: dict) -> None:
    Path(path).write_text(
        json.dumps({"meta": meta, "stats": stats, "deletions": deletions}, indent=1)
    )


def load_plan(path: Path | str) -> dict:
    return json.loads(Path(path).read_text())


def shred_file(path: Path | str) -> None:
    path = Path(path)
    size = path.stat().st_size
    with open(path, "r+b") as f:
        f.write(os.urandom(size))
        f.flush()
        os.fsync(f.fileno())
    path.unlink()


def shred_work(work: Path | str) -> int:
    """Overwrite and remove every file under work/, then remove the tree.

    Returns the number of files shredded.
    """
    work = Path(work)
    if not work.exists():
        return 0
    count = 0
    for path in sorted(work.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if path.is_file() or path.is_symlink():
            try:
                shred_file(path)
            except OSError:
                path.unlink(missing_ok=True)
            count += 1
        elif path.is_dir():
            path.rmdir()
    work.rmdir()
    return count
