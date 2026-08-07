# vault-dedupe

Deduplicate a Vaultwarden vault and reconcile it with Apple Passwords.
Built for vaults with thousands of entries. Secrets are replaced by keyed
HMAC-SHA256 digests at ingest, so comparison, reporting, and planning all
operate on digests and plaintext never touches disk.

## Security model

- `fetch` pipes `bw list items` output into the sanitizer in memory. What
  lands in `work/` is digest data plus account metadata (names, domains,
  usernames).
- Each secret (password, TOTP seed, note body, card number, hidden field,
  identity content) becomes `HMAC-SHA256(key, kind || 0x00 || value)`,
  keyed by 32 random bytes in `work/.hmac-key` (mode 600). Equal secrets
  produce equal digests, which is all dedupe and diff need. The digest
  files are useless for offline guessing without the key file.
- An Apple Passwords CSV is ingested with the same key, so cross-manager
  equality is digest equality. `--shred-csv` overwrites and deletes the
  CSV after ingest.
- Deletions are soft. `apply` re-syncs first, skips anything whose
  revisionDate changed since planning, verifies with a canary that the
  first deletion landed in trash, and routes bulk deletions through a
  temporary local `bw serve` so thousands of deletions take minutes
  instead of an hour. Interrupting `apply` is safe and re-running it
  resumes.

## Dedupe rules

Items group by identity key: logins by (registrable domain, username)
with multi-URI items bridging groups, notes by name, cards by number,
identities by name. Inside a group:

- An item is deleted only when a kept item carries a superset of its
  data: same password, same or absent TOTP seed, same or absent passkey
  credential ids, covered domains, same or absent notes and custom
  fields. The keeper is the richest copy (passkeys, then TOTP seeds,
  then attachments, then notes and password history), newest on ties.
- Flagged for review and never deleted: different passwords, different
  TOTP seeds, distinct passkey credential ids, unique notes or fields,
  anything with attachments, anything org-owned.

## Requirements

- nix (`shell.nix` supplies `bw` and Python with tldextract and pytest)
- a Bitwarden-compatible server reachable with the `bw` CLI
- macOS for the Apple Passwords side (CSV export and import live in
  Passwords.app)

## Usage

`nix-shell` starts a bash environment with the tools on PATH. From
Nushell, enter it first:

```nu
cd vault-dedupe
nix-shell
```

Inside the shell (bash):

```sh
# first time only
bw config server https://vault.example.com
bw login

# every session
export BW_SESSION="$(bw unlock --raw)"

python3 -m vaultdupe fetch        # vault -> work/vault.json (digests only)
python3 -m vaultdupe dedupe       # -> work/dedupe-report.md + plan.json
python3 -m vaultdupe apply        # soft-delete planned items, confirms first

# Apple side: Passwords.app -> File -> Export -> Passwords... (CSV)
python3 -m vaultdupe diff-apple Passwords.csv --shred-csv

# generate an Apple-format import CSV, OTPAuth seeds included
python3 -m vaultdupe export-apple

python3 -m vaultdupe shred        # destroy work/ when done
```

`./vd <cmd>` wraps a command in `nix-shell`. `--server` pins the expected
server URL. Without it the tool adopts whatever server `bw` is configured
with.

## Reports

- `work/dedupe-report.md` lists planned deletions with keeper and reason,
  and conflict groups for human review. Passwords appear as
  `#8-char-digest (len N)`.
- `work/diff-report.md` sections: identical accounts, password conflicts,
  TOTP mismatches, Apple-only entries, Vaultwarden-only logins, note
  differences, passkey inventory, Apple-internal duplicates.

## Apple Passwords notes

- Apple's CSV export contains no passkeys and no timestamps. The diff
  reports the Vaultwarden passkey inventory instead. Passkeys move only
  through Apple's app-to-app credential exchange (FIDO CXF).
- Apple's import is an upsert keyed by (site, username). Importing the
  `export-apple` CSV adds missing entries, attaches TOTP seeds, and
  no-ops identical rows. Re-importing it is idempotent. Importing the
  same file into Bitwarden twice is how vaults end up quadrupled.
- Deleting a duplicate discards that copy's password history. The kept
  item's history survives.

## Development

```sh
nix-shell --run 'python3 -m pytest tests/'
```

The keep-or-delete policy is `richness_score` in `vaultdupe/dedupe.py`.
