# Signed audit checkpoints (BTD-37)

The hash chain of the audit log (BTD-29, `lib/audit.h`) detects a changed, deleted or reordered
entry, but not a chain whose hashes were recomputed after a change. Signed checkpoints close that
gap for every entry that a later checkpoint covers (PLAN.md section 6.3).

## What is written

| Entry action | When | Params |
|---|---|---|
| `audit.key_create` | before the first checkpoint, and on each key rotation | `key_id`, `key_type` (`ED25519`; entries before BTD-97 have `ed25519`), `public_key` (PEM), `adopted_entries` (only on a first key that adopted an unsigned log, see below) |
| `audit.checkpoint` | after every N entries (database setting `audit_checkpoint_interval`, default 100, at most 1000: the setting is not signed), before each export unless the newest entry is a checkpoint, on `AuditLog::checkpoint()` and `AuditLog::rotateKey()` | `checkpoint_seq`, `checkpoint_hash`, `checkpoint_time`, `key_id`, `next_key_id` (rotation only), `signature` |

A checkpoint signs the entry just before it: `checkpoint_seq` and `checkpoint_hash` are that
entry's `seq` and `hash`. The signature (Base64, Ed25519) covers the canonical JSON (RFC 8785) of
the checkpoint's params without `signature`. `key_id` is the lowercase hex SHA-256 of the DER
public key.

The audit key lives in the table `audit_keys`, not in `items`, so no key list, dialog, export or
delete function shows it. Its private part is encrypted with the database password like every
other private key. Certificate issuance and renewal, CSR creation and CRL generation refuse a key
whose public key is an audit key with the error code `audit_key` (for a key copied out of the
database and imported). The guard sits where XCA signs, so every caller is covered:
`pki_x509::sign()` (issuance and the renewal dialog), `pki_x509req::createReq()` and
`pki_crl::sign()`. A rotation announces the new key and signs a checkpoint with the old key that
names it in `next_key_id`; the old key's private part is then deleted. A changed database password
re-encrypts the audit key (`MainWindow::changeDbPass`).

Without the database password (`xca --no-gui` without `--password`, or the unlock dialog
cancelled) no automatic checkpoint is written, the entry itself is, and the next entry tries
again. Automatic checkpoints never ask for the password; an explicit checkpoint, a rotation and
`--audit-export` do. An automatic checkpoint prepares everything that can fail (password, key
generation, signature) before its first write, so such a failure keeps the caller's change; a
database error while it writes fails the caller's operation (BTD-111) when the entry belongs to
the caller's transaction. An entry outside any transaction, such as the failure entry a service
function appends after its rollback, is already committed: the checkpoint failure is only logged,
the caller keeps its own error code, and the next entry tries again (BTD-143).

Entries after a change that does not chain are never signed (`audit_chain_broken`). Once the chain
announced a key, a checkpoint without a usable current key (row deleted, retired without
successor, private part gone) fails with `audit_key_missing` and creates no new key (BTD-110).

An automatic checkpoint that failed for such a state (a broken chain, a missing key, a key that
does not decrypt) is not tried again for every following entry: each try scans the whole unsigned
part, so an import would take quadratic time and log one line per entry. The next try comes when
a new checkpoint changes the head, after an explicit checkpoint, rotation or adoption, after a
change of the database password, or when the database is opened again (BTD-144). A missing or
wrong password source is tried again with the next entry, since that try scans nothing.

The first key is not announced over a log whose unsigned part is longer than any writer with the
database password leaves (more than interval + 1 entries, the revocation baseline excepted): such
a log looks exactly like one whose checkpoints and keys were deleted and rehashed. The automatic
checkpoint is skipped, an explicit checkpoint, rotation or export fails with
`audit_checkpoint_missing`, and `--audit-verify` keeps reporting `checkpoint_missing`. A log that
was really written without the password (e.g. `xca --no-gui` without `--password`) is signed only
on request, after it was checked:

```
xca --no-gui --database pki.xdb --password file:db.pass --audit-adopt --audit-verify
```

A skipped automatic checkpoint is reported to the user (BTD-148), once per error code and open
database: the GUI shows it in the status bar (no dialog, the work goes on), `xca --no-gui` prints
one `Notice:` line on stderr per command. The notice names the code and the next step:

| Code | Next step named in the notice |
|---|---|
| `audit_key_unavailable` | open the database with its password |
| `audit_password_rejected` | check the password source |
| `audit_checkpoint_missing` | check the log with `--audit-verify`, then sign it with `--audit-adopt` |
| `audit_key_missing` | run `--audit-verify`; restore the audit key from a backup of the database |
| `audit_signing_failed`, `audit_key_failed`, any other | run `--audit-verify`; the message carries the OpenSSL reason |

The exit code of the command stays 0: its own operation succeeded and its entry is stored. Scripts
that must not go on with an unsigned tail run `--audit-verify`. The log line
(`No audit checkpoint after entry`) remains and carries the code as well.

`--audit-adopt` (`AuditLog::adoptUnanchored()`) announces the first key with `adopted_entries`,
the number of entries it takes over without proof, and signs. The announcement is covered by the
checkpoint, so the mark cannot be removed later, and `--audit-verify` reports it as
`adopted_entries`.

## Export with and without a password

| `--audit-export` | Result |
|---|---|
| with `--password` (or an unlocked database) | signs a checkpoint over the newest entry unless it is one, then exports; exit 0 |
| without a password source | read only (BTD-70): no checkpoint, nothing written to the database; exports the log as it is, writes `Warning: no database password given, no audit checkpoint signed; the newest N audit entries are not covered …` to stderr; exit 0. `--audit-verify` shows the same N as `unanchored_entries`, plus one when the log has a checkpoint (the checkpoint row itself, see below) |
| with a wrong password source | `audit_password_rejected`, exit 1 |
| a checkpoint is due and the entries since the last one do not chain | `audit_chain_broken`, exit 1 (only with a password; without one the export reads as it is) |

## Entries written on open

Only an open with the verified database password writes (BTD-137): the GUI unlock dialog answered
with the right password, or `xca --no-gui` with a password source that matched. With the unlock
dialog cancelled or without a password source, a current database opens read-only as upstream
allows (public items, no entry, no setting migration), and a database that still needs a schema
upgrade is not opened at all: the open fails with `schema_upgrade_needs_password` and the file
stays byte for byte as it was, because the upgrade and the audit baseline would write. The legacy
`optionflags` row of old databases is likewise converted only after the verified unlock.

`database.rows_skipped` (BTD-209) is written after the verified unlock when the set of unreadable rows
the open left out differs from the set of the newest such entry (BTD-221). It carries `count`,
`skipped_items` (`key:3,template:7`, sorted) and `warning=rows_skipped`; the sets are compared as
sets, so the order does not matter. Reading commands open the database too, but as long as the
same rows stay unreadable no open adds an entry, so a cron job running `--list-items` does not
fill the log. The first open after every row loads again writes one closing entry with `count`
0, an empty `skipped_items` and no warning; later clean opens write nothing. No entry is ever
changed or removed.

The entry is best effort. On a read-only or locked database it is lost and logged, and the open,
the read and `--audit-verify` work as before (`test_cli_skipped_rows_readonly`,
`test_service_loaders::skippedRowsDatabaseLocked`).

## An older database is not migrated by an audit check

`--audit-verify` and `--audit-export` do not change the database they check (BTD-70). If its
upstream schema or `bxc_schema` is behind, the open stops after the unlock and before any write:
stdout gets `{"error":"...","ok":false,"schema_upgrade_required":true}` and the exit code is 1,
and the file stays byte-identical. Any other open (the GUI, a writing or a reading command)
migrates as before, but first copies the SQLite file to `<file>.bak-<UTC yyyyMMddTHHmmss>`; if the
copy cannot be written, the database is not upgraded. Remote databases are migrated without a
copy. On a current database the audit check works as before, including the checkpoint that
`--audit-export` with the password writes when one is due.

## Deviations from the ticket (accepted 2026-10-28)

1. **No second checkpoint table.** BTD-37 asked for a checkpoint "as its own record and as a
   special entry in the chain". The checkpoint is only the chain entry `audit.checkpoint`, which
   holds everything needed to check it. A copy in a second table can be changed by the same
   attacker who changes `audit_log`, so it adds no protection, only a consistency check.
2. **The audit key is not a key item.** BTD-37 asked for the key "stored in the XCA database and
   marked as audit key". It is stored in its own table `audit_keys` instead of `items` with a
   marker: no key list, dialog, export, delete, token or password function of XCA reaches it, so
   only the signing paths need a guard (`audit_key`): certificate signing (issuance and renewal),
   CSR creation and CRL generation, not every key path of the GUI.

## What verify reports

`xca --audit-verify` checks each checkpoint of the intact chain in order: its key is the trusted
key (the first announced key, then the `next_key_id` of each rotation), its signature verifies,
and `checkpoint_seq` is the entry just before the checkpoint, with the hash the chain has there.
Entries are anchored up to the `checkpoint_seq` of the last valid checkpoint. The checkpoint row's
own `created`, `actor`, `channel` and `object_id` are not signed, so the row itself is anchored
only by the next checkpoint (BTD-110, chosen instead of signing them, which would change the
signed payload). At the first invalid checkpoint it reports

| Field | Meaning |
|---|---|
| `reason` | `checkpoint_hash` (chain recomputed after the checkpoint, or `checkpoint_seq` not the entry before it), `checkpoint_signature` (checkpoint params changed), `checkpoint_key` (signed by a key that was not handed over by a rotation, an announcement whose `key_id` does not match its key, or a `next_key_id` never announced) |
| `last_checkpoint_seq` | the last valid checkpoint |
| `first_broken_seq` | the first entry that is not anchored: `checkpoint_seq` of the last valid checkpoint + 1 |
| `failed_checkpoint_seq` | the invalid checkpoint |

A chain whose checkpoints all verify still fails with `reason` `checkpoint_missing`
(`failed_checkpoint_seq` null, `first_broken_seq` the first entry that is not anchored) when
checkpoints were deleted: `audit_keys` holds a key that no `audit.key_create` of the chain
announces, or more than `audit_checkpoint_interval` + 1 entries are unanchored (a writer with the
database password never leaves more). The revocation baseline written on the upgrade of an old
database does not count, but only when its `audit.init` counts exactly the `revocation.baseline`
rows before it. A log written without the database password for longer than that fails the same
way until it is adopted (above). An empty log with a row in `audit_keys` is a deleted log and
reports `first_broken_seq` 1.

Always reported: `checkpoints` (valid ones), `unanchored_entries` (entries after the
`checkpoint_seq` of the last valid checkpoint, the checkpoint row included), `audit_keys` (key
ids in the order they signed) and `adopted_entries` (entries the first key adopted, 0 for none).
An `adopted_entries` param on any other announcement, or one that does not count exactly the
unsigned entries before it, is `checkpoint_key`.

Remaining limits without a trust anchor: entries after the last checkpoint have the hash chain
only; cutting off the newest entries including their checkpoints still verifies unless that
removes a key announcement; deleting the whole log or its checkpoints together with the
`audit_keys` rows verifies when the rest is at most interval + 1 entries long; an adopted log is
only as trustworthy as the check before `--audit-adopt`; a log rewritten from the first key
announcement with a new key verifies too.

## Trust anchor (BTD-101)

The checks above use only what is in the database. Two options pin values from outside it, kept
from an earlier `--audit-verify` report or export:

```
xca --no-gui --database pki.xdb --audit-verify --audit-key 3f2a… --audit-min-checkpoint 1204
```

| Option | Check | `reason` on failure |
|---|---|---|
| `--audit-key <key-id-list>` | the first entry of `audit_keys` is one of the comma separated ids; every later key must lead from it by rotation, so a rotation does not need a new pin | `untrusted_key` |
| `--audit-min-checkpoint <seq>` | `last_checkpoint_seq` is at least `<seq>` | `checkpoint_truncated` |

A chain or checkpoint error is reported first; the pin check only sets `reason` when the log is
otherwise intact. The report always carries `pinned_keys` (empty without `--audit-key`) and
`pinned_min_checkpoint` (null without `--audit-min-checkpoint`), so a stored report shows which
anchor it was checked against. A rewritten log (new first key) and a log cut off with its newest
checkpoints both fail with a pin. Keep the pins outside the database host, e.g. with the
exports.

## Checking an export with the OpenSSL CLI

Each line of the export is self-contained. With `jq` and OpenSSL 3 or later (run in the build
container, 2026-10-28):

```
xca --no-gui --database pki.xdb --password file:db.pass --audit-export audit.jsonl

# one PEM file per announced key, named after its key id
jq -r 'select(.action=="audit.key_create") | .params.key_id' audit.jsonl
jq -r 'select(.action=="audit.key_create" and .params.key_id=="<key_id>") | .params.public_key' audit.jsonl > key.pem

# the key id is the SHA-256 of the DER public key
openssl pkey -pubin -in key.pem -outform DER | openssl dgst -sha256 -r

# a checkpoint (here seq 102): payload, signature, check
jq -cjS 'select(.seq==102) | .params | del(.signature)' audit.jsonl > payload.json
jq -r 'select(.seq==102) | .params.signature' audit.jsonl | base64 -d > sig.bin
jq -r 'select(.seq==102) | .params.key_id' audit.jsonl
openssl pkeyutl -verify -pubin -inkey key.pem -rawin -in payload.json -sigfile sig.bin
```

The last command prints `Signature Verified Successfully` and exits 0. `jq -cjS` writes the
params sorted and compact without a trailing newline, which is their RFC 8785 form (the params of
a checkpoint hold only ASCII strings and integers). `test_service_checkpoint::opensslCli` runs
the `openssl` commands on every checkpoint of an export with a key rotation.
