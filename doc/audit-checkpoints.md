# Signed audit checkpoints (BTD-37)

The hash chain of the audit log (BTD-29, `lib/audit.h`) detects a changed, deleted or reordered
entry, but not a chain whose hashes were recomputed after a change. Signed checkpoints close that
gap for every entry that a later checkpoint covers (PLAN.md section 6.3).

## What is written

| Entry action | When | Params |
|---|---|---|
| `audit.key_create` | before the first checkpoint, and on each key rotation | `key_id`, `key_type` (`ed25519`), `public_key` (PEM) |
| `audit.checkpoint` | after every N entries (database setting `audit_checkpoint_interval`, default 100), before each export unless the newest entry is a checkpoint, on `AuditLog::checkpoint()` and `AuditLog::rotateKey()` | `checkpoint_seq`, `checkpoint_hash`, `checkpoint_time`, `key_id`, `next_key_id` (rotation only), `signature` |

A checkpoint signs the entry just before it: `checkpoint_seq` and `checkpoint_hash` are that
entry's `seq` and `hash`. The signature (Base64, Ed25519) covers the canonical JSON (RFC 8785) of
the checkpoint's params without `signature`. `key_id` is the lowercase hex SHA-256 of the DER
public key.

The audit key lives in the table `audit_keys`, not in `items`, so no key list, dialog, export or
delete function shows it. Its private part is encrypted with the database password like every
other private key. Certificate issuance and renewal, CSR creation and CRL generation refuse a key
whose public key is an audit key with the error code `audit_key` (for a key copied out of the
database and imported). The certificate guard sits in `pki_x509::sign()`, where issuance and the
renewal dialog both sign. A rotation announces the new key and signs a checkpoint with the old key that names it
in `next_key_id`; the old key's private part is then deleted. A changed database password
re-encrypts the audit key (`MainWindow::changeDbPass`).

Without the database password (`xca --no-gui` without `--password`, or the unlock dialog
cancelled) no automatic checkpoint is written, the entry itself is, and the next entry tries
again. Entries after a change that does not chain are never signed (`audit_chain_broken`).

## Export with and without a password

| `--audit-export` | Result |
|---|---|
| with `--password` (or an unlocked database) | signs a checkpoint over the newest entry unless it is one, then exports; exit 0 |
| without a password source | read only (BTD-70): no checkpoint, nothing written to the database; exports the log as it is, writes `Warning: no database password given, no audit checkpoint signed; the newest N audit entries are not covered …` to stderr; exit 0. `--audit-verify` shows the same N as `unanchored_entries` |
| with a wrong password source | `audit_password_rejected`, exit 1 |
| a checkpoint is due and the entries since the last one do not chain | `audit_chain_broken`, exit 1 (only with a password; without one the export reads as it is) |

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
and `checkpoint_hash` is the hash the chain has at `checkpoint_seq`. At the first invalid
checkpoint it reports

| Field | Meaning |
|---|---|
| `reason` | `checkpoint_hash` (chain recomputed after the checkpoint), `checkpoint_signature` (checkpoint params changed), `checkpoint_key` (signed by a key that was not handed over by a rotation, or an announcement whose `key_id` does not match its key) |
| `last_checkpoint_seq` | the last valid checkpoint: entries up to it are anchored |
| `first_broken_seq` | `last_checkpoint_seq + 1` |
| `failed_checkpoint_seq` | the invalid checkpoint |

and always `checkpoints` (valid ones), `unanchored_entries` (entries after the last valid
checkpoint) and `audit_keys` (key ids in the order they signed).

Remaining limits: entries after the last checkpoint have the hash chain only; cutting off the
newest entries including their checkpoints, or deleting the whole log, still verifies; a log
rewritten from the first key announcement with a new key verifies too. Keep the `key_id` of the
first export somewhere else and compare it with `audit_keys`.

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
