# bxc-pki command line

`bxc-pki` is the headless command line of the bxc-pki fork (BTD-41 part 1, BTD-42 part 2;
bxc-pki `docs/PLAN.md` 8.1). It works directly on an XCA database (default `./bxc-pki.xdb`),
links only `xcacore` (no Qt Gui, Widgets or Help; `test_core_link` checks the binary) and never
prompts unless `--interactive` is given.

```
bxc-pki init --cn "BxC Lab Root" --key rsa-4096 --validity P20Y --password env:PKI_PW
bxc-pki init --cn "BxC OT Issuing" --parent "BxC Lab Root" --path-len 0 --key rsa-3072 --password env:PKI_PW
bxc-pki request-cert --cn plc10 --ip 192.0.2.10 --dns plc10.lab --key ec-p256 --password env:PKI_PW
bxc-pki sign plc10 --ca "BxC OT Issuing" --template TLS_server_EC --validity P1Y --password env:PKI_PW
bxc-pki list --password env:PKI_PW
bxc-pki show plc10 --type certificate
bxc-pki revoke plc10 --reason keyCompromise --ca "BxC OT Issuing" --password env:PKI_PW
bxc-pki renew plc10 --rekey --password env:PKI_PW
bxc-pki crl --ca "BxC OT Issuing" --out ./pki --layout certstrap --password env:PKI_PW
bxc-pki export plc10 --type certificate --format p12 --out ./out --password env:PKI_PW --export-pass env:P12_PW
bxc-pki export "BxC OT Issuing" --format trustlist --target-format opcua-dir --out ./tl --password env:PKI_PW
```

`bxc-pki --help` documents every command and option; the option names are a stable interface
(bootstrap and scripts build on them).

## Contract

- stdout carries only results: JSON Lines (one document per line) by default, `--text` for
  people. Write commands print one result document (below), `list` a list document, `show` the
  object documents of `lib/json_report.h` (bxc-pki `schemas/`).
- stderr carries messages, warnings, prompts and errors. An error is one error object
  (`urn:bxc-pki:schema:error:v1`) with a typed `code`; with `--text` a line `Error: <detail> [<code>]`.
- Exit code 0 ok, 1 failure, 2 usage error (unknown option, wrong value, conflicting options).
- Secrets only as `pass:`, `env:`, `file:`, `fd:` or `stdin`; an unprefixed value is rejected
  (`invalid_secret_source`), `pass:` warns. One option per purpose: `--password` (database and
  key passwords), `--sqlpass`, `--import-pass`, `--export-pass`; `--pin`, `--so-pin`, `--new-pin`,
  `--new-so-pin` are reserved for BTD-17. A missing source is `missing_password` naming the option.
- Keys: `--key <type>` generates a new key; the type names are exactly those of the bootstrap
  file (bxc-pki `schemas/bootstrap.schema.json` `$defs/keyType`: `rsa-2048`, `rsa-3072`,
  `rsa-4096`, `ec-p256`, `ec-p384`, `ec-p521`, `ec-brainpoolp256r1/384r1/512r1`, `ed25519`,
  `ed448`, `ml-dsa-44/65/87`, `slh-dsa-sha2-*`, `slh-dsa-shake-*`), mapped onto the service's
  keyjob in one table (`input.cpp`). An unknown name is `invalid_key_type`, a name this build
  cannot generate is `not_supported`; `--help` lists the available ones. `--use-key <id|name>`
  takes a key of the database, `--key-file <file>` a key file (not stored). Size and curve follow
  from the name, so bxc-pki cannot pass a wrong size; the key generation service still rejects
  one (`invalid_key_size`, audited), reachable through `xca --keygen` (BTD-16).
- A failing OID initialisation stops every command before the database is opened
  (`oid_init_failed`).
- Every write goes through the service layer, which writes the audit entries (channel `cli`,
  actor `os:<login>`). `list` and `show` only read and write no audit entry (PLAN.md 6.1).

Result document of `init`, `request-cert`, `sign`, `revoke`, `crl`, `export` and `renew` (schema
`urn:bxc-pki:schema:cli-result:v1`):

```json
{"schema": "urn:bxc-pki:schema:cli-result:v1", "command": "sign", "plan": false,
 "objects": [{"type": "certificate", "id": 7, "name": "plc10", "validity_capped": false,
              "document": {"schema": "urn:bxc-pki:schema:certificate:v1", "...": "..."}}]}
```

`objects` lists only what was actually written, after the commit. A certificate entry carries
`validity_capped` and, when capped at the issuer chain, `requested_not_after` (BTD-51).

Members of part 2 (BTD-42), present only when a command sets them:

| Member | Set by | Content |
|---|---|---|
| `files` | every command with `--out`, `export` | one entry per file: `path`, `kind` (key, csr, crt, crl, der, chain, p12, public_key, pem_bundle, manifest), `secret`, `written`, `size` and `sha256` (not with `--plan`), `object_type`/`object_id`/`object_name` of the object in it; `export` adds `format`, `encrypted`, `pkcs12_algorithm` (p12) and `ml_dsa_encoding` (ML-DSA key) |
| `crls` | init, revoke, crl, sign (re-issue), export trustlist | one entry per CRL: `ca_id`, `ca_name`, `crl_id`, `crl_name`, `crl_number`, `revoked_count`, `this_update`, `next_update`, `reissue_fraction`, `reissue_at`, `remaining_seconds`, `remaining_validity` (ISO 8601), `reissue_due`, `expired`, `der_size`, `size_budget`, `within_budget`, `trigger` (init, revoke, command, reissue_due, missing); trustlist also `role` (trusted, issuer) and `reissued`. With `--plan` a CRL to be issued has `crl_id` null and only the times and settings |
| `revocation` | revoke | `certificate_id`, `certificate_name`, `serial`, `reason` (RFC 5280 name), `ca_id`, `ca_name`, `revocation_date` (not with `--plan`) |
| `renewal` | renew (BTD-56) | `predecessor` and `successor` (each `id`, `name`, `serial`; `successor` null with `--plan`), `rekey` |
| `trust_list` | export trustlist | `target_format`, `size` (DER bytes of the CA certificates, CRLs and leaves), `budget`, `within_budget`, `on_budget_exceeded`, `ca_count`, `leaf_count` |
| `warnings` | any | `code` and `detail` of what was accepted but must be seen: `budget_exceeded`, `crl_expired`, `crl_reissue_due`, `crl_missing` (trustlist with `--allow-stale-crl`), `cleanup_incomplete` (trustlist), `crl_not_issued` (init of a CA not valid now), `predecessor_key_compromised` (renew --rekey of a certificate revoked for keyCompromise); also printed on stderr |

`--plan` (writing commands): nothing is generated, signed or stored. The handlers run the checks
that need no signature — key type, inputs, `IssuanceChecks::preflight()` (spec, issuer chain,
CSR signature), the signer's private key and its unlock (the key is decrypted, nothing is
signed), the validity cap — and list the objects that would be written with `"id": null` and
`"document": null` (no PEM, serial, signature or fingerprint), certificates with
`validity_capped`/`requested_not_after`. The extension checks of a real issue (duplicate
extensions, CSR merge rules, OPC UA chain rules) run only when the certificate is built. One
audit entry `cli.plan` (object type `object`) records the run with the parameters `command`,
`planned` (`type:name,...`) and `count`; a failed plan writes it with result `failure` and the
error code, after the failure entries of service calls.

## Design (prepared for `bootstrap`, BTD-166)

| Piece | File | What it does |
|---|---|---|
| `OptionSpec`, `parseOptions()` | `options.cpp` | one strict parser for every command: global options (`Registry::globalOptions()`) plus the command's; typed values (flag, string, integer, ISO 8601 duration, RFC 3339 date-time, secret source, reference), required options, conflicting pairs, positional limits, reserved options (`not_supported`) |
| `Command`, `Registry` | `cli.h`, `commands.cpp` | name, summary, options, conflicts, `writes`, handler; `registerCommands()` adds them; the help is generated from the registry |
| `CommandContext` | `cli.h` | what a handler gets: parsed options, the `ServiceContext` (channel `cli`), `plan`, `text`, the result collector, the current step (for "object X was not written" errors) |
| handlers | `commands.cpp` | functions over the service layer (`db_key::newKey`, `db_x509req::newRequest`, `db_x509::newCert`); they neither open nor commit a transaction and record each written object in the collector |
| `ResultCollector` | `framework.cpp` | takes the JSON document of each written object at once (an object of a rolled back transaction is gone afterwards) and becomes one result document per command |
| `runInTransaction()` | `framework.cpp` | runs a list of handlers in ONE transaction it owns and commits. On failure everything is rolled back and the failure audit entries of the service calls are written again after the rollback (`AuditFailureCapture`, `lib/audit.h`). With `--plan` the handlers write and sign nothing (see below) |
| references | `framework.cpp` | `--ca`, `--parent`, `--use-key`, `--template` and `show` take a database id or a unique name; an ambiguous name is `ambiguous_reference` with the candidates |
| input checks | `input.cpp` | RFC 4514 subjects (order kept, multi-valued RDNs, DC, UTF8String), strict IP/URI/DNS/e-mail SANs, RFC 3339, ISO 8601 durations (`IsoDuration`, `lib/issuance.h`), key types |
| CRL lifecycle | `lifecycle.cpp` | `revoke`, `crl`; `issueCrl()`, `reissueIfDue()`, `crlReport()` shared by init, sign and export; CRL settings per CA (`lib/crl_policy.h`) |
| export | `export.cpp` | single objects through `db_base::exportItems()` (BTD-34), the trust list and its format registry |
| files | `output.cpp` | `OutputFiles`: staged before the commit, published by the runner after it (`lib/staged_file.h`); `--out`, `--layout`, the certstrap file names |

`bootstrap` (BTD-166, section Bootstrap below) is one more command: it reads its file, opens
the database itself (`Command::ownTransaction`, `createsDatabase`), builds init's options per
CA and calls `createCa()`, the code path of init, inside one `runInTransaction()`, so the whole
PKI is written in one transaction (all or nothing). Its `--plan` evaluates without a
transaction and writes nothing.

Design ideas (job validation, staged atomic output with owner-only key files, name-constraint check over the issuer chain) follow jstillwa/xca --certgen by John Stillwagen (https://github.com/jstillwa/xca, evaluated in bxc-pki docs/findings/BTD-53-certgen-evaluation.md). No code was copied.

## Rules (bxc-pki PLAN.md 8.4) in part 1

- Rule 1: `--path-len` only when given; absent means no constraint, never 0.
- Rule 2: serials come from `db_x509::getUniqueSerial()` (CSPRNG, positive, 9..20 octets).
- Rule 3: `sign` takes keyUsage and extended key usage only from `--template` (with the
  template's merge settings of BTD-54); without one: CA:FALSE, keyUsage digitalSignature (plus
  keyEncipherment for RSA), no EKU. From the request only the subjectAltName is taken
  (`ExtensionSpec::sanMerge` request, `copyRequestExtensions` off).
- Rule 4: `--dns`, `--ip`, `--uri`, `--email`, strictly checked; a request with a URI only is
  allowed (then the SAN is critical); the CN never comes from an IP address or URI.
- Rule 6: `--validity <ISO 8601 duration>` (`IssuanceSpec::validity`), `--not-before`,
  `--not-after` (RFC 3339), `--backdate`; the end is capped at the issuer chain
  (`IssuanceSpec::effectiveNotAfter()`) and the cap is reported.
- Rule 11: no prompt without `--interactive`; every failure exits non-zero with an error object
  naming the object and the cause; the result lists only written objects.
- Rule 12: see input checks; no template object is shared between calls.
- Rules 1 and 5: the checks of the service layer before every signature (BTD-55,
  `lib/issuance_checks.h`) end to end in `cli/test/cli_sign_checks.cmake`. Rule 3 by key type
  for templates in `cli/test/cli_sign_checks_pending.cmake`: the service checks key usage by
  the type of the subject key on every issuance (BTD-195), so an EC, EdDSA, ML-DSA or SLH-DSA
  key with a template that names keyEncipherment or dataEncipherment is refused with
  `key_usage_not_for_key_type`; the detail names every such bit. The default templates
  `TLS_server` and `TLS_client` are for RSA keys, `TLS_server_EC` and `TLS_client_EC` (signing
  bits only) for EC, EdDSA, ML-DSA and SLH-DSA keys (`cli/test/cli_default_templates.cmake`). `--profile` is reserved until Phase 2.

## Part 2 (BTD-42): revoke, crl, export, files

### Commands

- `revoke [<certificate>] --reason <reason>`: the certificate is a database id or a unique name
  (an ambiguous name is `ambiguous_reference` with the candidates), or `--serial <serial> --ca
  <ca>` (hex as XCA shows it, with or without `0x` and colons, digits only too; decimal only as
  `dec:<digits>`; normalised by `db_x509::certBySerial()`: `unknown_serial`), or
  `--fingerprint <sha256>`. A refusal before the revocation (unknown or ambiguous reference,
  serial or fingerprint, `wrong_issuer`) gets a `certificate.revoke` failure entry as well.
  `--reason` is required and takes the RFC 5280 names (`removeFromCRL` is refused: delta CRLs
  only). With `--ca` the issuer must be that CA (`wrong_issuer`). `--invalidity-date` must not
  be after the revocation date, which is now: a later one, also within a clock skew, is
  `invalid_invalidity_date` (exit code 2, audited like the refusals above; BTD-211). The
  revocation and the new CRL
  of the issuing CA are written in one transaction; sign, revoke and crl unlock the CA key the
  same way (`--password`, also for a key with a password of its own).
- `crl --ca <ca> [--this-update <date-time>]`: the next CRL of the CA. Given `--crl-*` options
  become the CA's stored settings. Publishing to targets is Phase 4. `--this-update` more than
  5 minutes (clock skew) in the future, before the thisUpdate of the CA's latest CRL, or giving
  a CRL whose nextUpdate is already past is `invalid_this_update` (exit code 2, also with
  `--plan`; BTD-211). `--allow-stale-crl` (only with `--this-update`) issues the last two
  anyway, for lab and test CRLs; a thisUpdate in the future is never accepted.
- `export <object>... --format pem|der|pkcs8|p12|chain|trustlist --out <dir>`: see Export.
- `--out <dir>` on init, request-cert, sign, crl and revoke: see Files.

### CRL lifecycle (rule 7, PLAN.md 14.6)

- `init` issues the empty CRL of the new CA at once (a CA not valid now, e.g. `--not-before` in
  the future, gets the warning `crl_not_issued` instead). CRL numbers come from the database
  and only grow (`db_crl::newCrl()`, `crl_number_not_increasing`).
- nextUpdate = thisUpdate + the CRL validity of the CA. Defaults (user decision 2026-10-27,
  bootstrap schema `$defs/crlSettings`): validity `P7D`, re-issue fraction 1/3, CRL size budget
  4096 bytes; trust-list budget 65535 bytes.
- Re-issue point: thisUpdate + fraction x validity (P7D: 56 hours, before IDIAL's CrlRefreshScheduler
  replaces a CRL at half of its lifetime). A command that finds a CRL of the CA it works with
  past that point issues a new one: `sign` (for `--ca`) and `export --format trustlist` (for
  every CA of the list); `revoke` and `crl` always issue one. The new CRL has `trigger`
  `reissue_due` in the result and in its `crl.generate` audit entry.
- Settings per CA: `--crl-validity <duration>`, `--crl-reissue-fraction <1/3|0.25>` (strictly
  between 0 and 1/2), `--crl-size-budget <bytes>` (at least 512) on `init` and `crl`. The
  validity is a whole number of days, at least `P1D` (`P7D`, `P1W`, also `PT48H`; no years,
  months or parts of a day, else `invalid_validity`): the GUI issues the CRLs of a CA for its
  `crlDays`, so both paths give the same validity (BTD-211; the GUI reading the CRL settings
  instead stays possible later). Storage: the validity also sets the CA's `crlDays`
  (authority table, the validity in days, what the GUI shows and uses);
  the whole setting is one row of the `settings` table, key `crlpolicy_<CA item id>`, value
  `{"validity":"P7D","reissue_fraction":0.333...,"size_budget":4096}` (`lib/crl_policy.h`;
  no schema change). Writing it is audited (`ca.crl_settings`). The row is read fail-closed
  (BTD-211): broken JSON, no object, an unknown or missing member, a validity that the option
  would refuse, a fraction outside (0, 1/2) or a size budget below 512 or not whole is
  `crl_settings_invalid` (exit code 1), naming the CA, the row and the member, on every command
  that reads the setting (`crl`, `revoke`, `sign`, the trust list). Giving all three `--crl-*`
  options does not read the row, so `crl` with all three replaces an invalid one. A CA without
  the row has the defaults with its `crlDays`. Per export target the same
  options plus `--trust-list-budget` and `--on-budget-exceeded` override them for one export
  and are not stored.

### Files (rules 7, 10, 11)

Every file goes through one helper, `lib/staged_file.h` (`StagedFile`): a temporary file
`.<name>.bxc-tmp-<random>` is created in the target directory with `O_EXCL`, mode 0600 from its
creation for private keys (Windows: a protected DACL with OWNER RIGHTS only; written for
BTD-13, not yet compiled or tested), checked to be owner-only (a file system that ignores the
mode, such as WSL drvfs or vfat, is refused here with `permission_check_failed`, before
anything is stored), written, `fsync`ed; only after the database commit it is
published: without `--force` with `renameat2(RENAME_NOREPLACE)`, or with `link()` and `unlink()`
where the file system rejects that flag (an existing file, also one that appeared meanwhile, is
never replaced: `file_exists`), with `--force` with `rename()`; then the directory is
`fsync`ed and the mode of a key file is checked again: a key file that fails is removed again
and listed as not written (`permission_check_failed` in `publish_failed`). Everything
that can fail before (key unlock, encoding, export password, directory and collision checks,
writing the temporary file) runs before the commit, so a refused file leaves the database
unchanged. A failure of the publish step is `publish_failed`: its detail names the objects that
are stored (id and name) and the files that are missing, and a failure entry `object.export`
follows; export the objects again instead of issuing them twice. A run killed at any point
leaves the target absent or complete (an old file unchanged); at most the hidden temporary file
stays. Public files are not refused for their mode.

Hardening (BTD-210; POSIX, the Windows branch is BTD-13):

- Publish without `--force` on any file system: before the commit the temporary file is
  renamed to a second temporary name with `RENAME_NOREPLACE` (or, where the flag is rejected,
  linked to one that is removed again). A directory where neither works (vfat or exFAT without
  `RENAME_NOREPLACE`, SMB, FUSE) is refused with `target_filesystem_unsupported`, naming the
  directory, before anything is stored, instead of a stored object without its file.
- The target directory is resolved once (`realpath`) and opened from `/` one component at a
  time with `O_NOFOLLOW`; every later step (create, check, publish, removal, `fsync`) is
  relative to that descriptor. Right before the publish the path must still lead to the same
  directory; one that was renamed or replaced by another directory or a symbolic link meanwhile
  gets nothing: `target_directory_changed` (inside `publish_failed` after the commit). A
  symbolic link in the given path (e.g. a home directory that is a link) is resolved once and is
  fine. The trust-list directory (`StagedDirectory`) likewise works relative to the directory
  above it: the check of the old content, the swap and every removal never follow a link, and the
  target must still be the directory of the check.
- Temporary files are named `.<name>.bxc-tmp-<16 hex>`; a name for which that would exceed 255
  bytes gets `.<prefix of name>-<16 hex of the SHA-256 of name>.bxc-tmp-<16 hex>`. A later run
  removes temporary files of killed runs from its directory: names matching
  `^\..+\.bxc-tmp-[0-9a-f]{16}$`, regular files only, owned by the user of the run and older
  than 10 minutes (a younger one may belong to a run that is still going); the result names
  them in the warning `stale_temp_removed`. A temporary file that cannot be removed after the
  `link()` publish is the warning `temp_file_left` with its path (it holds the file's content,
  for a key file the private key).

Names under `--out`:

- `--layout id` (default, rule 10): `<name>-<id>.<ext>`, the internal name and the database id
  of the object in the file, so two objects with the same CN never meet in one file.
- `--layout certstrap`: `<name>.<ext>` as certstrap writes them, i.e. `<CN>.key`, `<CN>.csr`,
  `<CN>.crt`, `<CN>.crl` (the CRL is named after its CA). An existing file is refused
  (`file_exists`) unless `--force`.
- `<name>`: the internal name (by default the CN); like certstrap, spaces become `_`; any other
  character outside `[A-Za-z0-9._+@-]` and a leading `.` become `_` as well.
- Files: init `key`, `crt`, `crl`; request-cert `key`, `csr`; sign `crt`; crl and revoke the
  CRL. Certificates, requests and CRLs are PEM. The key file is encrypted PKCS#8 (PBES2) with
  `--export-pass`; `--key-unencrypted` writes unencrypted PKCS#8 (as certstrap without a
  passphrase), `--no-key-file` none; without one of the three a command that writes a key
  stops before generating anything (`missing_password` naming `--export-pass`).
- certstrap compatibility is the file names and the PEM content only, not certstrap's CA
  directory structure or its depot; `cli/test/cli_out.cmake` runs a script written for
  certstrap's output unchanged against the files (`certstrap-script.log` in its work directory).

### Export (rule 9)

| `--format` | certificate | key | request | crl |
|---|---|---|---|---|
| `pem` | `.crt` | public key `.pub.pem` | `.csr` | `.crl` |
| `der` | `.der` | public key `.pub.der` | `.csr.der` | `.crl.der` |
| `chain` | `.chain.pem`, the chain up to the root | - | - | - |
| `p12` | `.p12`: certificate, key and chain, AES-256-CBC with PBKDF2 and an SHA-256 MAC (BTD-52) | - | - | - |
| `pkcs8` | its private key | `.key`, encrypted PKCS#8 with PBES2 | - | - |

Encrypted formats take their password from `--export-pass` only; without it the export fails
with `missing_password` and writes no file. Legacy only on request: `--pkcs12-algorithm
<name>` (e.g. `PBE-SHA1-3DES`, audited with `legacy`), `--key-unencrypted` (unencrypted
PKCS#8), `--legacy-key-pem` (OpenSSL traditional PEM with RFC 1423 encryption, PKCS#1 for RSA).
`--pkcs12-mac hmac-sha256|pbmac1` selects the PKCS#12 MAC (PBMAC1, RFC 9579, is read by
OpenSSL 3.4 and newer, not by Windows, Java, older OpenSSL and many devices) and
`--pkcs12-iterations <n>` the PBKDF2 count of encryption and MAC, 2048 to 10000000 (default: the
setting `pkcs12_iterations`, 2048); both only with `--format p12` (`conflicting_options`) and not
with a legacy algorithm (`invalid_pkcs12_mac`, `invalid_pkcs12_iterations`). The result names
`pkcs12_algorithm`, `pkcs12_mac` and `pkcs12_iterations` as written, like the audit entry.
`--mldsa-key-format both|seed|expanded` selects the RFC 9881 encoding of an ML-DSA private key
(`ExportSpec::privateKeyFormat`); the result (`files[].ml_dsa_encoding`) and the audit entry
`key.export_private` name it; on another key it is `format_not_applicable`. To check the stored
encoding, read the first byte of the RFC 9881 `ML-DSA-PrivateKey` inside the decrypted PKCS#8:
`0x80` seed, `0x04` expanded, `0x30` both. `openssl pkcs8` and `openssl pkey` are no proof:
they decode the key and encode it again, so a seed-only key comes back as both.
`misc/mldsa-key-encoding.sh <file> [<password variable>]` decrypts PBES2 without decoding the
key and prints the encoding as JSON (password from `EXPORT_PASS` by default). `--plan` runs the
option checks of the export service (`db_base::checkExportSpec()`: format, PKCS#12 algorithm,
ML-DSA key format) and reports the error of the real run (BTD-211). Every export writes
`object.export`, a private key also `key.export_private`. `--type` selects the object kind when
a name is used by more than one.

### Trust lists

Decision (user, 2026-10-27; recorded in BTD-42): the OPC UA directory layout is the trust list
format for OT devices, but targets are not only OPC UA devices, so the format is selected per
target: `--target-format opcua-dir` (default), `pem-bundle`, `der-files`. SCALANCE XB208 has no
trust-list management (IDIAL research), device leaf packages are BTD-66.

- Content: the given CAs are trusted; their chains up to the root and `--issuer-ca` are issuers
  (only for chain building, OPC 10000-12 7.8.2). Every CA comes with its latest CRL. `--leaf`
  adds trusted leaf certificates (peers) after them, role `trusted` in the manifest. One export is meant for one hierarchy; CAs of several roots
  share the same `trusted/` and `issuer/` directories.
- The trust list owns `--out`: it must be empty or hold exactly an earlier trust list, i.e. a
  `manifest.json` with the schema `urn:bxc-pki:schema:trust-list-manifest:v1` and nothing but
  the files it lists and their directories (replaced only with `--force`, else `file_exists`).
  Anything else, e.g. a web app with its own `manifest.json` or an extra file in `trusted/`, is
  refused (`invalid_output`) and not touched, and so is a mount point. The files are staged in
  a hidden sibling `.<dir>.bxc-tmp-<random>`; after the database commit the target is checked
  again and swapped in as a whole (`renameat2` `RENAME_EXCHANGE`; without it two renames). Of
  the old content only the entries found by that check are removed; files that appeared later
  stay in the old directory, which keeps its temporary name (warning `cleanup_incomplete`). A
  device sees the old or the new list, never a mix, and no file of an earlier export stays.
- `opcua-dir`: `trusted/certs/<name>-<id>.der`, `trusted/crl/<CA>-<CA id>.crl` (DER; named after
  the CA, so a new CRL replaces the old one),
  `issuer/certs/`, `issuer/crl/`, leaves in `trusted/certs/` as trusted peers (BTD-211; they
  were in `own/certs/` before, which OPC 10000-12 7.8.2 keeps for the application's own
  certificate; no device used that layout yet, and no option writes `own/`). `pem-bundle`: `trustlist.pem` with
  all CA certificates, then all CRLs (leaves in `leaves.pem`). `der-files`: one DER file per
  certificate (`.der`) and CRL (`.crl`).
- `manifest.json` (`urn:bxc-pki:schema:trust-list-manifest:v1`) lists every entry with
  `position`, `kind`, `role`, `path`, `name`, `object_id`, `der_size`, `sha256` and for CRLs
  number and times: CA certificates first, then CRLs, then leaves (OPC UA push order: the trust
  list before CreateSigningRequest and UpdateCertificate).
- CRL freshness: a missing CRL or one past its re-issue point is renewed with the CA key; with
  `--no-reissue` (or a CA without private key) an expired CRL is `crl_expired`, one past its
  re-issue point `crl_reissue_due`, a missing one `crl_missing`; `--allow-stale-crl` exports
  them with a warning (an S7 refuses the whole trust list for one expired CRL).
  `--force` only replaces the files; a routine re-export needs it and keeps the CRL check.
- Budgets: per CRL (`--crl-size-budget`, else the CA's setting, default 4096) and for the whole
  list (`--trust-list-budget`, default 65535; the size is the sum of the DER sizes of the CA
  certificates, CRLs and leaves, in every target format; BTD-211). `--on-budget-exceeded warning` (default) exports and warns,
  `error` refuses (`budget_exceeded`) and writes nothing. The result reports every size and the
  remaining validity of every CRL.
- One audit entry `trustlist.export` (object type `object`) with `format`, `file` (the
  directory), `count`, `der_size`, `trust_list_budget`, `name` (the trusted CAs) and `warning`;
  a refusal is the same action with result `failure`.

Extension point: a device-specific layout is one more `TrustListFormat` in
`trustListFormats()` (`export.cpp`): a name, a description, its default budget action and a
`layout()` function that maps the content (CA certificates, CRLs and leaves in manifest order,
each with DER and PEM) to files. Content, CRL checks, budgets, manifest and audit stay the same
for every format, so the existing formats do not change.

### Audit (part 2)

New actions: `ca.crl_settings`, `trustlist.export`. New parameters (allow-list in
`lib/audit.cpp`): `crl_validity`, `reissue_fraction`, `size_budget` (ca.crl_settings),
`trigger` (crl.generate), `trust_list_budget` (trustlist.export). The other entries are those
of the services (`certificate.revoke`, `crl.generate`, `object.export`, `key.export_private`).

### Error codes (part 2)

`invalid_reason`, `invalid_fingerprint`, `wrong_issuer` (revoke); `file_exists`,
`invalid_output`, `write_failed`, `permission_check_failed`, `publish_failed` (files);
`format_not_applicable` (export format for the object), `crl_missing`, `crl_expired`,
`crl_reissue_due`, `budget_exceeded` (trust lists); from the services `unknown_serial`,
`already_revoked`, `self_signed`, `unknown_issuer`, `missing_password` (also for an empty
export password, PKCS#12 included; `--interactive` asks for a new password twice,
`wrong_password` for an export when the entries differ).

## Renewal (BTD-56)

- `renew [<certificate>]`: the certificate is chosen as by `revoke` (a reference, `--serial`
  with `--ca`, `--fingerprint`; the same usage errors). Subject, every extension and the issuer
  are the predecessor's (`db_x509::renew()`, the service function the renewal dialog uses too);
  the serial is new (rule 2). The validity options are those of `sign`; without them the new
  certificate has the period of the predecessor, from now, capped at the issuer chain (rule 6).
- `--rekey` makes a new key of the predecessor's key type, or of `--key`; `--use-key` takes a key
  of the database. A new key gets its own subject key identifier (and, self-signed, authority
  key identifier); all other extensions are copied as they are.
- A predecessor revoked for keyCompromise is never renewed with its own key (`key_compromised`);
  with a new key the result carries the warning `predecessor_key_compromised`.
- The issuer checks, the profile and the policies of `sign` apply: a predecessor issued under a
  stored profile is renewed under that profile version again (OPC UA chain rules included).
- The predecessor stays; revoking it is `bxc-pki revoke`. The audit entry is `certificate.renew`
  (the parameters of `certificate.issue` plus `predecessor_id`, `predecessor_serial`, `rekey`);
  the link is kept in the table `renewals` (`bxc_schema` 5). The CRL of the CA is re-issued when
  it is due (rule 7), as by `sign`.
## Bootstrap (BTD-166, Phase 2)

```
bxc-pki bootstrap --file lab.json [--db <db>] [--password <source>] [--plan]
```

One JSON file (bxc-pki `schemas/bootstrap.schema.json`, `urn:bxc-pki:schema:bootstrap:v1`)
describes the PKI; `bootstrap` sets up its `database`, `cas`, `profiles` and `policies` in ONE
transaction (all or nothing) and is idempotent (bxc-pki PLAN.md 8.2).

- **Reader** (`bootstrap_reader.cpp`): a strict typed reader, no schema library. The members
  of this phase are checked as the schema checks them (types, enums, patterns, required and
  unknown members, `additionalProperties`/`unevaluatedProperties` false, the two `oneOf` of a
  CA: `cn` or `dn`, `validity` or `not_after`); the patterns are the schema's, written for PCRE
  (`$` as `\z`). Every error is `invalid_bootstrap_file` with the JSON pointer in front of the
  detail (`/cas/2/key: 'rsa-1024' is not one of ...`; `/` is the whole file). Values the schema
  takes but the fork refuses get their own code at the pointer: a CRL validity that is no whole
  number of days of at least P1D (`invalid_validity`, `CrlPolicy::validityError()`, BTD-211), a
  fraction of a second in a timestamp (`invalid_value`), a CRL distribution point that is no
  strict URI (`invalid_uri`). Bootstrap checks of the file: CA ids unique, every `parent` a CA
  of the file, no cycle; CAs are set up parents first. `server` and `roles` (Phase 3, BTD-160),
  `enrollment`, `ocsp`, `publishers`, `rollover` and `"parent": "external"` (with every CA
  below it) are Phase 4 or later: they are checked for their type only and listed in
  `bootstrap.skipped`, never an error, so one `lab.json` works across phases. The bxc-pki side
  cross-checks the reader against the real schema (`bootstrap --plan` against check-jsonschema);
  the invalid samples of later-phase elements pass the reader by design.
- **Profiles and policies**: an entry is a path relative to the bootstrap file (a `.json` file,
  or a directory ending in `/` whose `*.json` files are taken in name order) or an inline object
  with `id`; a missing file is `invalid_bootstrap_file` at the entry. They are stored through
  the profile store of BTD-167 (`ProfileStore::create`; a stored document that differs, or is
  retired, becomes a new version with `ProfileStore::update`; an equal one is kept).
- **Profiles and policies of a CA**: `profiles` and `policies` (arrays of unique ids) are
  assigned to the CA (`ProfileStore::assign` of BTD-167: the profiles the CA may issue with,
  the name policies every issuance under the CA is checked against); the assignment of a
  profile refuses one without a signature for the CA's key (`profile_signature_mismatch`).
  `issued_with` (one id) names the profile the CA's own certificate is issued with. Every id
  must name a profile (`issued_with`, `profiles`) or a policy (`policies`) of the file or of the
  database; otherwise `unknown_reference` at the pointer of the id (`/cas/1/profiles/0: there
  is no profile 'x' in the file or the database`). A profile or policy in `profiles` or
  `policies` that exists only in the database and is retired is refused with
  `document_retired`, the code of `ProfileStore::assign` (BTD-232): a retired document never
  takes effect. A retired document that the file defines is stored as a new version first and
  stays assignable; `issued_with` may name a retired profile, since it only records how the
  CA was issued. `issued_with` is recorded and compared, not
  applied: the certificate is made from the CA's own members (key, subject, validity,
  `path_len`, `name_constraints`, `key_usage`, the parent's CDP), and bootstrap does not run
  the profile over it, because a CA profile cannot carry name constraints or a CDP, caps the
  validity (`validity.max`) and wants a CSR or a server key of its own, so applying it would
  override or refuse the values of the file. What it does: the id must exist, it is stored in
  the definition of the CA (mapping row, `definition_sha256`) and shown in the result
  (`issued_with`), and a different `issued_with` for an existing CA is `bootstrap_conflict`,
  like every member the certificate was made from. What it does not do: it does not check the
  certificate against the profile, it records no profile version for the CA certificate
  (`issued_profiles`) and it does not assign the profile to the CA or its parent.
- **CAs**: init's code path (`createCa()` in `commands.cpp`) with the file's values: key type
  (the vocabulary of `--key`), subject from `cn` plus `subject` (order C, ST, L, O, OU, CN) or
  `dn` (RFC 4514 string or RDN list, order and multi-valued RDNs kept), `parent`, `hash`,
  `validity`/`not_before`/`not_after`, `path_len` (only when given, rule 1), `name_constraints`
  (critical by default; CIDR becomes address/mask), `key_usage` (`contentCommitment` is
  `nonRepudiation`; default keyCertSign and cRLSign), and as CDP of an intermediate CA the
  `crl.distribution_points` of its parent. The CRL settings (`crl`, with the defaults of
  `CrlPolicy` for missing values) are always stored through `CrlPolicy::store()` (settings
  row, crlDays, `ca.crl_settings`), and every CA issues its empty CRL (rule 7). `key_password`
  gives the CA key a password of its own (XCA "own password"); it also unlocks the key when the
  CA signs a child. `rsa_padding: pss` is valid in the schema but `not_supported` for every CA
  in this build (the signing service has no RSASSA-PSS; BTD-234). A CA
  whose parent (or a CA above) forbids it by `path_len` is `path_length_exceeded`.
- **Idempotency**: the settings row `bootstrap_<10 hex digits>` maps a bootstrap id to its
  object (`settings.key_` is CHAR(20), so the key is the first 10 hex digits of
  SHA-256(`<kind>:<id>`); the value names kind and id, a collision is `bootstrap_conflict`).
  The row of a CA holds the item id, its name, the definition it was made from and the SHA-256
  of that definition; the row of a profile or policy its name and version. A second run keeps
  every object and writes only `bootstrap.apply`. A CA whose definition differs in `key`, `cn`,
  `subject`, `dn`, `parent`, `path_len`, `name_constraints`, `key_usage`, `hash`, `rsa_padding`,
  `validity`, `not_before`, `not_after`, its parent's distribution points, `key_password` or
  `issued_with` is `bootstrap_conflict` naming the pointer, the bootstrap id and the member, and
  nothing of the run is written; changed CRL settings (`CrlPolicy::store`) and changed
  `profiles` or `policies` are updates. The row of a CA also lists the profiles and policies
  the file assigns: an update assigns the ids the CA lacks and takes back (`unassign`) the ids
  an earlier run assigned and the file no longer lists; an assignment made outside bootstrap
  stays. A row whose CA is gone is `bootstrap_conflict` too.
- **Secrets**: every secret field of the file is a reference (`env:`, `file:` or `op://`); a
  literal is `invalid_bootstrap_file` at its pointer and never shown, also in elements of later
  phases. Before the database is opened the real run reads every reference it uses (the
  database password, `key_password` of the CAs it sets up) through the BTD-30 sources: an
  unreadable one is `missing_password` at its pointer, an `op://` reference
  `unresolved_secret_reference` naming the field and the route (`op run` or `op inject` into
  an `env:` reference); the fork contains no 1Password code (`cli_bootstrap_errors` checks the
  link dependencies). SQLite: `database.password` is the database password; PostgreSQL and
  MariaDB: `password` is the server's (`--sqlpass` replaces it), `key_password` the database
  password (not tested: no database server in the build container). `--db` replaces the
  file's database, `--password` its password.
- **--plan**: reads no secret, opens an existing database without its password (public
  objects and settings rows; a missing database is not created) and writes nothing, not even
  `cli.plan`; closing it runs no `VACUUM`, because XCA vacuums only after a run that
  committed a write (BTD-225): the file stays byte-identical. This differs on purpose from the
  `--plan` of the other commands, which add one `cli.plan` entry: BTD-166 asks for a plan
  that leaves the file hash unchanged and needs no password source, and a missing database
  is not created. An entry written without the password would be unsigned, and repeated
  plans would grow the unsigned tail past the checkpoint interval (BTD-110), so that the next
  writer fails with `audit_checkpoint_missing`. It lists every object as create, keep, update, skip
  or error (an error of one object, e.g. `bootstrap_conflict` or `not_supported`, is an entry
  with `error`, exit code 0; an error of the file ends the plan as in the real run) and under
  `unchecked` every check it could not do: the secret references, the private keys and
  passwords of existing CAs, key generation, signatures and the issuance checks of new CAs.
- **Audit**: `bootstrap.apply` (object type `database`) is the first entry of the run's
  transaction, on an empty database seq 1 (a new database writes no entry before it), with
  `file_sha256`, `schema`, `created`, `kept`, `updated`, `skipped`; the entries of every object
  follow (`profile.create`, `policy.create`, `key.generate`, `certificate.issue`,
  `ca.crl_settings`, `crl.generate`, `profile.assign`, ...). Any error rolls the run back; the
  failure entries of the service calls are written again after the rollback, followed by
  `bootstrap.apply` with result `failure` and the error code (not for an error of the file or
  of a secret, which comes before the database is opened).
- **Result**: the cli-result with `command` `bootstrap`, `objects` (key, certificate and CRL
  of every new CA), `crls` (the empty CRLs) and the member `bootstrap`:

```json
{"file": "lab.json", "file_sha256": "<hex>", "schema": "urn:bxc-pki:schema:bootstrap:v1",
 "database": "/data/bxc-pki.xdb",
 "counts": {"created": 10, "kept": 0, "updated": 0, "skipped": 6, "errors": 0},
 "entries": [
  {"kind": "profile", "bootstrap_id": "root-ca", "pointer": "/profiles/0", "action": "create",
   "type": "profile", "name": "root-ca", "source": "profiles/root-ca.json", "version": 1},
  {"kind": "ca", "bootstrap_id": "ot-rsa-root", "pointer": "/cas/0", "action": "create",
   "type": "certificate", "id": 3, "name": "BxC OT RSA Root CA", "key_type": "rsa-4096",
   "serial": "...", "fingerprint": "AB:...", "issuer": "CN=BxC OT RSA Root CA,...",
   "subject": "CN=...", "issuer_bootstrap_id": null, "issued_with": "root-ca",
   "profiles": ["issuing-ca"], "policies": [],
   "not_before": "...", "not_after": "...", "crl_id": 4, "crl_number": 1,
   "next_update": "...", "definition_sha256": "<hex>"}],
 "skipped": [{"element": "/server", "reason": "the server TLS of xca-server comes in Phase 3 (BTD-160)"}],
 "unchecked": [{"object": "ca:ot-rsa-root", "check": "..."}]}
```

  `action` is create, keep, update (with `changed`: `crl`, `profiles`, `policies`, `document`,
  `retired`),
  skip (with `reason`) or, with `--plan`, error (with `error`: `code`, `detail`; also entries of
  kind `secret` for an `op://` reference). With `--plan` a new CA has `id`, `serial`,
  `fingerprint`, `issuer`, `crl_*` and `next_update` null; `unchecked` is present only with
  `--plan`. With `--text` the result is printed for people: the objects written, the counts,
  one line per object with kind, bootstrap id, action and database id (the item id of a CA,
  the version of a profile or policy, `-` while there is none), `changed`, the reason of a skip
  or the error of an entry, then the skipped elements and, with `--plan`, the unchecked steps:

```
bootstrap lab.json: created 10, kept 0, updated 0, skipped 6, errors 0
profile root-ca: create, version -
ca ot-rsa-root: create, id -
ca ot-p256-issuing: update, id 9 (changed: profiles, policies)
skipped /server: the server TLS of xca-server comes in Phase 3 (BTD-160)
unchecked database: '/data/lab.xdb' does not exist: every object would be created, ...
```
- **Error codes**: `invalid_bootstrap_file`, `bootstrap_conflict`,
  `unresolved_secret_reference`; from the checks above `invalid_validity`, `invalid_value`,
  `invalid_uri`, `invalid_subject`, `missing_password`, `unknown_reference`,
  `document_retired`, `path_length_exceeded`, `not_supported`, `invalid_profile`, `invalid_policy`, and the codes of
  the services, each with the pointer of the object in front of the detail. A subject that
  `parseDn()` refuses names the pointer of its member (`/cas/2/dn`, `/cas/2/cn`, or
  `/cas/2/subject` for an attribute of `subject`): `/cas/2/subject: 'CN=R,O=' is no RFC 4514
  distinguished name: the value of O is empty`; on the command line the source is the option
  (`--subject 'CN=x,C=DEU' is no RFC 4514 distinguished name: ...`).

## Tests

`ctest -L cli` (build container, `deploy/build/linux/dev.py test -L cli` in bxc-pki): the
scripts in `cli/test/` run the binary against fresh databases; each keeps a `transcript.log`
of every call in its work directory under the build tree. `cli_fixture` is a test helper that
creates what the command line cannot (templates with a custom EKU, a key with a password of
its own, many revocations for a large CRL). Part 2: `cli_revoke`, `cli_crl`, `cli_export`, `cli_renew` (BTD-56),
`cli_out` (certstrap layout and script), `cli_trustlist`, `cli_files`; the hardening of
BTD-210: `cli_files_noreplace`, `cli_files_tempfiles`, `cli_files_dirswap`,
`cli_files_longname`. `cli_files*` run `bxc-pki-faults`, the same command line built with
`BXC_PKI_FAULTS`: `BXC_PKI_FAULT=<mode>:<step>:<text>` (several separated by `,`), step one
of `create`, `owner_check`, `probe`, `write`, `sync`, `publish`, `noreplace`, `unlink`,
`recheck`, `swap`, acts on every file or directory whose path contains the text: `fail` makes
the step fail (`probe`: as on vfat; `noreplace`: as on a file system without
`RENAME_NOREPLACE`), `kill` ends the process there (exit code 137) like a killed run, `addfile`
adds `late.txt` to a directory, `addtarget` creates the target file, `swapdir` renames the
directory away and puts a symbolic link to `<dir>.other` in its place. The shipped `bxc-pki`
has no such hook.

Bootstrap (BTD-166): `cli_bootstrap` sets up a lab-like file (`cli/test/data/bootstrap/lab.json`:
the hierarchies ot-rsa, ot-p256 and pqc with root and issuing CA each, three profiles and a
policy adapted from the bxc-pki examples) on an empty database, verifies every chain with
`openssl verify` and every CRL with `openssl crl -verify`, checks seq 1 `bootstrap.apply`,
the second run (nothing changes), `--plan` without any password source (database file
byte-identical), a file with one more CA, updates of CRL settings and a profile, the
profiles and policies assigned per CA and their change (assign, unassign), a different
`issued_with` (`bootstrap_conflict`) and `--text` with and without `--plan`;
`cli_bootstrap_errors` the refused files (schema errors with their pointers, CRL validity,
literal, unresolvable and `op://` secrets, conflicts, an error in the middle of the run,
`issued_with`, `profiles` and `policies` of the wrong type or not unique, unknown ids as
`unknown_reference`, DN errors with the pointer instead of `--subject`, `--text`),
own key passwords, skipped offline roots and the link dependencies (`ldd`, no 1Password
library).
