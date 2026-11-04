# Service functions in lib/

How a GUI action becomes a GUI-free service function (BTD-31, the pattern for BTD-32 to BTD-35).
The names come from the parity matrix of bxc-pki (`docs/parity/parity-matrix.json`, BTD-27).
Certificate issuance is the reference implementation.

## Shape

| Part | Rule | Issuance (BTD-31) |
|---|---|---|
| Location | a member of the existing model class in `lib/db_*.cpp`, named as `service_function` in the parity matrix | `db_x509::newCert` in `lib/db_x509.cpp` |
| Signature | `ServiceContext` first (BTD-29, `lib/audit.h`), then one value object; returns the new or changed object | `pki_x509 *newCert(const ServiceContext &, const IssuanceSpec &)` |
| Value object | `<Action>Spec` in its own file `lib/<area>.h/.cpp`; plain public members, defaults that match the dialog's defaults; references to database objects are non-owning pointers; created per call, nothing static or shared | `IssuanceSpec`, `ExtensionSpec` in `lib/issuance.h` |
| Errors | a rejected spec throws `serviceError(code, message)` (`lib/exception.h`); `code` is stable snake_case and becomes the audit `error_code`; any other `errorEx` is an internal error | `missing_key`, `invalid_public_key`, `no_private_signing_key`, `duplicate_certificate`, `serial_exhausted`, `random_failure`, `database_error`, `read_only_database`, `disk_full`; every other exception is audited as `internal_error` and rethrown |
| No interaction | no dialog, message box, question or password prompt in the service path; secrets come from `PasswordSource` (BTD-30); success messages (`createSuccess`) and follow-up questions belong to the GUI caller | the token question "Store the certificate to the key on the token?" moved to the GUI caller |
| Audit | exactly one `AuditLog::append()` per call: `success` inside the operation's transaction, `failure` (or `denied`) after the rollback, with the parameters known at that point (allow-list of `AuditParams`, no secrets) | action `certificate.issue`, object type `certificate`, object id = item id (empty on failure); params `name`, `subject`, `issuer`, `ca_id`, `serial`, `not_before`, `not_after` (the certificate's end date after the cap at the issuer chain; null for the undefined date 99991231235959Z), `validity_capped`, `requested_not_after` (only when capped, BTD-51; a cap that leaves no window, end at or before `not_before`, fails with `invalid_validity`), `hash_algo`, `template`, `fingerprint` |
| GUI caller | the dialog only fills the value object (`NewX509::getIssuanceSpec()`), calls the service function with `ServiceContext::localUser(ServiceContext::gui)` and shows the `serviceError` with `XCA_ERROR` | `widgets/NewX509_issue.cpp` |
| Tests | `test/service/test_service_<area>.cpp` on the harness of BTD-28; check the result with openssl where possible, the audit entry of success and of every rejection, and `AuditLog::verify()` | `test/service/test_service_issuance.cpp` |

Structure of the service function: a public wrapper builds the audit parameters, calls a private
worker that does the work in one `Transaction`, and appends the `failure` entry when the worker
throws (the worker's transaction is rolled back by then). The worker appends the `success` entry
before its commit. Service functions are called outside a transaction; a `failure` entry appended
inside the caller's transaction would be rolled back with it. The `failure` (or `denied`) entry is
best effort and the original error always wins: it is written with `AuditLog::appendFailure()`,
which never throws; when the database is the reason of the failure (locked, read-only, full) the
entry is lost and logged, and the wrapper rethrows its own error (BTD-138). Since BTD-33, `auditedTransaction()`
in `lib/audit.h` is that wrapper: the service function passes the work as a lambda
(`db_x509::revoke`, `unrevoke`, `setRevocations`, `db_crl::newCrl`).

`TransCommit()` is false when the outermost commit fails and also when any inner transaction
rolled back, e.g. a helper that returned without commit and whose caller carried on: the outermost
transaction then rolls everything back (BTD-142; before, it returned the result of that rollback,
true, and the caller reported success with nothing stored). Every outermost commit is checked; a
service function turns false into `database_error` with a `failure` entry. The log names the first
inner rollback (`Commit at ... rolled back after the rollback at file(line)`).

The close of a database vacuums only after a run that committed a write (BTD-225). For SQLite
the file change counter in the header (bytes 24 to 27) decides: it is read at the open and at the
close, and a read, `--plan`'s rolled-back work or an open that wrote nothing leave it as it was. So
a read-only command (`bxc-pki list` and `show`, `--list-items`, `--index`, `--hierarchy`,
`--audit-verify`, an `--audit-export` with no checkpoint due) leaves the file byte-identical, also
its mtime, and a read-only file closes without a VACUUM attempt. A plan run and an export that
writes its due checkpoint are audited, so they are writes. A failed VACUUM is logged with its SQL
error and the close goes on. Remote databases (PostgreSQL, MariaDB) keep the VACUUM on every close
that they had. `test_cli_readonly`, `test_service_sql_errors::failedVacuumLogged`.

A failed SQL write is a typed error, never a message box in a service path (BTD-50).

- **The helper.** `throwSqlError(QSqlError, what)` in `lib/sql.h` picks the code from SQLite's result code:
  - `read_only_database`: read-only file or mount, `PRAGMA query_only`, or the database file removed while open;
  - `disk_full`;
  - `database_error` for everything else.
- **Where it is used.** These functions throw it:
  - `execOrThrow(q, what)`;
  - `TransThrow()`;
  - `TransCommitThrow()`, which carries the error of the failed COMMIT.
- **The text.** It is `what` and SQLite's reason, never the statement and its values (they may hold key material). The full statement goes to the debug log.
- **Helpers throw instead of returning false.** This covers `x509revList::sqlUpdate()`, `pki_x509req::markSigned()`, `pki_evp::sqlUpdatePrivateKey()` and the UPDATEs of `db_x509::markRequestSigned()`, `pki_x509::getTaKey()` and `pki_scard::updateLabel()`. Their callers therefore stop at the first failure instead of running on in a transaction that can only roll back.
- **`db_base::insertPKI()` and the `insert()` overrides** throw without deleting:
  - the object stays with the caller, unstored and without id;
  - `importItems()` hands it back through `ImportSpec::unstored`, with the other objects;
  - `insert()` returns NULL only for a duplicate, which it deleted.

An operation that changes several revocation rows (`db_x509::setRevocations`, the Manage
revocations dialog) writes one `certificate.revoke` or `certificate.unrevoke` entry per changed
row in its transaction, because `AuditLog::verify()` recomputes the revocations table from those
entries; a rejection writes one `ca.set_revocations` failure entry.

Memory follows the database (BTD-130): after a rollback the in-memory store and the views show
what the database holds. A change of memory that later steps of the transaction need (a new object
in the store and the views, a link set by `inToCont()`, a revocation flag) is made at once and
registers its undo with `DbTransaction::onRollback()`; the undo runs, last first, when the
outermost transaction ends without a successful COMMIT, and changes memory only, never the
database. A change that removes or replaces memory (freeing a deleted object) waits in
`DbTransaction::afterCommit()` for the outermost COMMIT. `db_base::storeInMemory()` and
`db_base::removeItem()` do this for every insert and delete; a service function frees an object
whose insert was rolled back (`!isStored()`).

Who owns an object that a rollback took out of the store (BTD-228): the undo of
`storeInMemory()` (`db_base::unstore()`) puts it on the list of unstored objects
(`pki_base::addUnstored()`). It is the database's until someone deletes or claims it:

- A service function whose own transaction rolled back deletes it in its catch (`!isStored()`),
  as before; the destructor takes it off the list, so nothing is freed twice.
- A caller that keeps it takes it off the list with `pki_base::claimUnstored()`. Today that is
  only `ImportSpec::unstored`, the hand-back to the import dialog (BTD-114).
- The rest is what a later step of an outer transaction rolled back after the storing function
  had returned (bxc-pki `runInTransaction`): `pki_base::freeUnstored()` frees it where no caller
  holds one, at the start of the next request (`runInTransaction`, later each request of the
  server of BTD-154) and when the database closes. Not at the next transaction: the failure entry
  of `auditedTransaction()` is one, written before the caller's catch block deletes its object.

## Service functions so far

| Ticket | Service function | Value object | Audit action | Error codes |
|---|---|---|---|---|
| BTD-31 | `db_x509::newCert(ctx, IssuanceSpec)` | `IssuanceSpec` (`lib/issuance.h`) | `certificate.issue` | see above |
| BTD-32 | `db_key::newKey(ctx, keyjob, name)` | `keyjob` (`lib/pki_key.h`, already a value) | `key.generate` | `invalid_key_type`, `invalid_key_size`, `invalid_curve`, `duplicate_key`, `database_error` |
| BTD-32 | `db_x509req::newRequest(ctx, RequestSpec)` | `RequestSpec` (`lib/request.h`, shares `ExtensionSpec`) | `request.create` | `missing_key`, `no_private_key`, `duplicate_request`, `database_error` |
| BTD-34 | `database_model::importItems(ctx, ImportSpec)` | `ImportSpec` (`lib/importexport.h`): files, bytes or read objects, password source | `object.import` per object (`outcome` created, completed, existing), plus `certificate.revoke`/`unrevoke` for the revocation rows a CRL or a renewed CA adds | `missing_password`, `wrong_password`, `unreadable_input`, `no_pki_data`, `nothing_to_import`, `unsupported_type`, `database_error` |
| BTD-34 | `db_base::exportItems(ctx, ExportSpec)` | `ExportSpec` (`lib/importexport.h`): items, `pki_export` format or clipboard text, password source, file or bytes | `object.export` per written object, `key.export_private` per private key in the output (`encrypted`, no key, no password), `secret.export` per symmetric secret in the output (BTD-90) | `nothing_to_export`, `wrong_object_type`, `invalid_format`, `single_item_format`, `format_not_applicable`, `invalid_pkcs12_mac`, `invalid_pkcs12_iterations`, `missing_password`, `cancelled`, `export_failed`, `write_failed`, `database_error` |
| BTD-35 | `db_temp::newTemplate(ctx, TemplateSpec)`, `db_temp::updateTemplate(ctx, temp, TemplateSpec)` | `TemplateSpec` (`lib/template.h`): name, comment, subject, `ExtensionSpec`, validity period | `template.create`, `template.update` | `missing_template`, `database_error` |
| BTD-35 | `db_base::rename(ctx, pki, name)`, `db_base::updateProperties(ctx, pki, name, comment)`, `db_token::rename(ctx, pki, name)` | the new values | `object.rename`, `object.update_comment` | `missing_object`, `wrong_object_type`, `token_error`, `database_error` |
| BTD-224 | `settings::update(ctx, changes)` (`lib/settings.h`), used by the Options dialog | key/value map | `settings.update` per changed setting: `setting` (a host-specific key with `:<hostId>`), `old_value`/`new_value` only for the 15 Options keys, `redacted` for any other key and never a value for `pwhash` or a key with "pass" | `read_only_database`, `database_error` (neither setting nor entry stored) |
| BTD-35 | `db_base::deleteItems(ctx, items)` | `pki_base *` list; returns `DeleteResult` | `object.delete` (`template.delete` for templates) per object | `nothing_to_delete`, `wrong_object_type`, `missing_object`, `database_error` |

Import and export (BTD-34):

- Secrets: a call's `passwordSource` (`pass:`, `env:`, `file:`, `fd:`, `stdin`) answers the requests
  of its purpose (`ImportPassword`, `ExportPassword`) through `PasswordSourceScope`
  (`lib/PwDialogCore.h`), whatever GUI or headless configuration is set; without it
  `PwDialogCore` asks as before. The export writers no longer prompt: they take the password
  (`pki_evp::writeKey`/`writePKCS8`, `pki_pkcs12::writePKCS12`).
- Writers take any `QIODevice`, so `exportItems()` builds the output in memory, appends the
  audit entries, then writes the file and commits: no file without its entries, no entries
  without the file (the file is removed when the commit fails).
- `object.export` names every object in the output, not only the selected items: the chain
  (`F_CHAIN`, and `F_JWK_X5C` for the `x5c` of format 43), all matching certificates
  (`F_UNREVOKED`, `F_ALL`, `F_UNUSABLE`), and for format 18 (CA vCalendar) the CA, its issued
  certificates in the calendar and its latest CRL (object type `crl`), BTD-90.
- Secrets that are not private keys (BTD-90): `secret.export`, object type `certificate`, object
  id of the certificate that stores the secret, parameters `kind`, `format`, `file`,
  `name` (of that certificate) and `encrypted`; never the secret. The only such secret is the
  OpenVPN tls-auth key (`kind` `openvpn_tls_auth`), stored with a CA and shared by its
  end-entity certificates (`pki_x509::taKeyOwner()`): format 39 writes it alone, format 4 in
  its `<tls-auth>` block, the one of the last certificate of the chain. Both are plain text
  (`encrypted` false). A separate action and not `key.export_private` with a type parameter,
  because consumers read `key.export_private` (object type `key`, a key fingerprint) as "a
  private key left". The output file of every export with a private key or a secret in it
  (`F_PRIVATE` or `exportedSecrets()`) is created owner read/write only.
- Readers: `pki_base::fromBytes()` parses the content of a file (`fload()` reads the file and
  calls it), `load_base::loadData()` and `pki_multi::probeData()` probe bytes like files.
- The import dialog (`ImportMulti`) and the detail dialog only read and show objects; storing
  goes through `importItems()` with the read objects. The export dialog fills an `ExportSpec`
  (`ExportDialog::exportSpec()`); Ctrl+C and dragging items out are exports with
  `ExportSpec::clipboard`. `xca --import` uses `importItems()` with channel `cli`.
- `lib/` signatures of the group take `pki_base *` lists, no `QModelIndex`; only the Qt model
  override `db_base::mimeData(QModelIndexList)` remains and calls `exportItems()`.

Templates, rename and delete (BTD-35):

- `TemplateSpec` (`lib/template.h`) is a template as value: subject, `ExtensionSpec` and the
  validity period relative to the issuance (`validity`, `unit`, `midnight`,
  `noWellDefinedExpDate`). `fromTemplate()`/`toTemplate()` convert to and from the stored
  settings of `pki_temp`, `applyTo(IssuanceSpec&)` is the dialog's "Apply all" (it sets
  `templateName`, so `certificate.issue` names the template), `fromIssuanceSpec()` and
  `fromObject()` (Transform > Template) make one. The dialog fills and reads its widgets through
  `TemplateSpec` (`NewX509::extensionsFromTemplate()`, `NewX509::templateSpec()`), so the mapping
  exists once. Applying a template changes nothing in the database and writes no entry.
- Audit parameters: `template.create`/`template.update` `name`, `subject`, `old_name` (only when
  the name changed); `object.rename` `name`, `old_name`, `on_token` (renamed on a token,
  `db_token`); `object.update_comment` `name` (never the comment); `object.delete` and
  `template.delete` `name`, `dependents` (objects that stay and referred to it),
  `revocations` (certificates only: the revocation rows it had as a CA).
- `deleteItems()` deletes all objects of the call in one transaction or none. The objects that
  refer to a deleted one are handled as XCA always did and listed in `DeleteResult::dependents`:
  certificates and requests lose their private key; certificates lose their issuer (and move to
  another certificate with the issuer's subject and key, if there is one); CRLs lose their issuer;
  the CA's revocation rows are deleted. `AuditLog::verify()` replays an `object.delete` of a
  certificate as the removal of its revocation rows. The question `item.delete` and the deletion
  on a token (`pki_base::deleteFromToken()`) stay with the GUI caller (`XcaTreeView::deleteItems`,
  `xcaWarning::confirmOkCancel()` records the answer in the `ServiceContext`).
- `lib/` signatures of the group take `pki_base *`; `db_base::remFromCont(pki_base *)` replaces
  the `QModelIndex` variant and `db_base::removeItem()` the old `deletePKI(QModelIndex)` (no
  audit, used by the import that completes a public key). Only the Qt model override
  `db_base::setData(QModelIndex, ...)` (inline editor, F2) remains and calls `rename()`.

Where an existing value-based entry point asked a question or showed a message (key generation:
"Key size too small", the question before an RSA/DSA size outside 1024..8192, the success
message), it stays as the interactive wrapper for the GUI and `xca --no-gui` and calls the service
function with `ServiceContext::localUser(ServiceContext::processChannel)`; the rejection itself
moved into the service function, so the wrapper only asks and reports.

Questions (BTD-71): every `XCA_YESNO`/`XCA_OKCANCEL` carries a stable question id (`key.size`,
`item.delete`, `token.*`, `dh.abort`). Without a GUI, `xcaWarningCore` answers "yes" only if the
command line confirmed the question (`--yes` for all, `--confirm <id,...>` per id); otherwise it
throws `confirmationError` (`lib/exception.h`) with the id, and `xca --no-gui` exits 1. A wrapper
whose service call depends on the answer asks with `xcaWarning::confirm(ctx, id, msg)`: the "yes"
is recorded in the `ServiceContext`, and `AuditLog::append()` writes it as parameter `confirmed`
(`key.size:--yes`, `key.size:--confirm`, `key.size:dialog`). An unconfirmed question writes a
`denied` entry with error code `confirmation_required` and parameter `question`, and nothing is
changed. Service functions themselves still never ask; a caller without a GUI (REST, EST, CMP)
passes its confirmations in the `ServiceContext`.

OpenSSL errors are checked where they happen (BTD-95, decision of 2026-10-28). `_openssl_error()`
in `lib/func_base.cpp` and the macros `openssl_error()`, `openssl_error_msg()` and
`pki_openssl_error()` only print the OpenSSL error queue to stderr and never throw: upstream
`a8ebef92` (2024-09-29, "Extend Error messages by line and function") replaced the loop that filled
the error text by `ERR_print_errors_cb()` and kept `if (!error.isEmpty()) throw`, which can no
longer run. The fork keeps that behaviour for the GUI and upstream merges; code that must not go on
after a failure checks the OpenSSL result itself:

- A service function checks the return value of every OpenSSL call that can fail (sign, encode,
  set, add, keygen) and throws a `serviceError` with a stable code, e.g. `signing_failed`
  (BTD-171); never one of the macros above.
- A loader (`fromPEM_BIO()`, `fromBytes()`, `fromPEMbyteArray()`, `d2i()`, `parse()`) checks the
  object it decoded and throws an `errorEx` that names the file or item and the OpenSSL reasons
  (`throw_unreadable()` in `lib/pki_base.h`); it never keeps an object without content. The
  import then fails with `no_pki_data` or `unreadable_input` and a `failure` entry, and a database
  row that does not decode is left out on open (`db_base::loadContainer()`). The rows left out
  are reported once for the whole load, each with its reason. After the unlock they are also
  audited: one `database.rows_skipped` entry with `count`, `skipped_items` (`key:3,template:7`)
  and `warning=rows_skipped` (BTD-209). It is written once per change of the skipped set, not
  per open; when every row loads again, one closing entry with `count` 0 follows (BTD-221,
  doc/audit-checkpoints.md, "Entries written on open"). An
  `errorEx` without text is shown nowhere (`xcaWarning::error()` drops it), so a loader never
  throws one.
- The template loader, which the import probe tries last, accepts only a well-formed template
  export (size field equal to the rest, known version, the settings consumed completely), so it
  does not hide the errors of the loaders before it (BTD-88). A stored template row is not
  checked for data after the settings (BTD-209).
- `ign_openssl_error()` empties the queue into the debug log with the same text as
  `take_openssl_errors()`. Neither uses OpenSSL's static buffer of `ERR_error_string(e, NULL)`,
  which threads would share (BTD-209).
- Key material and the audit log: `pki_evp::encryptKey()` throws `key_encryption_failed`
  before it replaces the private key by the public one, `changeDatabasePassword()` fails when a
  key is not stored with the new password, and `AuditKey` throws `audit_key_failed` or
  `audit_signing_failed` instead of storing an empty key or signature; a checkpoint signs before
  its first write, so a failure writes nothing.
- Extension input that OpenSSL cannot encode is `invalid_extension`: `x509v3ext::create()`
  (every caller, the GUI dialogs included), the advanced block (a CONF error names the line), the
  request's extensions, the merge and order paths of the issuance; an extension of a request that
  does not decode is `invalid_request_extension` with its name, not taken for absent (BTD-197).
  Before, the object was signed without the extension and audited as success.
- A URI, rfc822Name or dNSName of the SAN is an IA5String (RFC 5280 4.2.1.6): one with a byte
  above 0x7F is `san_not_ia5` naming the entry, never converted, because an OPC UA
  ApplicationUri is compared byte for byte. `IssuanceChecks::sanIa5()` runs in
  `IssuanceChecks::names()` on every certificate path (dialog, template, profile, registration
  URI, a signed device CSR: refused, not repaired; a non-ASCII dNSName there stays
  `invalid_dns_name`) and in `db_x509req::create()` for CSR creation (BTD-208). An IRI is written
  as a URI (RFC 3987), an IDN as A-labels.
- The CRL build checks every step (version, issuer, each revoked entry with serial, date, reason
  and invalidity date, AKI, IAN, CRL number, update times) and compares the built CRL with the
  revocations it was built from before signing; a failure or a difference is `crl_build_failed`
  naming the step, nothing is stored and the CRL number is not consumed (BTD-198). Tests inject
  a failed step with `crlBuild::fail()` (`lib/x509rev.h`).
- Every export writer checks its encoder with `export_check()` and its output with
  `export_write()` (`lib/func_base.h`): a failed `PEM_write_bio_*`, `i2d_*_bio`,
  `PKCS12_set_mac`, `PKCS7_add_certificate` or `RAND_bytes`, and empty or short output of a
  writer, is `export_failed` naming the encoder and the object. It comes before the success
  entries of `exportItems()`, so the export writes its `failure` entry and no file. Formats that
  may be empty by design (all unusable certificates, the index file, a vCalendar without entries)
  are no writer failure and still succeed with an empty file. `i2d_bytearray()` throws
  `encoding_failed` instead of returning empty or short DER, so no fingerprint of empty bytes
  and no empty DER row is stored (BTD-199). Tests make the encoders fail with
  `encodeFault::bioWrites` (a read-only BIO from `BioByteArray::bio()`) and `encodeFault::i2d`.
- A value that a subject entry or request attribute cannot hold is `invalid_string`
  (`QStringToAsn1()`, `throwInvalidString()`); before, the NULL string crashed the caller.
- `take_openssl_errors()` builds the message text: the reasons with their data strings, one per
  line, from a buffer of its own (`ERR_error_string(e, NULL)` writes a static one), and
  "unknown OpenSSL error" for an empty queue.

The loaders and their tests: `test/service/test_service_loaders.cpp` (broken certificate,
request, CRL, PKCS#7, PKCS#12 and key input; broken database rows; junk that is no template; old
template versions that still import).

A request's extensions are built in the context of a temporary self-signed certificate with the
spec's subject and key (`RequestSpec::buildExtensions()`), as the dialog did when its temporary
context was current. "hash" (subject key identifier) and `DNS:copycn` therefore always refer to
the request; the dialog's own context is set up only by some widget events
(`NewX509::setupTmpCtx()`).

## Moving GUI code

- Code that builds something from widget values moves into the value object's file and works on
  the value object; the widget keeps one-line delegates where other dialog code (validation view,
  check icons) uses it. `widgets/NewX509_ext.cpp` now only reads the widgets into an
  `ExtensionSpec`; the building is `ExtensionSpec::build()` in `lib/issuance.cpp`.
- The output must stay identical for the same input: same OpenSSL configuration strings, same
  order of the extensions. Behaviour changes go into their own tickets (for issuance: AKI on
  self-signed certificates BTD-48, validity clamp BTD-51, issuer checks BTD-55, extension merge
  policy BTD-54, SQL write errors BTD-50).
- `db_*` entry points that open a dialog are GUI glue. They move to a file in `widgets/`, as
  members of the view that offers the action (`CertTreeView::newItem()`, `ReqTreeView::newItem()`,
  like `KeyTreeView::newItem()`), not of the model class.
- `lib/` is the target `xcacore` and links Qt Core and Qt Sql only (BTD-36); `widgets/` is
  `xcagui` on top of it. What the core needs from the GUI goes through an interface the GUI sets:
  questions `xcaWarning`, secrets and token choices `PwDialogCore`, progress `XcaProgress`, item
  icons, row colours and the wait cursor `XcaPresentation`. The ctests `test_core_sources` (grep)
  and `test_core_link` (whole-archive link, readelf) fail on any GUI reference in the core.
- Where the GUI used to show an information box and stop (for issuance: the certificate already
  exists, practically unreachable with random serials), the service throws a `serviceError` and
  the GUI shows it as an error.
- New code goes into new files where possible, to keep the fork's diff against upstream small.

## Serial numbers

`db_x509::randomSerial()` and `getUniqueSerial()` implement rule 2 of the certstrap triage for
every certificate, root and intermediate CAs included: `serial_len / 8` octets (at least 9, at
most 20), the first octet `0x01`..`0x7f` and the others from `RAND_bytes`, so the value is
positive, keeps its length and carries at least 70 random bits. A draw that the issuer already
used (its own serial, a revoked serial, a child in memory, or a row in `certs` with that issuer
and serial) is replaced, at most 100 times, then the call fails with `serial_exhausted`. The
serial is never part of the spec.
