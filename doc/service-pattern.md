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
| Errors | a rejected spec throws `serviceError(code, message)` (`lib/exception.h`); `code` is stable snake_case and becomes the audit `error_code`; any other `errorEx` is an internal error | `missing_key`, `invalid_public_key`, `no_private_signing_key`, `duplicate_certificate`, `serial_exhausted`, `random_failure`, `database_error`; every other exception is audited as `internal_error` and rethrown |
| No interaction | no dialog, message box, question or password prompt in the service path; secrets come from `PasswordSource` (BTD-30); success messages (`createSuccess`) and follow-up questions belong to the GUI caller | the token question "Store the certificate to the key on the token?" moved to the GUI caller |
| Audit | exactly one `AuditLog::append()` per call: `success` inside the operation's transaction, `failure` (or `denied`) after the rollback, with the parameters known at that point (allow-list of `AuditParams`, no secrets) | action `certificate.issue`, object type `certificate`, object id = item id (empty on failure); params `name`, `subject`, `issuer`, `ca_id`, `serial`, `not_before`, `not_after` (the certificate's end date after the cap at the issuer chain; null for the undefined date 99991231235959Z), `validity_capped`, `requested_not_after` (only when capped, BTD-51; a cap that leaves no window, end at or before `not_before`, fails with `invalid_validity`), `hash_algo`, `template`, `fingerprint` |
| GUI caller | the dialog only fills the value object (`NewX509::getIssuanceSpec()`), calls the service function with `ServiceContext::localUser(ServiceContext::gui)` and shows the `serviceError` with `XCA_ERROR` | `widgets/NewX509_issue.cpp` |
| Tests | `test/service/test_service_<area>.cpp` on the harness of BTD-28; check the result with openssl where possible, the audit entry of success and of every rejection, and `AuditLog::verify()` | `test/service/test_service_issuance.cpp` |

Structure of the service function: a public wrapper builds the audit parameters, calls a private
worker that does the work in one `Transaction`, and appends the `failure` entry when the worker
throws (the worker's transaction is rolled back by then). The worker appends the `success` entry
before its commit. Service functions are called outside a transaction; a `failure` entry appended
inside the caller's transaction would be rolled back with it. Since BTD-33, `auditedTransaction()`
in `lib/audit.h` is that wrapper: the service function passes the work as a lambda
(`db_x509::revoke`, `unrevoke`, `setRevocations`, `db_crl::newCrl`).

`TransCommit()` is false when the outermost commit fails and also when any inner transaction
rolled back, e.g. a helper that returned without commit and whose caller carried on: the outermost
transaction then rolls everything back (BTD-142; before, it returned the result of that rollback,
true, and the caller reported success with nothing stored). Every outermost commit is checked; a
service function turns false into `database_error` with a `failure` entry. The log names the first
inner rollback (`Commit at ... rolled back after the rollback at file(line)`).

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

## Service functions so far

| Ticket | Service function | Value object | Audit action | Error codes |
|---|---|---|---|---|
| BTD-31 | `db_x509::newCert(ctx, IssuanceSpec)` | `IssuanceSpec` (`lib/issuance.h`) | `certificate.issue` | see above |
| BTD-32 | `db_key::newKey(ctx, keyjob, name)` | `keyjob` (`lib/pki_key.h`, already a value) | `key.generate` | `invalid_key_type`, `invalid_key_size`, `invalid_curve`, `duplicate_key`, `database_error` |
| BTD-32 | `db_x509req::newRequest(ctx, RequestSpec)` | `RequestSpec` (`lib/request.h`, shares `ExtensionSpec`) | `request.create` | `missing_key`, `no_private_key`, `duplicate_request`, `database_error` |
| BTD-34 | `database_model::importItems(ctx, ImportSpec)` | `ImportSpec` (`lib/importexport.h`): files, bytes or read objects, password source | `object.import` per object (`outcome` created, completed, existing), plus `certificate.revoke`/`unrevoke` for the revocation rows a CRL or a renewed CA adds | `missing_password`, `wrong_password`, `unreadable_input`, `no_pki_data`, `nothing_to_import`, `unsupported_type`, `database_error` |
| BTD-34 | `db_base::exportItems(ctx, ExportSpec)` | `ExportSpec` (`lib/importexport.h`): items, `pki_export` format or clipboard text, password source, file or bytes | `object.export` per written object, `key.export_private` per private key in the output (`encrypted`, no key, no password) | `nothing_to_export`, `wrong_object_type`, `invalid_format`, `single_item_format`, `format_not_applicable`, `missing_password`, `cancelled`, `write_failed`, `database_error` |
| BTD-35 | `db_temp::newTemplate(ctx, TemplateSpec)`, `db_temp::updateTemplate(ctx, temp, TemplateSpec)` | `TemplateSpec` (`lib/template.h`): name, comment, subject, `ExtensionSpec`, validity period | `template.create`, `template.update` | `missing_template`, `database_error` |
| BTD-35 | `db_base::rename(ctx, pki, name)`, `db_base::updateProperties(ctx, pki, name, comment)`, `db_token::rename(ctx, pki, name)` | the new values | `object.rename`, `object.update_comment` | `missing_object`, `wrong_object_type`, `token_error`, `database_error` |
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
