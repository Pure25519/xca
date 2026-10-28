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

An operation that changes several revocation rows (`db_x509::setRevocations`, the Manage
revocations dialog) writes one `certificate.revoke` or `certificate.unrevoke` entry per changed
row in its transaction, because `AuditLog::verify()` recomputes the revocations table from those
entries; a rejection writes one `ca.set_revocations` failure entry.

Known limit until BTD-50: a database error after the object was inserted (for example while the
success entry is appended) rolls the transaction back, but the object stays in the in-memory store
until the database is reopened. The `failure` entry is written; the caller sees the error.

## Service functions so far

| Ticket | Service function | Value object | Audit action | Error codes |
|---|---|---|---|---|
| BTD-31 | `db_x509::newCert(ctx, IssuanceSpec)` | `IssuanceSpec` (`lib/issuance.h`) | `certificate.issue` | see above |
| BTD-32 | `db_key::newKey(ctx, keyjob, name)` | `keyjob` (`lib/pki_key.h`, already a value) | `key.generate` | `invalid_key_type`, `invalid_key_size`, `invalid_curve`, `duplicate_key`, `database_error` |
| BTD-32 | `db_x509req::newRequest(ctx, RequestSpec)` | `RequestSpec` (`lib/request.h`, shares `ExtensionSpec`) | `request.create` | `missing_key`, `no_private_key`, `duplicate_request`, `database_error` |

Where an existing value-based entry point asked a question or showed a message (key generation:
"Key size too small", the question before an RSA/DSA size outside 1024..8192, the success
message), it stays as the interactive wrapper for the GUI and `xca --no-gui` and calls the service
function with `ServiceContext::localUser(ServiceContext::processChannel)`; the rejection itself
moved into the service function, so the wrapper only asks and reports.

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
- `db_*` entry points that open a dialog are GUI glue. They move to a file in `widgets/` (still
  members of the model class until BTD-36 splits xcalib); the `lib/db_*.cpp` file then no longer
  includes the dialog's header.
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
