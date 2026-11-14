# xca-server: process-global and static state of lib/ (BTD-154)

xca-server runs every call into `lib/` on one DB worker thread (`server/worker.h`). The HTTP pool threads of
cpp-httplib parse, authenticate (peer certificate SHA-256), queue a job and wait for its result; they never
call into `lib/`. This file is the review list of the process-global and static state in `lib/`. Each item is
marked:

- **worker only**: only touched on the DB worker, so one thread uses it, as in the single-threaded GUI and CLI.
- **per request**: made per request (or per session) instead of shared.
- **thread-safe**: safe to use from any thread.

The list must be checked again whenever a request thread is to call into `lib/`, or when a second DB worker
(one per open database, after BTD-72) is added.

## How the list was made

From the fork root, on commit of BTD-154 (2026-11-13):

```
# static data members in the headers
grep -nE '^\s*static\s+[^()]*[;={]\s*$|^\s*static\s+[A-Za-z_:<>*& ,]+\s+[A-Za-z_]+(\[[^]]*\])?\s*(=.*)?;' lib/*.h | grep -v 'lib/test_'
# file-scope variables in the sources (non-const)
grep -nE '^(static\s+)?[A-Za-z_][A-Za-z0-9_:<>, *]*\s+\*?[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\s*(=[^;]*|\{[^}]*\})?;\s*(//.*|/\*.*)?$' lib/*.cpp | grep -v 'lib/test_' | grep -vE ':[0-9]+:(static )?(const|constexpr) '
# function-local statics (non-const)
grep -nE '^\s+static\s+[^(]*[;=]' lib/*.cpp | grep -vE 'static (const|constexpr)|lib/test_'
```

Constants (`static const`, `constexpr`, the action names of `AuditLog`) are immutable and left out.

## The seven items of the ticket

| Item | Where | Status | Ticket |
|---|---|---|---|
| `encAlgo::exportName` | `lib/pki_pkcs12.*` | made per call: the name is computed from the algorithm, no shared buffer | BTD-183, done |
| `encAlgo::default_encAlgo` | `lib/pki_pkcs12.h` | worker only: set from the settings when the database is opened, read by export | BTD-174 (open: make it part of the session) |
| `take_openssl_errors()` buffer | `lib/func_base.cpp` | thread-safe: a buffer of its own per call, the OpenSSL error queue is per thread | BTD-95, done |
| `DbTransaction` static state (`mutex`, `error`, `items`, `hasTransaction`, `firstRollback`, `failure`) | `lib/sql.h` | worker only: the transaction belongs to the default connection, which only the worker opened | BTD-172 (open: per connection) |
| `Settings` and `settings::setAction` defaults | `lib/settings.*` | worker only: loaded from the open database on the worker | BTD-154 (with the session, BTD-72 follow-up) |
| Passwords: the key context | `lib/key_context.h`, `KeyContext::current` | per session: the database password and pwhash live in the session's `KeyContext` of `database_model`, ended on close | BTD-72, done |
| Passwords: front-end sources | `PwDialogCore::cmdline_passwd`, the headless source object of `PwDialogCore` | front end only: never set or read by the server; guarded by `test_service_key_context::frontEndSecretsStayInFrontEnds`. The server answers the database password through a `PasswordSourceScope` on the worker's stack (`server/worker.cpp`) | BTD-72, BTD-154 |
| `XcaPresentation` and `xcaWarningCore` hooks | `lib/XcaPresentation.h` (`gui`), `lib/XcaWarningCore.h` (`gui`, `confirmAll`, `confirmed`), `lib/XcaProgress.h` (`progress`) | set once in `main()` before any thread starts (`installHooks()`), then used on the worker only; no question is ever confirmed in the server | BTD-154 |

## The rest of the grep

| State | Where | Status |
|---|---|---|
| `Database` (`xca_db`) | `lib/database_model.cpp` | worker only: opened, used and closed on the worker |
| `Store` (`pki_lookup`) | `lib/pki_base.cpp` | worker only |
| `database_model::open_without_password`, `refuse_schema_upgrade`, `read_only` | `lib/database_model.h` | worker only |
| `ServiceContext::processChannel`, `processPasswordVerified` | `lib/audit.h` | worker only: set to `rest` and by the open on the worker; the request threads build no `ServiceContext`, the job does |
| `AuditFailureCapture::current`, `checkpointNotices`, `failedCheckpointHead`, `lostEntries` | `lib/audit.*` | worker only |
| `skippedRows` | `lib/db_base.cpp` | worker only |
| `PwDialogCore::pwdialog`, `scope` | `lib/PwDialogCore.*` | worker only: no GUI is set; the scope lives on the worker's stack |
| `pki_key::unlocked`, `pki_key::defaultjob` | `lib/pki_key.h` | worker only |
| `pki_base::count`, `pem_comment`, `limitPattern`, `pki_base.cpp` set of unstored objects | `lib/pki_base.*` | worker only |
| `pki_export::elements` | `lib/pki_export.h` | worker only after the start; freed in `closeSession()` on the worker and again (empty) in `main()` |
| `digest::default_md` | `lib/digest.h` | worker only: from the settings |
| `XSqlQuery::table_prefix`, `DatabaseStamp`, `dbhistory::lastRemote` | `lib/sql.h`, `lib/dbhistory.h` | worker only |
| OID tables (`first_additional_oid`, `extkeyuse_nid`, `distname_nid`, `oid_name_clash`, `oid_lower_map`, `dn_translations`, `D`), `builtinCurves` | `lib/oid.cpp`, `lib/func_base.cpp`, `lib/pki_key.cpp` | worker only: `initOIDs()` runs in the worker's open job |
| `Entropy` pool and timer | `lib/entropy.*` | worker only: the `Entropy` object lives on the worker's stack |
| `pkcs11` state (`pctr`, `libraries`, `segv_data`, provider methods, `eng_idx`) | `lib/pkcs11*.cpp` | worker only (no token is used by the skeleton) |
| `pki_evp.cpp` library contexts | `lib/pki_evp.cpp` | thread-safe: guarded by its `QMutex` |
| `staged_file.cpp` directory table | `lib/staged_file.cpp` | worker only (no file output in the skeleton) |
| `JsonReport::json`, `is_gui_app`, `debug_info` patterns | `lib/json_report.h`, `lib/func_base.cpp`, `lib/debug_info.*` | set in `main()` before the threads start, read only afterwards |
| function-local caches in `lib/func.cpp` (`portable`, `docdir`, `dir`, `qm`, `id`) | `lib/func.cpp` | worker only (file locations, filled on first use) |
| `DatabaseLock` (set of exclusively held lock files) | `lib/database_lock.*` | thread-safe: guarded by its `QMutex`; written in `main()` before the threads start and at the end, read by the open on the worker |

## The database lock (BTD-302, BTD-303)

`<database>.lock` next to the SQLite file carries a kernel lock on an open file: `flock()` on Linux and the other
POSIX hosts, `LockFileEx()` on Windows (`lib/database_lock.*`). xca-server holds it exclusive for its run
(`main()`); the GUI and the command line hold it shared while `database_model` has the database open. So the
server refuses a database that a GUI or CLI has open, they refuse one the server runs on, and several GUI and CLI
instances share a database as before. The open on the server's worker takes no second lock: the process already
holds it exclusive.

The kernel releases the lock when its holder ends, also after SIGKILL, so a killed server never locks the database
for good, whatever its PID or host name was (a recreated container). The PID, application and host the server writes
into the file are only a hint for the `database_in_use` message.

Network file systems: on NFS, Linux maps `flock()` to NFS byte-range locks that the NFS server coordinates
between clients (NFSv4, or NFSv3 with lockd); a client that dies keeps its lock until its lease ends (NFSv4:
about 90 seconds), and with the mount option `nolock` the lock covers only one client. SMB/CIFS mounts may keep
the lock on the client. SQLite is not safe on such file systems either: keep the database on a local disk or
on a volume of one host (one Docker host for the container).

## Conclusion

Work off the worker touches no unresolved item. The request threads of `server/routes.cpp` use only
cpp-httplib, OpenSSL (`X509_digest` on the peer certificate of their own connection), Qt Core JSON and
`JsonReport::error()`, which builds a JSON object from its arguments and reads no global state. The open items
(BTD-174, BTD-172, the settings) are worker only until a request thread or a second worker needs them.
