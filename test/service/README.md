# Service tests (ctest label `service`)

Tests for the service-layer functions of the bxc-pki fork (BTD-28). Each test function runs
against its own fresh XCA database and fails if any dialog would have been shown.

```
cmake --build build --target tests
ctest --test-dir build -L service --output-on-failure
```

## What the harness does

`ServiceTestCase` (`ServiceTestCase.h/.cpp`) is the base class of every service test.

| When | What happens |
|---|---|
| process start (`XCA_SERVICE_TEST_MAIN`) | `HOME` and `XDG_CONFIG_HOME`/`XDG_DATA_HOME`/`XDG_CACHE_HOME`/`XDG_STATE_HOME` point into a temporary directory (`settings.ini`, `dbhistory`, `.rnd` never reach the real profile); `QT_QPA_PLATFORM=offscreen` unless set; a `QApplication` (xcalib still links Qt Widgets until BTD-36) |
| `initTestCase()` | legacy provider, OIDs, entropy; installs `StrictPwDialog` as `PwDialogCore` GUI, `StrictWarning` as `xcaWarning` GUI and an OpenSSL `UI_METHOD` without reader |
| `init()` | new temporary directory `$TMPDIR/xca-service-XXXXXX`, database `service.xdb` in it, opened with the fixed password `ServiceTestCase::dbPassword` (the only expected prompt); the database option `suppress_messages` is switched on, so XCA's "Successfully created …" boxes do not count as prompts (a test that checks them sets `Settings["suppress_messages"] = false` and expects the message) |
| `cleanup()` | closes the database, removes the directory, fails the test if the directory is still there, if an expected prompt was not shown, or if anything unexpected was prompted or shown |
| process exit | the temporary `HOME` is removed |

Nothing is written to the build tree or left in `/tmp`.

### Prompts and messages

Every prompt is unexpected unless the test announced it **before** the call:

| Source | Announce with | Unannounced |
|---|---|---|
| password / PIN (`PwDialogCore::execute`, also the OpenSSL `pwCallback`) | `pwdialog->expect("secret")` or `pwdialog->expect("", pw_cancel)` | answered `pw_cancel`, test fails |
| question (`XCA_YESNO`, `XCA_OKCANCEL`) | `warning->expectQuestion(true)` | answered `false`, test fails |
| message (`XCA_INFO`, `XCA_WARN`, `XCA_ERROR`, `XCA_SQLERROR`) | `warning->expectMessage("substring")` | test fails |
| OpenSSL terminal UI | — | always fails |

Expectations are consumed in order; an announced prompt that never came also fails the test.
The ctest `test_service_harness_selfcheck` proves that an unexpected prompt really turns a test red.

## Adding tests for a service ticket

1. Create `test/service/test_service_<area>.cpp`:

   ```cpp
   #include "lib/database_model.h"
   #include "ServiceTestCase.h"

   class test_service_<area> : public ServiceTestCase
   {
   	Q_OBJECT
     private slots:
   	void someServiceFunction();
   };

   void test_service_<area>::someServiceFunction()
   {
   	/* Database is open and empty here */
   	...
   }

   XCA_SERVICE_TEST_MAIN(test_service_<area>)
   #include "test_service_<area>.moc"
   ```

2. Add one line to `test/service/CMakeLists.txt`: `ServiceTest(test_service_<area>)`.
3. Run `ctest -L service` in the build container (bxc-pki `deploy/build/linux/Dockerfile`).

Rules:

- Only private slots are test functions. Do not define `init()`/`cleanup()` in the test class;
  if you must, call `ServiceTestCase::init()` / `ServiceTestCase::cleanup()` first / last.
- `reopenDatabase()` closes and reopens the same database (expects the unlock prompt itself) —
  use it to check that a result is persisted.
- Use `Database.model<db_key>()` etc. and `Store.getAll<T>()` to inspect the result; never touch
  the GUI (`MainWindow`, widgets).
- Data-driven tests (`<name>_data()`) get a fresh database per row.

`test_service_key.cpp` is the reference example (key generation via
`db_key::newKey(keyjob, name)`), `test_service_harness.cpp` tests the harness itself.
`test_service_audit.cpp` covers the audit log (BTD-29); its fixture is described in
`data/README.md`. Audit entries land in the per-test database, so a test reads them with
`AuditLog::entries()` right after the call.
