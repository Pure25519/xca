# xca-server tests

Every server test has the ctest label `server` (`ctest -L server`).

## Adding a test (BTD-320)

Each test registers itself in its own file `server/test/<name>.test.cmake`.
`server/CMakeLists.txt` reads these files in sorted order with `file(GLOB)` and
registers no test itself, so branches that add server tests do not edit the
same lines. `test_server_layout` checks this.

The helpers come from `server/test/ServerTests.cmake`:

- `ServerShellTest(<name> <script> [VARIABLE=value]...)` runs
  `server/test/<script>` with `sh`. The script gets `SERVER`, `OPENSSL`, `WORK`
  (`<build dir>/<name without test_>`), `CMAKE` and `SERVER_TEST_DIR`, plus the
  variables given, for example `BXC_PKI=$<TARGET_FILE:bxc-pki>`.
- `ServerScriptTest(<name>)` follows an `add_test` of a script that runs the
  server binary or reads it: the label `server`, without `QT_QPA_PLATFORM`.
- `ServerTest(<name>)` follows any other `add_test`: the label `server`.

## The configuration of a test

A test never writes a complete `xca-server.json` of its own. All tests start
from one base config, `server/test/config/base.json`, which has every required
member, and set only what they need:

```sh
. "$SERVER_TEST_DIR/config/lib.sh"
xs_config listen/port "$PORT" database/path "$(xs_str "$DB")" \
    roles "[ $(xs_role reader '"client_certs": [ ... ]') ]" > "$WORK/xca-server.json"
```

- `xs_config` takes pairs of a JSON pointer without the leading `/` and a
  JSON value, applies them to the base config (`config/set.cmake`) and prints
  the result. A member that the base config lacks, such as `tls/key_password`,
  is added.
- `xs_role` writes one role with its required members; `cas` is `["*"]` unless
  given.
- `server_config.cmake` reads `config/base.json` the same way.

A new required member of `xca-server.json` goes into `config/base.json`, and a
new required member of a role goes into `xs_role`. No test script has to change.
`test_server_layout` fails when a script carries the schema id of
`xca-server.json`, which is the sign that it writes a configuration of its own.
