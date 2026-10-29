# Service test data

## `schema8-fork.sql`

SQL dump (Python `sqlite3.iterdump()`) of a database created by the unmodified fork, bxc-main
`119d539`, database schema 8. `test_service_audit::upgradeForkDatabase` loads it and checks that
the fork migration `bxc_schema` 1 (table `audit_log`, BTD-29) keeps every row, leaves upstream's
`schema` at 8 and writes the revocation baseline. `test_service_audit::upgradeWaitsForPassword`
and `cli_password_empty_db.cmake` (with the stored hash of the empty password) check that a
rejected password leaves it unchanged (BTD-117).

Content: an imported EC CA key and self-signed CA certificate (`fixture-ca-key`, `fixture-ca`), a
generated RSA key (`fixture-rsa`) and a CRL of the CA (`fixture-crl`). All private keys are throwaway
test keys, encrypted with `ServiceTestCase::dbPassword`. The CLI has no revoke command, so the one
row in `revocations` (CA item 2, serial `01A2B3`, reason bit 1) was inserted with sqlite in XCA's
column format before the dump.

Created in the build container (`bxc-pki-btd12-build`) with the bxc-main build:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.crt -days 3650 -subj "/CN=Fixture CA" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
xca --no-gui --database fixture.xdb --password pass:service-test-db-pass --import ca.key ca.crt --import-names "fixture-ca-key;fixture-ca"
xca --no-gui --database fixture.xdb --password pass:service-test-db-pass --keygen RSA:2048 --name fixture-rsa
xca --no-gui --database fixture.xdb --password pass:service-test-db-pass --crlgen fixture-ca --name fixture-crl
```

Regenerate it only with a build of the schema it stands for; a dump made by a newer schema no
longer tests the upgrade.

## `schema8-bxc2.sql`

SQL dump (Python `sqlite3.iterdump()`) of a database created by bxc-main `2700efa7`, database schema
8 with fork migration `bxc_schema` 2 (`audit_log`, `audit_keys`). `test_service_audit::upgradeKeyTypeColumn`
loads it and checks that `bxc_schema` 3 (BTD-16) widens `public_keys.type` from `CHAR(4)` to
`VARCHAR(32)`, turns the cut-off `ED25` into `ED25519`, keeps every other row and writes no audit
entry; `test_service_audit::upgradeWaitsForPassword` checks that a rejected password leaves it
unchanged (BTD-117).

Content: three generated keys, `fixture-ed25519` (stored type `ED25`), `fixture-rsa` (RSA 2048) and
`fixture-ec` (EC prime256v1), and their three `key.generate` audit entries. The private keys are
throwaway test keys, encrypted with `ServiceTestCase::dbPassword`.

Created in the dev container (`deploy/build/linux/dev.py`) with the bxc-main `2700efa7` build:

```
xca --no-gui --database fixture.xdb --password pass:service-test-db-pass --keygen ED25519 --name fixture-ed25519
xca --no-gui --database fixture.xdb --password pass:service-test-db-pass --keygen RSA:2048 --name fixture-rsa
xca --no-gui --database fixture.xdb --password pass:service-test-db-pass --keygen EC:prime256v1 --name fixture-ec
python3 -c "import sqlite3; open('schema8-bxc2.sql','w').write('\n'.join(sqlite3.connect('fixture.xdb').iterdump())+'\n')"
```
