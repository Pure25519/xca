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
