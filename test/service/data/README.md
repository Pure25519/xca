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

## `json/`

Fixtures of the JSON documents (BTD-39), made once with OpenSSL 4.1 in the dev container by
`json/gen.sh` (fixed serials and dates, so the documents do not change):

| File | Content |
|---|---|
| `ca.crt`, `ca.key` | EC P-256 CA "O=BxC Lab, CN=JSON Test CA", serial `4D2E8B19…`, 2026-10-01 to 2036-10-01 |
| `device.csr` | request "O=BxC Lab, OU=Prüfstand, CN=plc11" (UTF-8) with SAN, EKU and key usage as extension request, `unstructuredName` and the challenge password `Chall-Secret-42` |
| `device.crt`, `device.pub` | the device certificate issued by the CA (serial `A1B2C3D4…`) and its public key |
| `ca.crl` | CRL number 1 of the CA, the device certificate revoked with reason keyCompromise |
| `rsa-enc.key` | RSA 2048 as encrypted PKCS#8, password `Import-Secret-11` |
| `ec.key`, `own.key` | EC P-384 and Ed25519 keys; `own.key` gets the password `Own-Secret-77` of its own in the tests |

The `*.json` files are the expected documents of `test_service_json.cpp`: `<fixture>.json` for
each object, `stored.xca.json` and `predefined.xca.json` for the templates the test makes, and
`items.json`, `issuers.json`, `index.json`, `hierarchy.json` for the lists. Ids are those of a fresh
database in the import order of the test; the test checks the creation date against the item and
compares the rest unchanged. All keys are throwaway test keys.
