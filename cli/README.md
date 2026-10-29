# bxc-pki command line

`bxc-pki` is the headless command line of the bxc-pki fork (BTD-41, part 1; bxc-pki
`docs/PLAN.md` 8.1). It works directly on an XCA database (default `./bxc-pki.xdb`), links only
`xcacore` (no Qt Gui, Widgets or Help; `test_core_link` checks the binary) and never prompts
unless `--interactive` is given.

```
bxc-pki init --cn "BxC Lab Root" --validity P20Y --password env:PKI_PW
bxc-pki init --cn "BxC OT Issuing" --parent "BxC Lab Root" --path-len 0 --password env:PKI_PW
bxc-pki request-cert --cn plc10 --ip 192.168.0.10 --dns plc10.lab --password env:PKI_PW
bxc-pki sign plc10 --ca "BxC OT Issuing" --template TLS_server --validity P1Y --password env:PKI_PW
bxc-pki list --password env:PKI_PW
bxc-pki show plc10 --type certificate
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
- A failing OID initialisation stops every command before the database is opened
  (`oid_init_failed`).
- Every write goes through the service layer, which writes the audit entries (channel `cli`,
  actor `os:<login>`). `list` and `show` only read and write no audit entry (PLAN.md 6.1).

Result document of `init`, `request-cert`, `sign` (schema `urn:bxc-pki:schema:cli-result:v1`):

```json
{"schema": "urn:bxc-pki:schema:cli-result:v1", "command": "sign", "plan": false,
 "objects": [{"type": "certificate", "id": 7, "name": "plc10", "validity_capped": false,
              "document": {"schema": "urn:bxc-pki:schema:certificate:v1", "...": "..."}}]}
```

`objects` lists only what was actually written, after the commit. A certificate entry carries
`validity_capped` and, when capped at the issuer chain, `requested_not_after` (BTD-51).

## Design (prepared for `bootstrap`, BTD-166)

| Piece | File | What it does |
|---|---|---|
| `OptionSpec`, `parseOptions()` | `options.cpp` | one strict parser for every command: global options (`Registry::globalOptions()`) plus the command's; typed values (flag, string, integer, ISO 8601 duration, RFC 3339 date-time, secret source, reference), required options, conflicting pairs, positional limits, reserved options (`not_supported`) |
| `Command`, `Registry` | `cli.h`, `commands.cpp` | name, summary, options, conflicts, `writes`, handler; `registerCommands()` adds them; the help is generated from the registry |
| `CommandContext` | `cli.h` | what a handler gets: parsed options, the `ServiceContext` (channel `cli`), `plan`, `text`, the result collector, the current step (for "object X was not written" errors) |
| handlers | `commands.cpp` | functions over the service layer (`db_key::newKey`, `db_x509req::newRequest`, `db_x509::newCert`); they neither open nor commit a transaction and record each written object in the collector |
| `ResultCollector` | `framework.cpp` | takes the JSON document of each written object at once (an object of a rolled back transaction is gone afterwards) and becomes one result document per command |
| `runInTransaction()` | `framework.cpp` | runs a list of handlers in ONE transaction it owns: commit, or with `--plan` a deliberate rollback (nothing written, ids null in the result). On failure everything is rolled back and the failure audit entries of the service calls are written again after the rollback (`AuditFailureCapture`, `lib/audit.h`) |
| references | `framework.cpp` | `--ca`, `--parent`, `--key`, `--template` and `show` take a database id or a unique name; an ambiguous name is `ambiguous_reference` with the candidates |
| input checks | `input.cpp` | RFC 4514 subjects (order kept, multi-valued RDNs, DC, UTF8String), strict IP/URI/DNS/e-mail SANs, RFC 3339, ISO 8601 durations (`IsoDuration`, `lib/issuance.h`), key types |

`bootstrap` plugs in as one more command: it parses its file into the same `Options`-like inputs,
calls `runInTransaction(ctx, steps)` with one handler per object of the file, so the whole PKI
is written in one transaction (all or nothing), and `--plan` evaluates every step and rolls back.
Idempotence (skip existing objects) belongs to the bootstrap handlers.

Design ideas (job validation, staged atomic output with owner-only key files, name-constraint check over the issuer chain) follow jstillwa/xca --certgen by John Stillwagen (https://github.com/jstillwa/xca, evaluated in bxc-pki docs/findings/BTD-53-certgen-evaluation.md). No code was copied.

## Rules (bxc-pki PLAN.md 8.4) in part 1

- Rule 1: `--path-len` only when given; absent means no constraint, never 0.
- Rule 2: serials come from `db_x509::getUniqueSerial()` (CSPRNG, positive, 9..20 octets).
- Rule 3: `sign` takes keyUsage and extended key usage only from `--template`; without one:
  CA:FALSE, keyUsage digitalSignature (plus keyEncipherment for RSA), no EKU. From the request
  only the subjectAltName is copied (`IssuanceSpec::requestExtensionNids`).
- Rule 4: `--dns`, `--ip`, `--uri`, `--email`, strictly checked; a request with a URI only is
  allowed (then the SAN is critical); the CN never comes from an IP address or URI.
- Rule 6: `--validity <ISO 8601 duration>` (`IssuanceSpec::validity`), `--not-before`,
  `--not-after` (RFC 3339), `--backdate`; the end is capped at the issuer chain
  (`IssuanceSpec::effectiveNotAfter()`) and the cap is reported.
- Rule 11: no prompt without `--interactive`; every failure exits non-zero with an error object
  naming the object and the cause; the result lists only written objects.
- Rule 12: see input checks; no template object is shared between calls.
- Rules 1, 3 and 5 checks of the service layer (BTD-55, BTD-65): `cli/test/cli_sign_checks.cmake`,
  switched on with `-DBXC_PKI_SIGN_CHECKS=ON` once they are merged.

## Tests

`ctest -L cli` (build container, `deploy/build/linux/dev.py test -L cli` in bxc-pki): the
scripts in `cli/test/` run the binary against fresh databases; each keeps a `transcript.log`
of every call in its work directory under the build tree. `cli_fixture` is a test helper that
creates what part 1 cannot (templates with a custom EKU).
