# xca-server metrics and probes (BTD-163)

## Probes

The probes run on the health listener, which is optional and set in `xca-server.json` (`health`):

- it uses plain HTTP and needs no client certificate;
- its address is a loopback address unless `allow_remote` is `true`;
- its port must differ from the port of the TLS listener.

| Request | Answer |
|---|---|
| `GET /health` | `200 {"status":"ok"}`: the process answers. No database job. |
| `GET /ready` | `200 {"status":"ok"}`, or `503 {"status":"not_ready"}` |
| anything else | `404`, no body is read |

`/ready` is ready only when all of these hold:

- the database is open and the TLS listener is bound;
- a job on the database worker takes and gives back the write lock that an audit entry needs (`BEGIN IMMEDIATE`, `ROLLBACK`), within `min(limits.job_timeout_s, 2)` seconds;
- the database is not read-only;
- the last audit entry of the server was written.

While another process holds the database lock, or the worker is busy, the answer is not ready. Only one readiness job waits at a time. `/ready` writes no audit entry.

## Metrics

`GET /v1/metrics` (operation `getMetrics`) runs on the mTLS listener:

- the roles `ca_admin` and `auditor` may read it;
- a role that is limited to some CAs gets `403` (reason `ca_scope_unfiltered`);
- the format is the Prometheus text format 0.0.4 (`text/plain; version=0.0.4`).

Labels hold ids, serials and fingerprints, never a subject or a name.

- **`ca_id`** is the bootstrap id of the CA (for example `ca-a`). Without one it is `item-<item id>`, and `none` when the issuer is not in the database.
- **`serial`** is the serial number in hex, as the database stores it.
- **`fingerprint`** is the SHA-256 of the certificate DER in lowercase hex.

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `xca_audit_entries_total` | counter | `action`, `channel`, `result` | entries of the audit log |
| `xca_issuances_total` | counter | `channel` | `certificate.issue` with result `success` |
| `xca_revocations_total` | counter | `channel` | `certificate.revoke` with result `success` |
| `xca_errors_total` | counter | `channel`, `action` | entries with result `failure` or `denied` |
| `xca_ca_certificate_expiry_seconds` | gauge | `ca_id`, `fingerprint` | seconds until a CA certificate expires (negative: expired) |
| `xca_certificate_expiry_seconds` | gauge | `ca_id` (issuer), `serial` | the same for every certificate, only up to `metrics.certificates_max` certificates |
| `xca_metrics_certificates_limited` | gauge | | `1` when the per-certificate values are left out |
| `xca_certificates` | gauge | `ca_id` (issuer) | certificates per issuing CA |
| `xca_certificates_expiring` | gauge | `ca_id`, `within` (`7d`, `30d`) | certificates that expire within 7 or 30 days |
| `xca_certificate_min_expiry_seconds` | gauge | `ca_id` | the shortest remaining lifetime per issuing CA |
| `xca_audit_checkpoint_age_seconds` | gauge | | seconds since the last `audit.checkpoint` entry; absent without one |
| `xca_http_request_duration_seconds` | histogram | `operation_id` | from the role check to the answer |
| `xca_db_queue_length` | gauge | | jobs waiting for the database worker |
| `xca_db_jobs_total` | counter | `state` (`done`, `failed`, `queue_full`, `timed_out`, `stopping`) | calls of the database worker by how they ended |

### Where the counters come from

The counters are read from the audit log. The log is append-only, so the counters only rise, they survive a restart, and they include the `cli` and `gui` channels.

- The first count reads the whole log.
- After that, only the entries after the last counted `seq` are read (`seq` is the primary key, so no extra index is needed).
- The result is cached for `metrics.audit_cache_s` seconds (required).

The latency, queue and job values belong to the process and start at zero.

### Configuration

Both members of `metrics` are required (condition 5 of the architecture):

- `certificates_max`: up to this many certificates the per-certificate values are given; above it only the per-CA values.
- `audit_cache_s`: how long the audit counters are reused.

## Test seam

Only in a build with tests (`BXC_PKI_TEST_SEAMS`), and only while the environment variable `BXC_PKI_TEST_SEAMS=1` is set:

- `POST /_test/stall?seconds=N` on the health listener keeps the database worker busy for N seconds (1 to 60).
- `test_release_no_seams` checks that a build without tests has no seam.
