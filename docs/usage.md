# Usage

Profiles: `quick` (triage) · `standard` (default) · `deep` · `forensic`
(live evidence, no cache). Select with `--profile`.

## Single target

```bash
python3 reconip.py 8.8.8.8 --profile quick
python3 reconip.py example.com --format sarif --format dot   # repeatable
python3 reconip.py example.com --deterministic               # byte-reproducible JSON
```

## Batch (up to 1000 targets per file)

```bash
python3 reconip.py --input targets.txt --workers 20 --output-dir reports/batch_01/
python3 reconip.py --input targets.txt --filter "threat > 50" --report-only-alerts
```

`--filter` fields: `threat`, `coverage`, `anomalies`, `ports`,
`threat_confidence`. Operators: `> >= < <= == !=`, joined with `and`/`or`.
A bad expression exits 2 before any scan runs. Filtering scopes the listing
and summary — pipeline files on disk are the raw record and are kept.
Failures are never filtered out of the exit code.

## Change detection

```bash
python3 reconip.py example.com --watch 3600 --alert-file changes.log
python3 reconip.py example.com --compare-with 2026-09-01
```

Alert types: certificate change, DNS change, threat score increase, new
subdomain, new port. Channels: `--alert-file`, `--alert-webhook`,
`--alert-email` (localhost SMTP, fail-soft).

## Continuous monitoring

```bash
python3 reconip.py --input watchlist.txt --schedule "0 */6 * * *" \
  --alert-on-change --notify-webhook https://hooks.example.com/reconip
```

Standard 5-field cron. First cycle runs immediately. `--alert-on-change`
notifies only on detected change; otherwise a per-cycle summary is also
sent. `--watch-count N` caps cycles (useful for testing). `--schedule` and
`--watch` are mutually exclusive.

## Server mode

```bash
export RECONIP_API_TOKEN=secret
python3 reconip.py --server --port 8080
```

| Method & path          | Meaning                              |
|------------------------|--------------------------------------|
| `POST /scan`           | `{"target": "…"}` or `{"targets": […]}` → `202 {job_id}` |
| `GET /scan/{id}`       | job state (result embedded when done) |
| `GET /scan/{id}/report`| final report + export paths          |
| `GET /health`          | liveness + provider health           |
| `GET /metrics`         | JSON, or Prometheus text with `Accept: text/plain` |
| `GET /providers`       | provider inventory                   |

Invalid targets return `400 invalid_target`; unknown jobs `404`.
Without a token (and `phase_m.require_auth: true`) every request is `401` —
the server warns about this at startup.

## Metrics

```bash
python3 reconip.py --metrics                            # exposition text
curl -H 'Accept: text/plain' http://127.0.0.1:8080/metrics
```

Scrape with `examples/prometheus.yml`.

| Metric | Type | Labels |
|---|---|---|
| `reconip_scans_total` | counter | `status="success\|failed"` |
| `reconip_scan_duration_seconds` | summary | (`_count`, `_sum`) |
| `reconip_threat_score` | gauge | `target="…"` |
| `reconip_provider_errors_total` | counter | `provider="…"` |

Counters are in-process (reset on restart) — the standard pattern for a
scan tool; persist via Prometheus.

## Diagnostics

```bash
python3 reconip.py --list-providers        # inventory + how to enable
python3 reconip.py --show-auth             # key state, no secrets shown
python3 reconip.py 8.8.8.8 --test-providers # read-only, no writes
python3 reconip.py --health                # JSON health snapshot
python3 validate_matrix.py                 # 20-check release matrix
```
