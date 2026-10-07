# Changelog

All notable changes, newest first. Early history follows the Git log
(`v30.1` → `v49.0`); only phase-level milestones are listed there.

## Unreleased — X7 visual polish (display-only, v53.1 candidate)

- **Branding:** product identity `RECONIP / X7 SECURITY INTELLIGENCE / X7ΛΞX`
  in banner, footer and report footers. Command (`reconip` / `reconip.py`) unchanged.
- **Color semantics:** green LOW/VERY_LOW, yellow MODERATE, red HIGH/VERY_HIGH;
  confidence VERY_LOW renders dim (uncertain ≠ dangerous). Thresholds and
  scoring untouched.
- **Executive summary:** live anomaly counts (`HIGH / MODERATE / LOW`) plus a
  derived `ACTION` hint and an evidence-philosophy reminder. Values computed
  from the report; nothing hardcoded.
- **Anomalies:** `[SEVERITY]` badges, full messages (no 80-char cut), folded
  narrow-terminal layout. Evidence completeness unchanged.
- **Reports:** `00 REPORTS` gains a `[✓]` status column with folded paths.
- **Threat intel:** failure line lists failed/not-configured provider names
  with `[!]` / `[✓]` markers; failures stay in the evidence/limitations model.
- **Readability:** widened display truncation for ASN/org/issuer fields
  (config `display.truncation`; reports keep full values).
- **Repo:** hardened `.gitignore` (venv, `*.db`, logs, `reports/`, secrets),
  added `config.yaml.example` and `SECURITY.md`, rewrote `README.md` for
  public release. No detection, scoring or report-schema changes.

## v53.0 — Metrics & distribution

- **K4:** Prometheus metrics — `reconip_scans_total{status}`,
  `reconip_scan_duration_seconds` (count/sum), `reconip_threat_score{target}`,
  `reconip_provider_errors_total{provider}`. Served at `GET /metrics`
  (`Accept: text/plain`) and `python3 reconip.py --metrics`.
- **K5:** `README.md`, `LICENSE` (MIT), `CHANGELOG.md`, `docs/usage.md`,
  `docs/providers.md`, `examples/` (sample inputs, `prometheus.yml`,
  server smoke test).
- **K6:** `docs/evidence-driven-osint.md` article draft; publishing and
  outreach checklist left to maintainers.

## v52.0 — Team & SOC operation (Phase K, part 1)

- **K1:** `--server --port/--host` API server mode (`POST /scan`,
  `GET /scan/{id}`, `GET /scan/{id}/report`, `GET /health`); invalid scan
  targets now `400 invalid_target` instead of `500`.
- **K2:** `--filter "threat > 50"` result scoping, `--report-only-alerts`;
  batch worker ceiling raised 16 → 32.
- **K3:** `--schedule "0 */6 * * *"` cron monitoring with
  `--alert-on-change` and `--notify-webhook` (merged with `--alert-webhook`).

## v50.0 — Validation, alerts, report formats (unreleased stages J4–J6)

- **J4:** automated safe validation on every vulnerability candidate
  (`validation.status`: `CONFIRMED` / `REJECTED` / `INCONCLUSIVE`).
- **J5:** `--watch`, `--compare-with`, `--alert-file/webhook/email`;
  five alert types (certificate, DNS, threat increase, subdomain, port).
- **J6:** `--format sarif`, `--format dot`, `--format pdf` (repeatable).

## v49.0 — Phase F freeze

Final fix and freeze (see Git log).

## v48.x — Phase C3 stabilization & polish

Progress mechanics, duplicate-output cleanup, Rich logging integration,
visual polish, header/profile fixes (see Git log `eb9d1f4` → `262484d`).

## v46.x — Terminal display (Phase B) / v46 clean baseline

Full rich terminal rendering, sections 01–18, reports summary.

## v30–v33 — Core engines

Core stabilization (v30.2), Evidence Engine (v31), Source Reliability (v32),
Threat Intel 2.0 (v32.1), DNS Intel (v33), Infrastructure Intel (v33.1).
