# RECONIP

![RECONIP banner](img/reconip-banner.png)

## X7 Security Intelligence — X7ΛΞX

Evidence-driven IP reconnaissance and intelligence platform.
Every claim carries evidence. Every number answers *why*.

```
RECONIP
X7 SECURITY INTELLIGENCE
X7ΛΞX
```

---

## 1. Description

RECONIP scans an **IP address or domain** through 13+ intelligence stages —
geo/ASN/RDAP, network, DNS, certificates (live handshake + CT), passive DNS,
historical snapshots, multi-provider threat intel, infrastructure correlation,
attack surface, technology fingerprinting, vulnerability *candidates*, anomaly
detection, confidence and scoring — and assembles an **18-section report**
(sections `01`–`18`, plus `00 REPORTS`).

Design principles:

- **Evidence > assumption.** Every finding links to the evidence that produced it.
- **UNKNOWN > false certainty.** No banner, no version — never guessed.
- **Candidate ≠ confirmed vulnerability.** A CVE matching a version string is a lead.
- **Open port ≠ vulnerability.** Active scanning is disabled by default.
- **Score ≠ verdict.** Scores are explainable estimates, not conclusions.
- **Confidence ≠ accuracy.** Confidence is the tool's own estimate of how much it knows.

## 2. Features

Implemented capabilities (all verified in `reconip.py` / `config.yaml`):

- IP intelligence (geo, country/city, coordinates)
- ASN intelligence (ASN, prefix, RIR, allocation, routing origin)
- Network intelligence (organization, abuse contact, related prefixes)
- DNS intelligence (A, AAAA, PTR, NS, MX, TXT, CAA, SOA, CNAME; TTL, mail and security checks)
- Certificate intelligence (live TLS handshake + crt.sh CT history, SANs, fingerprints, expiry/weak-algo checks)
- Passive DNS (timeline, lifecycle, churn, related domains)
- Historical intelligence (SQLite snapshots, field-level diff with severity map)
- Threat intelligence (abuseipdb, virustotal, alienvault/OTX, urlhaus, threatfox, feodo, sslbl, greynoise, cins, spamhaus_drop — keyless lists enabled by default, keyed APIs opt-in)
- Infrastructure correlation (graph of shared ASN/prefix/org/domain/NS/MX/cert with confidence)
- Attack surface analysis (imported services; active port scan/banner grab **disabled by default**, allowlist-gated)
- Technology fingerprinting (passive hints; active probing disabled by default; `UNKNOWN` when evidence is insufficient)
- Vulnerability candidate identification (version → CVE candidates + read-only safe validation: `CONFIRMED` / `REJECTED` / `INCONCLUSIVE` — never exploits)
- Evidence tracking (every value carries source, timestamp, confidence, freshness, status)
- Confidence scoring (data / threat / geo / assessment, with guardrails)
- Reports: **JSON, HTML, Markdown, CSV, STIX 2.1, MISP** (plus opt-in **SARIF**, **Graphviz DOT**, **PDF** via repeatable `--format`)
- Batch scanning (up to 1000 targets/file, `--filter`, `--report-only-alerts`)
- Monitoring (`--watch`, `--compare-with`, `--schedule` + `--alert-on-change`, file/webhook/email alerts)
- API server mode + Prometheus metrics (`GET /metrics`, `--metrics`)
- Profiles: `quick` (triage) · `standard` (default) · `deep` · `forensic` (no cache, full raw evidence)
- Local cache (SQLite, per-provider TTLs, stale/expired semantics — failed providers are never cached)

## 3. Architecture

```
                ┌─────────────┐
                │  CLI / API  │  argparse entry (main) · --server · batch
                └──────┬──────┘
                       ▼
          ┌───────────────────────┐
          │   Pipeline (recon)    │  geo → asn/rdap → dns → certs → passive DNS
          │  13+ collectors       │  → history → threat → correlation → attack
          │  evidence objects     │  surface → tech → vuln → anomalies → confidence
          └──────┬────────────────┘
                 ▼
   ┌─────────────────────────────┐
   │  Report builder (sections   │  01 target … 18 next investigation
   │  01–18) + exporters         │  JSON/HTML/MD/CSV/STIX/MISP (+SARIF/DOT/PDF)
   └──────┬──────────────────────┘
          ▼
   ┌─────────────────────────────┐
   │  Terminal renderer (rich)   │  banner · header · 01–18 · 00 REPORTS · footer
   │  display-only, read-only    │  never recomputes scores or evidence
   └─────────────────────────────┘
```

- **Collectors** return `Evidence` (source, timestamp, confidence, freshness, status).
- **Report builder** assembles sections `01_target_profile` … `18_next_investigation`.
- **Terminal renderer** (`render_all`, `_render_01` … `_render_18`) is display-only.
- **State**: `reconip.db` (history snapshots) and `reconip_cache.db` (provider/DNS cache) — local only, git-ignored.
- **Config**: `config.yaml` (see §6). Secrets come from environment variables only.

## 4. Installation

Exact commands (Python ≥ 3.10, 3.11+ recommended):

```bash
git clone <your-repo-url> reconip && cd reconip
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp config.yaml.example config.yaml   # optional; defaults already work keyless
```

Verify:

```bash
python3 reconip.py --version
python3 reconip.py --list-providers
python3 reconip.py 8.8.8.8 --test-providers   # read-only provider check
```

The `reconip` executable name refers to `reconip.py` — run it as
`python3 reconip.py …` (or symlink/wrap it as `reconip` if desired).
No command has been renamed.

## 5. Usage

```bash
python3 reconip.py 8.8.8.8 --profile quick        # fast triage (~seconds)
python3 reconip.py 8.8.8.8                        # full standard scan
python3 reconip.py example.com --profile deep     # extended scan
python3 reconip.py example.com --profile forensic # no cache, full raw evidence

python3 reconip.py --list-providers                # what is queried, and why
python3 reconip.py --show-auth                     # key / env-var state (no secrets printed)
python3 reconip.py 8.8.8.8 --test-providers        # read-only provider health

python3 reconip.py example.com --format sarif --format dot   # opt-in formats (repeatable)
python3 reconip.py example.com --deterministic               # byte-reproducible JSON

# Batch (up to 1000 targets per file)
python3 reconip.py --input targets.txt --workers 20 --output-dir reports/batch_01/
python3 reconip.py --input targets.txt --filter "threat > 50" --report-only-alerts

# Change detection / monitoring
python3 reconip.py example.com --watch 3600 --alert-file changes.log
python3 reconip.py example.com --compare-with 2026-09-01
python3 reconip.py --input watchlist.txt --schedule "0 */6 * * *" \
  --alert-on-change --notify-webhook https://hooks.example.com/reconip

# API server + metrics
export RECONIP_API_TOKEN=secret
python3 reconip.py --server --port 8080
curl -H 'Accept: text/plain' http://127.0.0.1:8080/metrics
python3 reconip.py --metrics
```

Full CLI reference: `docs/usage.md`. Provider keys/free tiers: `docs/providers.md`.

## 6. Configuration

`config.yaml` (copy from `config.yaml.example`) controls providers, timeouts,
reliability weights, profiles, display, cache and reports. Key points:

- **Providers** (`providers:`): each entry has `enabled`, `auth_type`, `api_key_env`,
  `timeout`, `reliability`, `weight`. Disabled providers are never queried and emit
  no warnings. To enable a keyed provider: obtain the key → `export ENV_VAR=…` →
  set `enabled: false` → `true` → verify with `--test-providers`.
- **API keys** (`api_keys:` + `auth:`): secrets are read from **environment variables
  only** and are redacted from logs and reports. Never write keys into the YAML.
- **Profiles** (`profiles:` + `default_profile: standard`): `quick` / `standard` /
  `deep` / `forensic` select provider sets, sections and timeout budgets.
- **Display** (`display:`): banner/header/footer toggles, `mode` (terminal/minimal/quiet),
  `box_style`, `colors`, `width`, per-field `truncation` (display-only — reports keep
  full values).
- **Identity** (`identity:`): `tool_name: RECONIP`, `tagline: X7 SECURITY INTELLIGENCE`,
  product signature `X7ΛΞX` (used when `operator_signature` is null).
- **Performance/cache** (`performance:`, `cache:`): worker counts, per-provider
  timeouts/rate limits, timeout budget, TTLs. Forensic profile disables cache.
- **Reports** (`reports:`): `output_dir`, `formats`, `sections`, `deterministic`.

## 7. Output

Terminal output (rich) — banner, target header, sections `01`–`18`, `00 REPORTS`, footer:

```
╭─ 01 │ TARGET PROFILE ─────────────────────────╮
│  Target / IP / ASN / Org / Prefix / RIR …      │
╰────────────────────────────────────────────────╯

╭─ 02 │ EXECUTIVE SUMMARY ──────────────────────╮
│  Assessment Confidence + 6 scored bars         │
│  Anomalies  1 HIGH / 2 MODERATE / 0 LOW       │
│  ACTION  → Manual review recommended           │
│  Score ≠ verdict. Confidence ≠ accuracy.      │
╰────────────────────────────────────────────────╯
…
╭─ 00 │ REPORTS ────────────────────────────────╮
│  [✓] JSON      reports/8.8.8.8_….json         │
│  [✓] HTML      reports/8.8.8.8_….html         │
╰────────────────────────────────────────────────╯
── RECONIP v53.0 • X7ΛΞX • X7 SECURITY INTELLIGENCE ──
```

Colors are semantic: **green** safe/low, **yellow** moderate/warning,
**red** high/critical/failed, **cyan** headings/metadata, **magenta**
X7 accents only, **dim** secondary, **white** key values. Provider failures
(`[!] … failed`) and `UNKNOWN` states are always shown — `UNKNOWN ≠ SAFE`.

## 8. Reports

Every scan writes timestamped files to `reports/` (default: JSON, HTML,
Markdown, CSV, STIX, MISP):

| Format   | File pattern        | Notes                                              |
|----------|---------------------|----------------------------------------------------|
| JSON     | `*_*.json`          | SIEM-compatible, sorted keys, full evidence        |
| HTML     | `*_*.html`          | Human-readable, capped lists (`max_*_in_html`)     |
| Markdown | `*_*.md`            | Human-readable, X7 footer                          |
| CSV      | `*_*.csv`          | `section,category,severity,value,evidence,source`  |
| STIX 2.1 | `*_*.stix.json`     | Identity + indicator + observed-data bundle        |
| MISP     | `*_*.misp.json`     | Event with attributes                              |
| SARIF    | `*_*.sarif`         | Opt-in (`--format sarif`), GitHub code scanning    |
| DOT      | `*_*.dot`           | Opt-in (`--format dot`), infrastructure graph       |
| PDF      | `*_*.pdf`           | Opt-in (`--format pdf`, needs weasyprint)          |

Report generation behavior is unchanged by display settings; truncation and
colors affect the terminal only.

## 9. Evidence philosophy

```
Evidence  >  assumption
UNKNOWN   >  false certainty
Candidate != confirmed vulnerability
Open port != vulnerability
Score     != verdict
Confidence != accuracy
```

- An **anomaly** is a deviation from expectation, not a verdict.
- A **shared relationship** (ASN, cert, NS) is shared infrastructure, not shared intent.
- A **low-confidence** report is not a bad report — it is an honest one.
- Every limitation and provider failure is part of the report.

## 10. Limitations

- Passive reconnaissance + keyless feeds by default; keyed providers need opt-in keys.
- Threat verdicts depend on provider coverage at scan time — absence of data ≠ absence of threat.
- Geo data conflicts on anycast/CDN infrastructure are expected and reported, not hidden.
- Technology versions come from passive hints; `UNKNOWN` is returned when evidence is insufficient.
- CVE candidates require on-target validation; safe validation is read-only and may return `INCONCLUSIVE`.
- Active port scanning / banner grabbing are disabled by default and require explicit allowlisting.
- No exploitation is ever performed.

## 11. Legal / ethical use

Use RECONIP **only** against systems and IP addresses you are **authorized** to
investigate — your own infrastructure, your customers' (with written permission),
or public infrastructure within the scope of a bug-bounty / research program.
Respect provider terms of service and rate limits. The authors accept no
liability for misuse. See `SECURITY.md`.

## 12. Author / branding

```
X7
X7ΛΞX — X7 Security Intelligence
```

RECONIP is maintained under the **X7** research identity. No personal names are
published in this repository.

## 13. Validate & license

```bash
python3 validate_matrix.py                        # full 20-check matrix
python3 validate_matrix.py --only V1,V2,V11,V13,V16 --no-pty
```

MIT — see `LICENSE`. Changelog: `CHANGELOG.md`.
