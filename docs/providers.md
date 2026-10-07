# Providers

Threat-intel providers are declared in `config.yaml` under `providers:`.
Each block carries its own `remediation` (why a key is needed, which env
var, signup URL, free tier, verification command). `python3 reconip.py
--list-providers` prints the same inventory from the live config.

## State model

- `enabled: false` — never queried, never mentioned in reports. Silent.
- `enabled: true` + key present — queried normally.
- `enabled: true` + key missing — **one** summary warning per run; the
  provider reports `NOT_CONFIGURED` (never `FAILED`). Missing data is
  distinguished from negative data everywhere.

Secrets live in environment variables only — never in `config.yaml`, logs,
or reports (values are redacted by key name and by content pattern).

## Keyless (enabled by default)

| Provider | Data | Notes |
|---|---|---|
| `spamhaus_drop` | Spamhaus DROP nets (CIDR list) | Public list |
| `feodo` | Feodo Tracker botnet C2 IPs | Public list |
| `sslbl` | SSL blacklisted IPs (CSV) | Public list |
| `cins` | CI Army bad-guys list | Public list |

## Keyed (disabled until configured)

| Provider | Env var | Free tier | Signup |
|---|---|---|---|
| `abuseipdb` | `ABUSEIPDB_API_KEY` | 1000 req/day | https://www.abuseipdb.com/account/api |
| `virustotal` | `VIRUSTOTAL_API_KEY` | 500 req/day, 4 req/min | https://www.virustotal.com/gui/my-apikey |
| `threatfox` | `THREATFOX_API_KEY` | Unlimited, personal use | https://auth.abuse.ch/ |
| `alienvault` | `ALIENVAULT_API_KEY` | Unlimited, community | https://otx.alienvault.com/settings |
| `greynoise` | `GREYNOISE_API_KEY` | 50 req/week (community) | https://viz.greynoise.io/account/api-key |
| `urlhaus` | `URLHAUS_API_KEY` | Unlimited, personal use | https://auth.abuse.ch/ |

To enable one:

```bash
export ABUSEIPDB_API_KEY=...        # 1. obtain key
# 2. flip enabled: false → true in config.yaml
python3 reconip.py 8.8.8.8 --test-providers   # 3. verify
```

## Reliability model

Each provider declares `reliability` (weight of its word) and `weight`
(influence on the aggregate). The engine separates **threat confidence**
(what providers agree on) from **data confidence** (freshness, coverage,
agreement) — a single dead provider lowers confidence, never the verdict.
Per-provider health (ok/fail/timeout/rate-limit counters, circuit state)
feeds `reconip_provider_errors_total` and `GET /health`.
