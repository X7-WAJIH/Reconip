# Security Policy

## Scope

RECONIP is a **defensive, evidence-driven reconnaissance tool**: passive DNS,
certificates, routing data and threat-intel feeds. Active port scanning and
banner grabbing are **disabled by default** and require explicit allowlisting.

## Authorized use only

Use RECONIP only against systems you are authorized to investigate:

- your own infrastructure, or
- customer / research targets with written permission, or
- public infrastructure within an explicit program scope.

Respect provider terms of service and rate limits. Do not use this tool to
facilitate unauthorized access. The authors accept no liability for misuse.

## Secrets handling

- API keys are read from **environment variables only** (see `config.yaml`
  `providers.*.api_key_env` and `--show-auth`).
- Never commit keys, tokens, or private URLs. `config.yaml.example` ships
  with empty key slots.
- Logs and reports redact credential-shaped values; if you suspect a leak,
  rotate the key and open an issue with the redacted excerpt.

## Reporting a vulnerability

If you find a security issue in RECONIP itself (e.g. credential exposure,
command injection, path traversal, unsafe deserialization):

1. **Do not** open a public issue with exploit details.
2. Contact the maintainers through the repository's private channel with:
   - affected version (`--version`), config profile, and reproduction steps,
   - the minimum log/report excerpt that demonstrates the issue (redact keys).
3. Allow reasonable time for a fix before any disclosure.

## Defensive posture (v53.0 review)

- Subprocess use is allowlisted (`whois` only), argv-based (`shell=False`),
  with character denylist and timeout.
- YAML parsing uses the safe loader (`CSafeLoader` / `safe_load`).
- Report filenames sanitize the target (`[^a-zA-Z0-9._-]` → `_`).
- No exploitation, no payload delivery, no credential brute-forcing.
