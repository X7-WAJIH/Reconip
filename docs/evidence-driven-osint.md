# Evidence-Driven OSINT: Why Your Scanner Should Say "I Don't Know"

*Draft — the design philosophy behind ReconIP. Written for practitioners
who have been burned by scanner output that states opinions as facts.*

## The problem: verdicts without evidence

Most reconnaissance tools print conclusions: "VULNERABLE", "MALICIOUS",
"CRITICAL". Underneath, the chain is often one witness deep — a version
string in a banner, matched against a CVE range, rendered as a finding.
Three quiet leaps hide inside that output:

1. The banner is trusted as fact (banners lie; honeypots speak fluent nginx).
2. A version *range match* is presented as *presence of the bug*.
3. Absence of data ("provider timed out") is rendered the same as
   negative data ("provider says clean").

Each leap is small. Together they convert a lead into an incident ticket.

## The discipline: evidence, then verdict — usually neither

Evidence-driven OSINT inverts the pipeline. The unit of work is not the
*finding* but the *observation*: who said it, when, how fresh is it, how
much is that source worth? A CVE matched to `nginx/1.24.0` is stored as a
**candidate** — with the CPE, the affected range, the technology
confidence, and a validation requirement attached. The report language is
deliberate: *candidate, not confirmation; vulnerability, not exploit;
exploit, not impact.*

Then comes the part scanners skip: a **safe validation probe**. One
read-only `HEAD /`, one `Server` header, three possible honest answers —
`CONFIRMED`, `REJECTED`, `INCONCLUSIVE`. No payloads, no login attempts, no
version-specific gadgetry. When the header is absent or the product class
has no safe probe (SSH, DNS, mail stacks), the answer is `INCONCLUSIVE`,
and the report says so in plain language instead of padding the silence.

## Confidence is not accuracy

ReconIP tracks four separate confidences because they fail independently:

- **Data confidence** — coverage, freshness, agreement between sources.
- **Threat confidence** — what providers actually agree on.
- **Geo confidence** — approximate by nature, worse behind anycast and CDNs.
- **Assessment confidence** — the tool's own estimate of how much it knows.

A low-confidence report is not a bad report. It is an honest one, and it
tells the analyst exactly which additional source would raise it.

## What this means operationally

- **Triage by validation status**, not by CVSS alone. `CONFIRMED` first,
  `INCONCLUSIVE` with high exposure second, `REJECTED` never.
- **Monitor the diff, not the snapshot.** Certificate rotations, DNS
  changes, threat-score deltas, new subdomains and new ports are the
  signals; a scheduled `--schedule` loop with `--alert-on-change` turns
  them into webhooks instead of tickets.
- **Audit the tool.** A 20-check validation matrix (determinism over five
  replayed runs, error isolation per stage, snapshot retention caps) runs
  before every release. Trust, but `python3 validate_matrix.py`.

The scanner's job is not to be certain. It is to be *checkable* — every
claim traceable to evidence, every gap labeled, every probe safe enough
to run twice.
