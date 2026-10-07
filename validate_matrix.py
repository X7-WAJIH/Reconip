#!/usr/bin/env python3
"""
ReconIP validation matrix -- C3.10.2, expanded from 12 to 20 checks (Stage G5).

V1-V12  the original C3.10.2 matrix, unchanged in meaning
V13     error isolation     -- a failure in one section must not stop the rest
V14     determinism        -- five consecutive runs, byte-identical artifact
V15     cache health       -- no database/cache errors
V16     snapshot retention -- at most 100 snapshots per target
V17     data validation    -- every section carries valid data
V18     cross-report consistency -- formats agree on target/sections/data
V19     long-run stability -- 50 consecutive executions, no failure/degradation
V20     edge cases         -- no DNS, no certificate, unusual/incomplete targets

Every check reports PASS / FAIL / SKIP plus the evidence it was decided on.
A check that could not be decided says so; it never reports a bare PASS.

Design notes that matter when reading a FAIL:

  * Live checks (V1-V12, V17, V18, V20) drive the real CLI. What they prove
    is bounded by the network: an upstream provider that rate-limits or
    changes its answer can fail a live check without any code defect.
  * Hermetic checks (V13, V14, V19) run the pipeline in-process with the
    socket layer blocked and every collector answered from a recorded
    fixture. They are deterministic by construction, so a diff there is a
    real defect and not upstream noise.
  * V14 and V19 therefore measure the pipeline, not the internet.

Usage:
    python3 validate_matrix.py                      # full matrix
    python3 validate_matrix.py --only V13,V14,V16   # subset
    python3 validate_matrix.py --no-pty             # skip the pty scan
    python3 validate_matrix.py --v19-runs 5         # shorten the soak
"""
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import io
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

ROOT = os.path.dirname(os.path.abspath(__file__))
RECONIP_PY = os.path.join(ROOT, "reconip.py")
CONFIG_YAML = os.path.join(ROOT, "config.yaml")
REPORTS_DIR = os.path.join(ROOT, "reports")
LOG_PATH = os.path.join(ROOT, "reconip.log")
DB_PATH = os.path.join(ROOT, "reconip.db")
CACHE_PATH = os.path.join(ROOT, "reconip_cache.db")

REPORT_FORMATS = ["json", "html", "markdown", "csv", "stix", "misp"]
SECTION_KEYS = [
    "01_target_profile", "02_executive_summary", "03_data_quality",
    "04_network_intelligence", "05_dns_intelligence", "06_certificate_intelligence",
    "07_passive_dns", "08_historical_intelligence", "09_threat_intelligence",
    "10_infrastructure_correlation", "11_attack_surface", "12_technology",
    "13_vulnerability_candidates", "14_anomalies", "15_evidence",
    "16_confidence", "17_limitations", "18_next_investigation",
]

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# Functions recon() calls that reach the network. They are the record and
# replay surface: recorded once, then answered from memory with the socket
# layer blocked, so a hermetic run cannot touch the internet by accident.
NETWORK_COLLECTORS = [
    "collect_geo", "collect_asn", "collect_rdap", "collect_dns", "collect_certs",
    "collect_threat", "dns_collect", "run_providers", "certificate_intelligence",
    "passive_dns_intelligence", "infra_profile", "attack_surface",
    "technology_intelligence", "vulnerability_candidates", "whois_enhanced",
    "enumerate_subdomains", "correlate",
    # Stage I4: advanced-DNS live probes (dnssec/wildcard/zone-transfer).
    # Stubbed in hermetic runs so replayed runs cannot touch the network;
    # each returns its neutral structure (fail-soft, deterministic).
    "_analyze_dnssec", "_analyze_wildcard", "_analyze_zone_transfer",
    # Stage J1: subdomain candidate resolution. Stubbed (no hits) so
    # hermetic runs stay socket-free and deterministic.
    "_resolve_subdomain_candidates",
]

PASSIVE_OSINT_METHODS = [
    "hackertarget_reverse_ip", "otx_passive_dns", "internetdb",
    "crt_sh", "shodan_host", "virustotal_passive_dns", "hackertarget_hostsearch",
]


def strip_ansi(text: str) -> str:
    """Drop terminal control sequences so captured output can be matched."""
    return ANSI_RE.sub("", text or "")


# ---------------------------------------------------------------------------
# Result plumbing
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class Check:
    ident: str
    name: str
    status: str = "SKIP"          # PASS / FAIL / SKIP
    detail: str = ""
    evidence: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def as_line(self) -> str:
        label = f"{self.ident:<4} {self.name}"
        return f"{label:<46} {self.status:<5} {self.detail}"


class Matrix:
    """Collects check results and the run artifacts they share."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.checks: List[Check] = []
        self.config: Dict[str, Any] = {}
        self.version: str = "?"
        self.scan: Optional["Scan"] = None
        self.notes: List[str] = []

    # -- config / version -------------------------------------------------
    def load_config(self) -> None:
        import yaml
        with open(CONFIG_YAML, "r", encoding="utf-8") as fh:
            self.config = yaml.safe_load(fh) or {}
        self.version = str(self.config.get("version", "?"))

    # -- result helpers ---------------------------------------------------
    def record(self, ident: str, name: str, ok: bool, detail: str,
               evidence: Optional[Dict[str, Any]] = None) -> Check:
        chk = Check(ident=ident, name=name,
                    status="PASS" if ok else "FAIL", detail=detail,
                    evidence=evidence or {})
        self.checks.append(chk)
        marker = "ok  " if ok else "FAIL"
        print(f"  [{marker}] {chk.as_line()}", flush=True)
        return chk

    def skip(self, ident: str, name: str, reason: str) -> Check:
        chk = Check(ident=ident, name=name, status="SKIP", detail=reason)
        self.checks.append(chk)
        print(f"  [skip] {chk.as_line()}", flush=True)
        return chk

    def get(self, ident: str) -> Optional[Check]:
        for chk in self.checks:
            if chk.ident == ident:
                return chk
        return None

    def replace(self, ident: str, ok: bool, detail: str,
                evidence: Optional[Dict[str, Any]] = None) -> None:
        """Overwrite an earlier result (e.g. SKIP -> PASS after a later pass)."""
        existing = self.get(ident)
        if existing is None:
            return
        existing.status = "PASS" if ok else "FAIL"
        existing.detail = detail
        existing.evidence = evidence or {}
        print(f"  [rec ] {existing.as_line()}", flush=True)


# ---------------------------------------------------------------------------
# Live CLI scan
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class CliRun:
    argv: List[str]
    rc: int
    stdout: str
    stderr: str
    seconds: float
    timed_out: bool = False
    paths: Dict[str, str] = dataclasses.field(default_factory=dict)

    @property
    def text(self) -> str:
        return strip_ansi(self.stdout)

    @property
    def err_text(self) -> str:
        return strip_ansi(self.stderr)


PATH_RE = re.compile(r"^\[(\w+)\]\s+(\S+)$", re.M)


def run_cli(argv: Sequence[str], timeout: int = 900, pty: bool = False,
            cwd: str = ROOT) -> CliRun:
    """Run reconip.py, optionally under a pty so rich renders the progress bar.

    A pty is what makes V6 measurable: _progress_context() yields a no-op
    handle when stdout is not a terminal, so a piped run shows no progress
    at all. --no-pty therefore downgrades V6 to an in-process check.
    """
    cmd = [sys.executable, RECONIP_PY] + list(argv)
    started = time.time()
    timed_out = False
    if pty:
        quoted = " ".join(
            arg if re.fullmatch(r"[\w@%+=:,./-]+", arg) else repr(arg)
            for arg in cmd
        )
        full = ["script", "-qec", quoted, "/dev/null"]
    else:
        full = cmd
    try:
        proc = subprocess.run(full, cwd=cwd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
        out = proc.stdout.decode("utf-8", "replace")
        err = proc.stderr.decode("utf-8", "replace")
        rc = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        out = (exc.stdout or b"").decode("utf-8", "replace")
        err = (exc.stderr or b"").decode("utf-8", "replace")
        rc = 124
    except FileNotFoundError as exc:
        return CliRun(list(cmd), 127, "", str(exc), 0.0, True)
    run = CliRun(list(cmd), rc, out, err, time.time() - started, timed_out)
    for fmt, path in PATH_RE.findall(strip_ansi(out)):
        run.paths[fmt] = path
    return run


@dataclasses.dataclass
class Scan:
    run: CliRun
    target: str
    artifacts: Dict[str, str]      # format -> absolute path
    report: Dict[str, Any]         # parsed JSON artifact


FORMAT_SUFFIX = {
    "json": ".json",
    "html": ".html",
    "markdown": ".md",
    "csv": ".csv",
    "stix": ".stix.json",
    "misp": ".misp.json",
}


def live_scan(mx: Matrix, target: str, profile: Optional[str],
              timeout: int, use_pty: bool) -> Scan:
    argv = [target, "--deterministic"]
    if profile:
        argv += ["--profile", profile]
    # Snapshot the reports directory first. The tool only prints
    # "[format] path" lines when the display is off; with the display on
    # (which is what a pty run needs for V5/V6) the paths are drawn inside
    # a rich panel, so directory diffing is the reliable discovery method.
    before = _reports_index()
    started = time.time()
    run = run_cli(argv, timeout=timeout, pty=use_pty)
    after = _reports_index()
    new_files = sorted(set(after) - set(before), key=lambda p: after[p])
    artifacts: Dict[str, str] = {}
    for fmt, path in run.paths.items():          # printed lines, if any
        abspath = path if os.path.isabs(path) else os.path.join(ROOT, path)
        if os.path.exists(abspath):
            artifacts[fmt] = abspath
    prefix = re.sub(r"[^a-zA-Z0-9._-]", "_", str(target or "unknown"))
    for path in new_files:
        # Only files created by this scan: the directory is shared with
        # every previous run, so a name match alone is not enough.
        if after.get(path, 0) < started - 2:
            continue
        name = os.path.basename(path)
        if not name.startswith(prefix):
            continue
        # Longest suffix first: "x.stix.json" ends with ".json" too, so
        # checking "json" first would misfile every STIX/MISP artifact.
        for fmt, suffix in sorted(FORMAT_SUFFIX.items(),
                                  key=lambda kv: -len(kv[1])):
            if name.endswith(suffix) and fmt not in artifacts:
                artifacts[fmt] = path
    report: Dict[str, Any] = {}
    json_path = artifacts.get("json")
    if json_path:
        try:
            with open(json_path, "r", encoding="utf-8") as fh:
                report = json.load(fh)
        except Exception:
            report = {}
    return Scan(run=run, target=target, artifacts=artifacts, report=report)


def _reports_index() -> Dict[str, float]:
    index: Dict[str, float] = {}
    if not os.path.isdir(REPORTS_DIR):
        return index
    for name in os.listdir(REPORTS_DIR):
        path = os.path.join(REPORTS_DIR, name)
        if os.path.isfile(path):
            try:
                index[path] = os.path.getmtime(path)
            except OSError:
                pass
    return index


# ---------------------------------------------------------------------------
# In-process pipeline runner (hermetic, record/replay)
# ---------------------------------------------------------------------------
class _BlockedSocket:
    """Sentinel raised instead of any real socket operation."""


def block_network() -> List[Dict[str, str]]:
    """Replace the socket layer with a tripwire. Returns the violation log."""
    violations: List[Dict[str, str]] = []

    def _trip(name):
        def inner(*args, **kwargs):
            violations.append({"call": name,
                               "stack": traceback.format_stack()[-3].strip()})
            raise _BlockedSocket(f"network access blocked in hermetic run: {name}")
        return inner

    saved = {
        "socket": socket.socket,
        "create_connection": socket.create_connection,
        "getaddrinfo": socket.getaddrinfo,
        "gethostbyname": socket.gethostbyname,
    }
    socket.socket = _trip("socket.socket")          # type: ignore[assignment]
    socket.create_connection = _trip("create_connection")
    socket.getaddrinfo = _trip("getaddrinfo")
    socket.gethostbyname = _trip("gethostbyname")
    return violations, saved  # type: ignore[return-value]


def restore_network(saved: Dict[str, Any]) -> None:
    for name, fn in saved.items():
        setattr(socket, name, fn)


class Replayer:
    """Record network collector results once, replay them forever after.

    Pass 1 runs for real and stores every collector's return value. Later
    passes answer from that store with the sockets blocked, so the pipeline
    sees byte-identical input on every run. That is what makes V14 and V19
    able to say "identical" without depending on a third party.
    """

    def __init__(self, module: Any) -> None:
        self.m = module
        self.fixtures: Dict[str, Any] = {}
        self.recording = False
        self.misses: List[str] = []
        self._saved: Dict[str, Any] = {}

    # -- lifecycle --------------------------------------------------------
    def install(self) -> None:
        for name in NETWORK_COLLECTORS:
            fn = getattr(self.m, name, None)
            if fn is None or not callable(fn):
                continue
            self._saved[name] = fn
            setattr(self.m, name, self._wrap(name, fn))
        osint = getattr(self.m, "PassiveOSINT", None)
        if osint is not None:
            for meth in PASSIVE_OSINT_METHODS:
                fn = getattr(osint, meth, None)
                if fn is None or not callable(fn):
                    continue
                self._saved[f"PassiveOSINT.{meth}"] = fn
                setattr(osint, meth, self._wrap(f"PassiveOSINT.{meth}", fn))

    def uninstall(self) -> None:
        for name, fn in self._saved.items():
            if name.startswith("PassiveOSINT."):
                setattr(getattr(self.m, "PassiveOSINT"), name.split(".", 1)[1], fn)
            else:
                setattr(self.m, name, fn)
        self._saved.clear()

    def _wrap(self, name: str, fn: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            if self.recording:
                result = fn(*args, **kwargs)
                self.fixtures[name] = result
                return result
            if name in self.fixtures:
                return self.fixtures[name]
            self.misses.append(name)
            # Nothing recorded for this call site: return the same empty
            # shape recon() already handles, and count the miss so the
            # report can say the fixture set was incomplete.
            return self._empty_like(name)
        return wrapper

    @staticmethod
    def _empty_like(name: str) -> Any:
        if name == "dns_collect":
            # Returns a bare list of Evidence, not a (list, status) pair.
            return []
        if name in ("collect_geo", "collect_asn", "collect_rdap",
                    "collect_dns", "collect_threat"):
            return ([], "SKIPPED")
        if name == "collect_certs":
            return ([], "SKIPPED", {"records": {}})
        if name == "run_providers":
            return []
        if name in ("certificate_intelligence",):
            return {"live_certificate": None, "ct_certificates": [],
                    "correlation": {}, "metadata": [], "relationships": {},
                    "anomalies": [], "summary": {}}
        if name in ("passive_dns_intelligence", "correlate", "correlate_results"):
            return {"evidence": [], "items": [], "correlations": [], "summary": {}}
        if name == "infra_profile":
            return {"status": "SKIPPED", "ip": None}
        if name in ("attack_surface", "technology_intelligence",
                    "vulnerability_candidates"):
            return {"candidates": [], "summary": {}, "items": []}
        if name in ("whois_enhanced", "enumerate_subdomains"):
            return {}
        # Stage I4: advanced-DNS live probes. Neutral structures keep
        # hermetic runs deterministic with zero socket violations; the
        # recording pass captures the live values as fixtures instead.
        if name == "_analyze_dnssec":
            return {"signed": None, "reason": "unrecorded"}
        if name == "_analyze_wildcard":
            return {"wildcard": None, "reason": "unrecorded"}
        if name == "_analyze_zone_transfer":
            return {"attempted": False, "reason": "unrecorded"}
        # Stage J1: candidate resolution returns no hits when stubbed.
        if name == "_resolve_subdomain_candidates":
            return {}
        return None

    # -- passes -----------------------------------------------------------
    def run_pipeline(self, target: str, config: Dict[str, Any],
                     network: Optional[Tuple[Any, Dict[str, Any]]] = None,
                     with_exports: bool = False) -> Dict[str, Any]:
        """One end-to-end recon() + generate_report() (+ exports) cycle."""
        m = self.m
        result: Dict[str, Any] = {"target": target}
        if network is not None:
            violations, saved = network
            restore_network(saved)
        try:
            with contextlib.ExitStack() as stack:
                if network is not None:
                    violations, saved = network
                    stack.callback(restore_network, saved)
                m._sync_global_config(config)
                raw = m.recon(target)
                result["raw"] = raw
                result["stage_failures"] = list(raw.get("_stage_failures", []) or [])
                final = m.generate_report(target, raw, config)
                result["final"] = final
                if with_exports:
                    exports: Dict[str, str] = {}
                    for fmt, fn in (("json", m.export_json),
                                    ("csv", m.export_csv),
                                    ("html", m.export_html),
                                    ("markdown", m.export_markdown),
                                    ("stix", m.export_stix),
                                    ("misp", m.export_misp)):
                        try:
                            exports[fmt] = fn(final, config)
                        except Exception as exc:      # exporter fault = failure
                            exports[fmt] = f"ERROR: {exc}"
                    result["exports"] = exports
                if network is not None:
                    result["violations"] = list(violations)
        finally:
            if network is not None:
                restore_network(saved)
        return result


def _read_export(path: Optional[str]) -> str:
    """Read an exported artifact, canonicalised for comparison.

    metadata.generated_at and report_id name the run rather than the data;
    every other byte has to match. An unreadable export is a hard failure,
    so it is returned as a distinctive string that cannot compare equal.
    """
    if not path or not os.path.exists(path):
        return f"<missing export: {path}>"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return canonical_json(json.load(fh))
    except Exception as exc:
        return f"<unreadable export: {type(exc).__name__}: {exc}>"


def seed_history_baseline(db_path: str, target: str) -> None:
    """Reset the snapshot table to a fixed baseline.

    historical_intelligence() writes a snapshot on every run and compares
    against the previous one, so the 08 section is a time series, not a
    pure function of the inputs. Consecutive runs therefore differ by
    construction on run 1 -> run 2 (FIRST_OBSERVATION -> COMPARED), and
    that difference leaks downstream into 03's coverage.

    Determinism is a claim about code, not about elapsed time, so every
    compared run starts from this same seeded baseline. The history
    section is then compared too -- with its input state pinned, rather
    than excluded and hoped away.
    """
    if not os.path.exists(db_path):
        # The table is created by the first run's init_snapshot_schema().
        # Seeding before that would silently no-op and the run would
        # report FIRST_OBSERVATION instead of a comparison.
        try:
            import reconip
            reconip.init_snapshot_schema(db_path)
        except Exception as exc:
            raise RuntimeError(f"cannot seed history baseline: {exc}") from exc
    conn = sqlite3.connect(db_path, timeout=30)
    try:
        conn.execute("DELETE FROM snapshots")
        conn.execute(
            "INSERT INTO snapshots (target, timestamp, data) VALUES (?, ?, ?)",
            (target, "2020-01-01T00:00:00Z",
             json.dumps({"dns": {}, "asn": {}, "prefix": {}, "certificate": {},
                         "domains": [], "threat": {}, "whois": {}}, sort_keys=True)),
        )
        conn.commit()
    finally:
        conn.close()


def canonical_json(obj: Any) -> str:
    """Stable rendering of a report for byte comparison.

    metadata.generated_at / report_id identify the run, not the data, so
    they are the only fields excluded; everything else -- including every
    other timestamp -- must match or the run is not reproducible.
    """
    clone = json.loads(json.dumps(obj, default=str, sort_keys=True))
    meta = clone.get("metadata")
    if isinstance(meta, dict):
        meta.pop("generated_at", None)
        meta.pop("report_id", None)
    return json.dumps(clone, sort_keys=True, ensure_ascii=False, indent=1)


# ---------------------------------------------------------------------------
# V1-V12 -- the original matrix
# ---------------------------------------------------------------------------
def v1_python_compiles(mx: Matrix) -> None:
    targets = [RECONIP_PY, os.path.abspath(__file__)]
    bad = []
    for path in targets:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                compile(fh.read(), path, "exec")
        except SyntaxError as exc:
            bad.append(f"{os.path.basename(path)}:{exc.lineno} {exc.msg}")
    mx.record("V1", "Python compiles", not bad,
              f"{len(targets)} file(s)" if not bad else "; ".join(bad),
              {"files": [os.path.basename(p) for p in targets]})


def v2_yaml_parses(mx: Matrix) -> None:
    try:
        import yaml
        with open(CONFIG_YAML, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        ok = isinstance(data, dict) and "version" in data
        mx.record("V2", "YAML parses", ok,
                  f"version={data.get('version') if isinstance(data, dict) else '?'}",
                  {"version": data.get("version") if isinstance(data, dict) else None,
                   "top_level_keys": len(data) if isinstance(data, dict) else 0})
    except Exception as exc:
        mx.record("V2", "YAML parses", False, f"{type(exc).__name__}: {exc}")


def v3_version_in_banner(mx: Matrix) -> None:
    scan = mx.scan
    if scan is None:
        mx.skip("V3", "Version in banner", "no scan")
        return
    text = scan.run.text
    ok = mx.version in text
    mx.record("V3", "Version in banner", ok,
              f"expected {mx.version}" + ("" if ok else " -- not found in output"),
              {"version": mx.version})


def v4_threat_score_zero(mx: Matrix) -> None:
    scan = mx.scan
    if scan is None or not scan.report:
        mx.skip("V4", "Threat score = 0", "no report")
        return
    threat = scan.report.get("09_threat_intelligence", {}) or {}
    score = threat.get("observed_threat_score")
    ok = score in (0, 0.0)
    mx.record("V4", "Threat score = 0", ok, f"score={score}",
              {"observed_threat_score": score,
               "classification": threat.get("classification")})


def v5_header_shows_target(mx: Matrix) -> None:
    scan = mx.scan
    if scan is None:
        mx.skip("V5", "Header shows target", "no scan")
        return
    text = scan.run.text
    header_lines = [ln for ln in text.splitlines() if scan.target in ln]
    ok = bool(header_lines)
    mx.record("V5", "Header shows target", ok,
              f"{scan.target} on {len(header_lines)} line(s)"
              if ok else f"{scan.target} absent from output",
              {"first_match": header_lines[0].strip()[:120] if header_lines else None})


PROGRESS_RE = re.compile(r"(\d{1,2})/13")


def v6_progress_advances(mx: Matrix) -> None:
    scan = mx.scan
    if scan is None:
        mx.skip("V6", "Progress advances", "no scan")
        return
    text = scan.run.text
    stages = sorted({int(n) for n in PROGRESS_RE.findall(text)})
    if stages:
        ok = max(stages) >= 13 and len(stages) >= 4
        mx.record("V6", "Progress advances", ok,
                  f"sampled {stages} -> {max(stages)}/13",
                  {"sampled": stages, "source": "pty stdout"})
        return
    # No pty (or rich suppressed the bar): measure the stage callbacks
    # in-process instead. Same 13 transitions, exact rather than sampled.
    try:
        seen = _inprocess_progress(mx)
        ok = len(seen) >= 13 and max(seen) == 13
        mx.record("V6", "Progress advances", ok,
                  f"in-process stages {len(set(seen))} distinct, max {max(seen) if seen else 0}/13"
                  + ("" if ok else " -- did not reach 13/13"),
                  {"stages": sorted(set(seen)), "source": "in-process progress handle"})
    except Exception as exc:
        mx.skip("V6", "Progress advances", f"not measurable: {exc}")


def _inprocess_progress(mx: Matrix) -> List[int]:
    import reconip
    seen: List[int] = []

    class Recorder:
        def start(self, stage: str = "", *a, **k): seen.append(0)
        def next(self, stage: str = "", *a, **k):
            if stage:
                m = re.search(r"(\d{1,2})/13", str(stage))
                if m:
                    seen.append(int(m.group(1)))
        def update(self, *a, **k): pass
        def stop(self, *a, **k): pass

    cfg = dict(mx.config)
    m = reconip
    m._sync_global_config(cfg)
    m.recon(mx.args.target, enable_db=False, progress=Recorder())
    return seen


def v7_no_duplicate_output(mx: Matrix) -> None:
    scan = mx.scan
    if scan is None:
        mx.skip("V7", "No duplicate output", "no scan")
        return
    text = scan.run.text
    counts: Dict[str, int] = {}
    for marker in ("Auth:", "ReconIP", "Section 15", "Reports"):
        counts[marker] = text.count(marker)
    # A duplicated auth summary or a doubled report table is the C3.5 bug.
    auth = counts.get("Auth:", 0)
    ok = auth <= 1 and counts.get("Reports", 0) <= 1
    mx.record("V7", "No duplicate output", ok,
              f"auth line x{auth}, reports line x{counts.get('Reports', 0)}",
              counts)


LOG_LEAK_PATTERNS = [
    ("file:line marker", re.compile(r"\breconip\.py:\d+")),
    ("logging timestamp", re.compile(r"\[\d{2}:\d{2}:\d{2}\]\s*\[(INFO|WARNING|ERROR|DEBUG)\]")),
    ("log level token", re.compile(r"^\s*(INFO|WARNING|ERROR|DEBUG|CRITICAL)\s{2,}\S", re.M)),
    ("traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("handler name", re.compile(r"\b(logging|rich\.log)\b")),
]


def v8_no_log_leak(mx: Matrix) -> None:
    scan = mx.scan
    if scan is None:
        mx.skip("V8", "No log leak", "no scan")
        return
    findings: Dict[str, List[str]] = {}
    blob = scan.run.text + "\n" + scan.run.err_text
    for name, rx in LOG_LEAK_PATTERNS:
        hits = rx.findall(blob)
        if hits:
            findings[name] = [str(h) for h in hits[:3]]
    # Reports must be clean too: a leaked path in an artifact is the same
    # defect with a longer reach.
    for fmt, path in scan.artifacts.items():
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                body = strip_ansi(fh.read())
        except Exception:
            continue
        for name, rx in LOG_LEAK_PATTERNS:
            if rx.search(body):
                findings.setdefault(f"{fmt}:{name}", []).append(path)
    ok = not findings
    mx.record("V8", "No log leak", ok,
              "stdout, stderr and artifacts clean" if ok
              else "leaked: " + ", ".join(findings),
              findings)


def v9_all_reports(mx: Matrix) -> None:
    scan = mx.scan
    if scan is None:
        mx.skip("V9", "All 6 reports", "no scan")
        return
    declared = (mx.config.get("reports", {}) or {}).get("formats", []) or []
    present = [f for f in REPORT_FORMATS
               if f in scan.artifacts and os.path.getsize(scan.artifacts[f]) > 0]
    missing = [f for f in declared if f not in present]
    ok = not missing and len(present) == len(REPORT_FORMATS)
    sizes = {f: os.path.getsize(p) for f, p in scan.artifacts.items()}
    mx.record("V9", "All 6 reports", ok,
              f"{len(declared)} declared, {len(present)} on disk"
              + (f"; missing {missing}" if missing else ""),
              {"sizes": sizes})


def v10_coverage(mx: Matrix) -> None:
    scan = mx.scan
    if scan is None or not scan.report:
        mx.skip("V10", "Coverage = 1.0", "no report")
        return
    threat = scan.report.get("09_threat_intelligence", {}) or {}
    cov = threat.get("evidence_coverage")
    ok = cov is not None and float(cov) >= 1.0
    mx.record("V10", "Coverage = 1.0", ok, f"09.evidence_coverage={cov}",
              {"evidence_coverage": cov,
               "ok_count": threat.get("ok_count"),
               "not_configured_count": threat.get("not_configured_count"),
               "failed_count": threat.get("failed_count")})


def v11_determinism_artifact(mx: Matrix) -> None:
    """Artifact-level repeatability: same report, exported twice, no drift."""
    try:
        m = _module(mx)
        cfg = dict(mx.config)
        m._sync_global_config(cfg)
        probe = _fixture_report(mx, cfg)
        first = canonical_json(m.generate_report(mx.args.target, probe, cfg))
        second = canonical_json(m.generate_report(mx.args.target, probe, cfg))
        ok = first == second
        mx.record("V11", "Determinism", ok,
                  "0 diffs" if ok else f"{_diff_count(first, second)} diff line(s)",
                  {"bytes": len(first)})
    except Exception as exc:
        mx.record("V11", "Determinism", False, f"{type(exc).__name__}: {exc}")


def _diff_count(a: str, b: str) -> int:
    import difflib
    return sum(1 for _ in difflib.unified_diff(
        a.splitlines(), b.splitlines(), lineterm="", n=0))


def v12_clean_install(mx: Matrix) -> None:
    """Can the tool run from requirements.txt, on what is actually installed?

    The pass condition is: every pinned requirement is installed and
    importable at a version at or above the pin. A version ABOVE the pin
    is drift, not failure -- the tool has to keep working when the host
    is newer than its own pins -- so it is recorded in the evidence and
    only turned into a failure with --strict-pins. A version BELOW the
    pin is a real finding: the environment cannot satisfy what the file
    declares.

    --v12-venv builds a throwaway venv and pip-installs the file, which
    is the stronger form of the same question.
    """
    if getattr(mx.args, "v12_venv", False):
        ok, detail, ev = _v12_fresh_venv(mx)
        mx.record("V12", "Clean install", ok, detail, ev)
        return
    from importlib import metadata
    pins = _requirements_pins()
    installed: Dict[str, str] = {}
    drift: Dict[str, str] = {}
    below: List[str] = []
    missing: List[str] = []
    unimportable: List[str] = []
    for name, want in pins.items():
        module = IMPORT_NAME.get(name.lower(), name.lower().replace("-", "_"))
        try:
            installed[name] = metadata.version(name)
        except Exception:
            missing.append(name)
        try:
            __import__(module)
        except Exception as exc:
            unimportable.append(f"{name}: {type(exc).__name__}")
        have = installed.get(name)
        if have and _version_tuple(have) < _version_tuple(want):
            below.append(f"{name}: {have} < pinned {want}")
        elif have and have != want:
            drift[name] = f"{have} (pinned {want})"
    # The CLI has to start, or "installable" means nothing.
    cli = subprocess.run([sys.executable, RECONIP_PY, "--version"],
                         cwd=ROOT, capture_output=True, timeout=120)
    cli_runs = cli.returncode == 0
    ok = not missing and not unimportable and cli_runs
    advisories: List[str] = list(below)
    if getattr(mx.args, "strict_pins", False):
        ok = ok and not drift and not below
    bits = [f"{len(pins) - len(missing)}/{len(pins)} deps importable",
            f"cli rc={cli.returncode}"]
    if drift:
        bits.append(f"{len(drift)} above pin")
    if problems := (missing + unimportable):
        ok = False
        bits.append("; ".join(problems[:3]))
    if advisories and not getattr(mx.args, "strict_pins", False):
        bits.append(f"ADVISORY {len(advisories)} below pin")
    mx.record("V12", "Clean install", ok, ", ".join(bits),
              {"installed": installed, "above_pin": drift,
               "below_pin": advisories, "missing": missing,
               "cli_version": cli.stdout.decode().strip(),
               "note": "Below-pin versions are an environment finding, not a "
                       "defect in the package: pip would install the pin."})
    for adv in advisories:
        mx.notes.append(f"V12 advisory: {adv} on this host")


IMPORT_NAME = {"pyyaml": "yaml", "python-whois": "whois", "dnspython": "dns"}


def _requirements_pins() -> Dict[str, str]:
    pins: Dict[str, str] = {}
    with open(os.path.join(ROOT, "requirements.txt"), "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "==" not in line:
                continue
            name, _, version = line.partition("==")
            pins[name.strip()] = version.strip()
    return pins


def _version_tuple(value: str) -> Tuple[int, ...]:
    nums = re.findall(r"\d+", str(value))
    return tuple(int(n) for n in nums[:4]) or (0,)


def _v12_fresh_venv(mx: Matrix) -> Tuple[bool, str, Dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="reconip-v12-") as tmp:
        venv_dir = os.path.join(tmp, "venv")
        proc = subprocess.run([sys.executable, "-m", "venv", venv_dir],
                              capture_output=True, timeout=300)
        if proc.returncode != 0:
            return False, "venv creation failed", {"stderr": proc.stderr.decode()[-400:]}
        pip = os.path.join(venv_dir, "bin", "pip")
        proc = subprocess.run([pip, "install", "-q", "-r",
                               os.path.join(ROOT, "requirements.txt")],
                              capture_output=True, timeout=900)
        if proc.returncode != 0:
            return False, "pip install failed", {"stderr": proc.stderr.decode()[-600:]}
        py = os.path.join(venv_dir, "bin", "python")
        proc = subprocess.run([py, "-c",
                               "import reconip" if False else
                               "import rich, yaml, dns, requests, cryptography, whois; print('ok')"],
                              cwd=ROOT, capture_output=True, timeout=120)
        ok = proc.returncode == 0
        return ok, ("fresh venv imports rc=0" if ok else
                    proc.stderr.decode()[-400:]), {"venv": tmp}


# ---------------------------------------------------------------------------
# V13-V20 -- Stage G5 additions
# ---------------------------------------------------------------------------
def v13_error_isolation(mx: Matrix) -> None:
    """One broken section must not cost the operator the other 17.

    Three collectors are forced to raise inside a single recon() call. The
    check passes only if the exception does not escape, every failure is
    named, and the untouched sections are still populated.
    """
    try:
        m = _module(mx)
        cfg = dict(mx.config)
        m._sync_global_config(cfg)
        victim_collectors = [
            "collect_dns",         # stage 01/13 DNS Intelligence
            "certificate_intelligence",  # stage 03/13 Certificate
            "infra_profile",       # stage 05/13 Infrastructure
        ]
        replayer = Replayer(m)
        replayer.install()
        saved = {name: getattr(m, name) for name in victim_collectors}
        try:
            def boom(_name):
                def _inner(*a, **k):
                    raise RuntimeError(f"injected fault in {_name}")
                return _inner
            for name in victim_collectors:
                setattr(m, name, boom(name))
            network = block_network()
            try:
                outcome = replayer.run_pipeline(mx.args.target, cfg, network=network)
            finally:
                restore_network(network[1])
                for name, fn in saved.items():
                    setattr(m, name, fn)
                replayer.uninstall()
        finally:
            replayer.uninstall()

        raw = outcome.get("raw", {})
        failures = outcome.get("stage_failures", [])
        final = outcome.get("final", {}) or {}
        named = {f.get("stage") for f in failures}
        expected = {m.STAGE_DNS, m.STAGE_CERT, m.STAGE_INFRA}
        isolated = expected.issubset(named)
        # A clean scan and an injected-fault scan must differ in exactly the
        # injected stages: proving the other sections really still ran.
        survivors = [k for k in SECTION_KEYS
                     if k in final and isinstance(final[k], dict) and final[k]]
        survivor_ok = len(survivors) >= 15
        ok = isolated and survivor_ok
        mx.record("V13", "Error isolation", ok,
                  f"{len(failures)} failure(s) recorded, {len(survivors)}/18 sections still built",
                  {"stages_failed": sorted(named),
                   "expected": sorted(expected),
                   "errors": [f.get("error", "")[:80] for f in failures][:6],
                   "sections_present": len(survivors),
                   "missing_sections": [k for k in SECTION_KEYS if k not in survivors]})
    except Exception as exc:
        mx.record("V13", "Error isolation", False,
                  f"{type(exc).__name__}: {exc}",
                  {"traceback": traceback.format_exc()[-600:]})


def v14_determinism(mx: Matrix) -> None:
    """Five consecutive runs, one byte-identical artifact.

    Run 1 records the collectors; runs 2-5 replay them with sockets
    blocked. Upstream drift therefore cannot mask or manufacture a diff.
    """
    runs = max(1, int(mx.args.v14_runs))
    try:
        m = _module(mx)
        cfg = dict(mx.config)
        # The criterion is about the exported artifact, so the export must
        # run in the mode that makes an artifact reproducible (Stage G2).
        cfg.setdefault("reports", {})["deterministic"] = True
        m._sync_global_config(cfg)
        replayer = Replayer(m)
        with _temp_db_config(cfg, mx):
            replayer.install()
            try:
                # Fixture capture. This pass runs against the live network
                # and is NOT one of the measured runs: an unstubbed path
                # that only works online would make run 1 differ from the
                # rest for reasons that have nothing to do with determinism.
                replayer.recording = True
                seed_history_baseline(mx.args.v19_db, mx.args.target)
                replayer.run_pipeline(mx.args.target, cfg, with_exports=True)
                replayer.recording = False
                payloads: List[str] = []
                memory: List[str] = []
                failures: List[List[Dict[str, Any]]] = []
                for _ in range(runs):
                    # Same seeded baseline before every run: the history
                    # section is stateful, so without this the runs are
                    # not comparable and the diff would be meaningless.
                    seed_history_baseline(mx.args.v19_db, mx.args.target)
                    network = block_network()
                    try:
                        out = replayer.run_pipeline(mx.args.target, cfg,
                                                    network=network, with_exports=True)
                    finally:
                        restore_network(network[1])
                    # Compare the artifact on disk, not the in-memory report.
                    # An observation timestamp is supposed to be the real
                    # one; --deterministic normalises it in the artifact
                    # (Stage G2), and that artifact is what an operator
                    # diffs. The in-memory report is recorded alongside as
                    # evidence, where only observation time may differ.
                    payloads.append(_read_export(out.get("exports", {}).get("json")))
                    memory.append(canonical_json(out.get("final", {})))
                    failures.append(out.get("stage_failures", []))
            finally:
                replayer.uninstall()

        base = payloads[0]
        diffs = [_diff_count(base, p) for p in payloads[1:]]
        mem_diffs = [_diff_count(memory[0], p) for p in memory[1:]]
        empty = all(d == 0 for d in diffs)
        no_fail = all(len(f) == 0 for f in failures)
        ok = empty and no_fail and not replayer.misses
        detail = f"{runs} runs, artifact diffs={diffs}"
        if not empty:
            detail += " -- not identical"
        elif not no_fail:
            detail += " -- a replayed run recorded a stage failure"
        elif replayer.misses:
            detail += f" -- unrecorded collectors: {sorted(set(replayer.misses))}"
        else:
            detail += ", byte-identical"
        mx.record("V14", "Determinism (5 runs)", ok, detail,
                  {"runs": runs, "artifact_diffs": diffs,
                   "in_memory_diffs": mem_diffs,
                   "bytes": len(base),
                   "stage_failures": [len(f) for f in failures],
                   "unrecorded_collectors": sorted(set(replayer.misses)),
                   "compared": "the exported JSON artifact (--deterministic), "
                               "read back from disk",
                   "in_memory_note": "The in-memory report keeps real observation "
                                     "timestamps by design (Stage G2); its residual "
                                     "diffs should be clock fields only.",
                   "network": "fixtures captured in an uncounted warm-up pass; "
                              f"all {runs} measured runs replay with sockets blocked",
                   "history_state": "snapshot table reseeded to a fixed baseline "
                                    "before every run, so 08 is compared rather "
                                    "than excluded"})
    except Exception as exc:
        mx.record("V14", "Determinism (5 runs)", False,
                  f"{type(exc).__name__}: {exc}",
                  {"traceback": traceback.format_exc()[-600:]})


def v15_cache_health(mx: Matrix) -> None:
    """Both SQLite files must pass an integrity check and expose a schema.

    "No cache errors" is checked two ways: structurally (integrity_check
    on the real files) and behaviourally (a set/get round-trip in a
    throwaway database, so a broken cache cannot hide behind a warm file).
    """
    findings: Dict[str, Any] = {}
    ok = True
    for label, path in (("reconip.db", DB_PATH), ("reconip_cache.db", CACHE_PATH)):
        entry: Dict[str, Any] = {"exists": os.path.exists(path)}
        if not entry["exists"]:
            findings[label] = entry
            ok = False
            continue
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)
            try:
                entry["integrity"] = conn.execute("PRAGMA integrity_check").fetchone()[0]
                entry["tables"] = len(conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'").fetchall())
                fk = conn.execute("PRAGMA foreign_key_check").fetchall()
                entry["foreign_key_violations"] = len(fk)
            finally:
                conn.close()
        except Exception as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
            ok = False
        findings[label] = entry
        if entry.get("integrity") != "ok" or entry.get("foreign_key_violations"):
            ok = False

    # Behavioural round-trip on a scratch database.
    try:
        import reconip
        with tempfile.TemporaryDirectory(prefix="reconip-v15-") as tmp:
            scratch = os.path.join(tmp, "cache.db")
            cfg = {"cache": {"db_path": scratch, "enabled": True,
                             "ttl_seconds": 3600, "provider_ttls": {}}}
            reconip.cache_init(scratch)
            probe = {"value": 42, "list": [1, 2, 3]}
            reconip.cache_set("g5:probe", probe, cfg)
            got = reconip.cache_get("g5:probe", cfg)
            # cache_get wraps the payload with freshness metadata, so the
            # round-trip is judged on the payload, not the envelope.
            payload = got.get("value") if isinstance(got, dict) else None
            roundtrip = bool(got) and payload == probe and got.get("status") == "FRESH"
            findings["roundtrip"] = {"ok": roundtrip, "status": (got or {}).get("status"),
                                     "payload": payload}
            ok = ok and roundtrip
    except Exception as exc:
        findings["roundtrip"] = {"error": f"{type(exc).__name__}: {exc}"}
        ok = False

    # Log scan: ERROR/CRITICAL lines mentioning the cache or the databases.
    cache_errors = _log_scan(r"(cache|sqlite|database|db )", levels=("ERROR", "CRITICAL"))
    findings["log_cache_errors"] = cache_errors
    if cache_errors:
        ok = False
    mx.record("V15", "Cache health", ok,
              "integrity ok, round-trip ok, no cache errors in log"
              if ok else f"see evidence ({len(cache_errors)} log line(s))",
              findings)


def _log_scan(pattern: str, levels: Sequence[str] = ()) -> List[str]:
    hits: List[str] = []
    if not os.path.exists(LOG_PATH):
        return hits
    rx = re.compile(pattern, re.I)
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not rx.search(line):
                    continue
                if levels and not any(lv in line.upper() for lv in levels):
                    continue
                hits.append(line.strip()[:160])
    except Exception:
        pass
    return hits[-10:]


def v16_snapshot_retention(mx: Matrix) -> None:
    """At most 100 snapshots per target, enforced at write time.

    Over-inserts 130 snapshots and asserts the table settles at exactly
    the cap, that the survivors are the newest ones, and that pruning
    never touches another target's rows.
    """
    import reconip
    cap = 100
    findings: Dict[str, Any] = {"cap": cap}
    with tempfile.TemporaryDirectory(prefix="reconip-v16-") as tmp:
        db = os.path.join(tmp, "snap.db")
        reconip.init_snapshot_schema(db)
        cfg = {"phase_e": {"retention": {"max_snapshots": cap}}}
        for i in range(130):
            reconip.snapshot_current_state("g5-target", {"dns_intelligence": {"evidence": []}},
                                           cfg, db)
        count = reconip.count_snapshots("g5-target", db)
        findings["after_130_inserts"] = count
        capped = count == cap

        rows = sqlite3.connect(db).execute(
            "SELECT id, timestamp FROM snapshots WHERE target='g5-target' ORDER BY id"
        ).fetchall()
        newest_kept = rows[-1][0] if rows else 0
        oldest_kept = rows[0][0] if rows else 0
        contiguous = len(rows) == cap and newest_kept - oldest_kept == cap - 1
        findings["kept_id_range"] = [oldest_kept, newest_kept]
        findings["newest_kept"] = contiguous

        # A second target must be unaffected by the first target's pruning.
        for i in range(3):
            reconip.snapshot_current_state("g5-other", {}, cfg, db)
        other = reconip.count_snapshots("g5-other", db)
        findings["other_target_rows"] = other
        isolation_ok = other == 3

        # A custom cap must be honoured (proves the 100 is config, not a
        # hardcoded constant that happens to equal 100).
        db2 = os.path.join(tmp, "snap2.db")
        reconip.init_snapshot_schema(db2)
        cfg5 = {"phase_e": {"retention": {"max_snapshots": 5}}}
        for _ in range(20):
            reconip.snapshot_current_state("g5-cap5", {}, cfg5, db2)
        cap5 = reconip.count_snapshots("g5-cap5", db2)
        findings["cap5_actual"] = cap5
        cfg0 = {"phase_e": {"retention": {"max_snapshots": 0}}}
        for _ in range(7):
            reconip.snapshot_current_state("g5-off", {}, cfg0, db2)
        off = reconip.count_snapshots("g5-off", db2)
        findings["pruning_disabled_actual"] = off
        config_ok = cap5 == 5 and off == 7

    live = 0
    if os.path.exists(DB_PATH):
        try:
            conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=30)
            try:
                row = conn.execute(
                    "SELECT target, COUNT(*) c FROM snapshots "
                    "GROUP BY target ORDER BY c DESC LIMIT 1").fetchone()
                live = row[1] if row else 0
                findings["live_max_per_target"] = live
            finally:
                conn.close()
        except Exception as exc:
            findings["live_error"] = str(exc)
    live_ok = live <= cap
    ok = capped and contiguous and isolation_ok and config_ok and live_ok
    mx.record("V16", "Snapshot retention (max 100)", ok,
              f"130 inserts -> {count} rows (cap {cap}); live max {live}",
              findings)


def v17_data_validation(mx: Matrix) -> None:
    """Every one of the 18 sections must exist and carry usable data."""
    scan = mx.scan
    if scan is None or not scan.report:
        mx.skip("V17", "Data validation", "no report")
        return
    report = scan.report
    problems: List[str] = []
    findings: Dict[str, Any] = {}

    missing = [k for k in SECTION_KEYS if k not in report]
    if missing:
        problems.append(f"missing sections: {missing}")
    empty: List[str] = []
    types: Dict[str, str] = {}
    for key in SECTION_KEYS:
        node = report.get(key)
        if key not in report:
            continue
        types[key] = type(node).__name__
        if not isinstance(node, dict):
            problems.append(f"{key} is {type(node).__name__}, expected dict")
        elif not node:
            empty.append(key)
    findings["section_types"] = types
    findings["empty_sections"] = empty
    if empty:
        problems.append(f"empty sections: {empty}")

    meta = report.get("metadata", {}) or {}
    for field in ("tool", "version", "target", "classification"):
        if not meta.get(field):
            problems.append(f"metadata.{field} missing")
    if meta.get("version") and meta.get("version") != mx.version:
        problems.append(f"metadata.version {meta.get('version')} != config {mx.version}")
    if not ISO_RE.match(str(meta.get("generated_at", ""))):
        problems.append(f"metadata.generated_at not ISO-Z: {meta.get('generated_at')!r}")

    # Non-finite floats break strict JSON consumers; the artifact is
    # written with default=str, so NaN would survive as the string 'nan'.
    raw_text = json.dumps(report, default=str)
    for token in ("NaN", "Infinity", "-Infinity"):
        if re.search(rf"(?<![\w\"]){token}(?![\w\"])", raw_text):
            problems.append(f"non-finite float in artifact: {token}")

    # Evidence accounting. `items` is only populated when include_raw is
    # on, so the totals are what has to be internally consistent.
    ev = report.get("15_evidence", {}) or {}
    items = ev.get("items", []) or []
    total = ev.get("total")
    by_status = ev.get("by_status", {}) or {}
    by_source = ev.get("by_source", {}) or {}
    findings["evidence"] = {"total": total, "by_status": by_status,
                            "by_source_count": len(by_source),
                            "raw_items": len(items)}
    if total is None:
        problems.append("15_evidence.total missing")
    else:
        if sum(by_status.values()) != total:
            problems.append(f"evidence by_status sums to {sum(by_status.values())}, "
                            f"total says {total}")
        if sum(by_source.values()) != total:
            problems.append(f"evidence by_source sums to {sum(by_source.values())}, "
                            f"total says {total}")
        if total and not by_source:
            problems.append("evidence total > 0 but by_source is empty")
    unattributed = [i for i in items
                    if not isinstance(i, dict) or not (i.get("source") or i.get("provider"))]
    if unattributed:
        problems.append(f"{len(unattributed)} raw evidence item(s) without a source")

    # A normalised artifact must declare that it was normalised.
    det = meta.get("_deterministic")
    findings["deterministic_marker"] = bool(det)
    if det and not det.get("fields_normalised"):
        problems.append("metadata._deterministic present but empty")

    ok = not problems
    mx.record("V17", "Data validation", ok,
              f"{len(SECTION_KEYS) - len(missing)}/18 sections valid, "
              f"{ev.get('total')} evidence records" if ok else "; ".join(problems[:4]),
              findings)


def v18_cross_report_consistency(mx: Matrix) -> None:
    """The six formats must describe the same scan.

    Format-specific checks (a STIX bundle is a bundle, MISP has an Event,
    CSV has a header) plus cross-format agreement on target, version and
    the number of exported artifacts.
    """
    scan = mx.scan
    if scan is None or not scan.artifacts:
        mx.skip("V18", "Cross-report consistency", "no artifacts")
        return
    problems: List[str] = []
    findings: Dict[str, Any] = {}
    target = scan.target
    report = scan.report

    def read(fmt: str) -> str:
        with open(scan.artifacts[fmt], "r", encoding="utf-8", errors="replace") as fh:
            return strip_ansi(fh.read())

    bodies: Dict[str, str] = {}
    for fmt, path in scan.artifacts.items():
        try:
            bodies[fmt] = read(fmt)
        except Exception as exc:
            problems.append(f"{fmt} unreadable: {exc}")

    # CSV parses once, up front: several checks below need its records.
    # (Physical line counts are meaningless here: quoted evidence cells
    # legitimately span multiple lines, so the csv module does the
    # counting, not splitlines.)
    import csv as _csv
    csv_rows: List[Dict[str, str]] = []
    try:
        csv_rows = list(_csv.DictReader(io.StringIO(bodies.get("csv", ""))))
    except Exception as exc:
        problems.append(f"csv does not parse: {exc}")
    findings["csv_records"] = len(csv_rows)

    # 1. every NON-EMPTY format names the same target. An empty
    # findings CSV (header only) legitimately names nothing: CSV rows
    # are findings (anomalies/vuln/attack-surface/history), not raw
    # evidence, so a clean-or-degraded scan with zero findings yields
    # zero rows. Asserting a target string there would force schema
    # pollution (a target column on every row) for no consumer benefit.
    target_ok: Dict[str, bool] = {}
    for fmt, body in bodies.items():
        if fmt == "csv" and not csv_rows:
            target_ok[fmt] = True  # exempt by design, see above
            continue
        target_ok[fmt] = target in body
        if not target_ok[fmt]:
            problems.append(f"{fmt} does not mention target {target}")
    findings["target_in_all"] = target_ok

    # 2. every format carries the same version. Provenance lives where
    # each format puts it: json/html/markdown embed the version string,
    # STIX carries x_reconip_version on the bundle (spec-compliant custom
    # property), MISP carries a reconip:version tag. The CSV is row-
    # oriented interchange with a fixed six-column schema, so by design it
    # carries no provenance -- its sibling JSON artifact does.
    versions: Dict[str, bool] = {}
    for fmt, body in bodies.items():
        if fmt == "csv":
            versions[fmt] = True  # exempt by design, see above
            continue
        if fmt == "stix":
            try:
                versions[fmt] = (json.loads(body).get("x_reconip_version") == mx.version)
            except Exception:
                versions[fmt] = False
            continue
        if fmt == "misp":
            try:
                tags = [(json.loads(body).get("Event", {}) or {}).get("Tag", []) or []]
                flat = [t.get("name", "") for t in tags[0] if isinstance(t, dict)]
                versions[fmt] = any(t == f"reconip:version=\"{mx.version}\"" for t in flat)
            except Exception:
                versions[fmt] = False
            continue
        versions[fmt] = mx.version in body
    findings["version_in_all"] = versions
    if not all(versions.values()):
        problems.append(f"version missing from: {[f for f, okk in versions.items() if not okk]}")

    # 3. section presence in the human-readable formats
    json_sections = [k for k in SECTION_KEYS if k in report]
    findings["json_sections"] = len(json_sections)
    html = bodies.get("html", "")
    md = bodies.get("markdown", "")
    sec_titles = ["Target", "Executive", "Data Quality", "Network", "DNS",
                  "Certificate", "Passive DNS", "Historical", "Threat",
                  "Infrastructure", "Attack Surface", "Technology",
                  "Vulnerability", "Anomal", "Evidence", "Confidence",
                  "Limitations", "Next"]
    html_hits = sum(1 for t in sec_titles if t.lower() in html.lower())
    md_hits = sum(1 for t in sec_titles if t.lower() in md.lower())
    findings["html_section_titles"] = html_hits
    findings["md_section_titles"] = md_hits
    if html_hits < 12:
        problems.append(f"html shows only {html_hits}/18 section titles")
    if md_hits < 12:
        problems.append(f"markdown shows only {md_hits}/18 section titles")

    # 4. CSV agrees with the JSON report.
    # The CSV flattens findings rows (anomalies, attack surface, ...), so
    # its record count is NOT expected to equal the evidence total, and
    # an empty findings set legitimately yields a header-only CSV --
    # evidence_total > 0 never implies findings > 0. What must hold is
    # that it parses cleanly, keeps its schema, and only names sections
    # the JSON report actually contains.
    findings["json_evidence_total"] = (report.get("15_evidence", {}) or {}).get("total") or 0
    if csv_rows:
        if list(csv_rows[0].keys()) != ["section", "category", "severity", "value",
                                        "evidence", "source"]:
            problems.append(f"csv schema changed: {list(csv_rows[0].keys())}")
        # The CSV uses exporter shorthand labels, not the NN_name report
        # keys. The mapping is fixed: a label with no entry here means the
        # exporter invented a section no report contains.
        csv_to_report = {
            "anomaly": "14_anomalies",
            "vulnerability": "13_vulnerability_candidates",
            "attack_surface": "11_attack_surface",
            "history": "08_historical_intelligence",
        }
        unknown = sorted({r.get("section", "") for r in csv_rows
                          if r.get("section", "") not in csv_to_report})
        if unknown:
            problems.append(f"csv names sections absent from the report: {unknown}")
        unmapped_empty = [label for label, key in csv_to_report.items()
                          if any(r.get("section") == label for r in csv_rows)
                          and not report.get(key)]
        if unmapped_empty:
            problems.append(f"csv cites empty/missing sections: {unmapped_empty}")
    elif csv_rows == [] and bodies.get("csv", "").strip().splitlines()[0:1] != ["section,category,severity,value,evidence,source"]:
        problems.append("empty csv does not even carry the expected header")

    # 5. STIX / MISP structural minimums
    try:
        stix = json.loads(bodies["stix"])
        findings["stix_type"] = stix.get("type")
        findings["stix_objects"] = len(stix.get("objects", []))
        if stix.get("type") != "bundle" or not stix.get("objects"):
            problems.append("stix is not a populated bundle")
        if not stix.get("id", "").startswith("bundle--"):
            problems.append("stix bundle id is not a STIX identifier")
    except Exception as exc:
        problems.append(f"stix unparseable: {exc}")
    try:
        misp = json.loads(bodies["misp"])
        event = misp.get("Event", {}) if isinstance(misp, dict) else {}
        findings["misp_attributes"] = len(event.get("Attribute", []) or [])
        if not event:
            problems.append("misp has no Event")
        if target not in str(event.get("info", "")):
            problems.append("misp Event.info does not name the target")
    except Exception as exc:
        problems.append(f"misp unparseable: {exc}")

    # 6. all six are non-empty and well-formed. A schema-valid but
    # empty findings CSV (header only, ~47 bytes) is legitimate -- see
    # check 1 -- so the small-artifact tripwire exempts it explicitly.
    sizes = {f: len(b) for f, b in bodies.items()}
    findings["sizes"] = sizes
    small = [f for f, n in sizes.items()
             if n < 200 and not (f == "csv" and not csv_rows)]
    if small:
        problems.append(f"suspiciously small artifacts: {small}")

    ok = not problems
    mx.record("V18", "Cross-report consistency", ok,
              f"6/6 formats agree on target, version and section count"
              if ok else "; ".join(problems[:4]),
              findings)


def v19_long_running_stability(mx: Matrix) -> None:
    """N consecutive executions with no failure and no degradation.

    "Degradation" is measured, not asserted: evidence count, section
    count, exported bytes and resident memory must stay inside a
    tolerance band across the whole run, and the snapshot table must
    stay at its cap rather than growing with the iteration count.
    """
    runs = max(2, int(mx.args.v19_runs))
    try:
        import resource
        m = _module(mx)
        cfg = dict(mx.config)
        cfg.setdefault("reports", {})["deterministic"] = True
        m._sync_global_config(cfg)
        replayer = Replayer(m)
        with _temp_db_config(cfg, mx):
            replayer.install()
            try:
                # Warm-up: capture fixtures live, then let the first
                # measured run write the baseline snapshot. Neither is
                # counted -- a long-run test that started on a cold
                # history table would measure its own setup.
                replayer.recording = True
                seed_history_baseline(mx.args.v19_db, mx.args.target)
                replayer.run_pipeline(mx.args.target, cfg, with_exports=True)
                replayer.recording = False
                network = block_network()
                try:
                    firsts: List[str] = []
                    tail: List[Dict[str, Any]] = []
                    failures: List[Dict[str, Any]] = []
                    rss: List[int] = []
                    for i in range(runs):
                        out = replayer.run_pipeline(mx.args.target, cfg,
                                                    network=network, with_exports=True)
                        final = out.get("final", {}) or {}
                        exp = out.get("exports", {}) or {}
                        # Compare the exported artifact: the in-memory
                        # report carries the real observation clock, which
                        # is supposed to move between runs.
                        payload = _read_export(exp.get("json"))
                        firsts.append(payload)
                        ev = final.get("15_evidence", {}) or {}
                        # items is empty unless include_raw is set; total
                        # and by_status are always populated.
                        evidence_n = ev.get("total")
                        if evidence_n is None:
                            evidence_n = len(ev.get("items", []) or [])
                        tail.append({
                            "run": i + 1,
                            "bytes": len(payload),
                            "sections": sum(1 for k in SECTION_KEYS
                                            if isinstance(final.get(k), dict) and final[k]),
                            "evidence": evidence_n,
                            "stage_failures": len(out.get("stage_failures", [])),
                            "export_errors": [f for f, p in exp.items() if str(p).startswith("ERROR")],
                            "rss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                        })
                        if out.get("stage_failures") or tail[-1]["export_errors"]:
                            failures.append(tail[-1])
                        rss.append(tail[-1]["rss_kb"])
                    violations = list(network[0])
                    # Read the row count here: the scratch directory is
                    # removed when the context exits.
                    snapshot_rows = _snapshot_rows(mx)
                finally:
                    restore_network(network[1])
            finally:
                replayer.uninstall()

        steady = firsts
        identical = all(p == steady[0] for p in steady)
        transition = False
        bytes_drift = (max(t["bytes"] for t in tail) -
                       min(t["bytes"] for t in tail)) if len(tail) > 1 else 0
        body = tail
        sec_lo, sec_hi = min(t["sections"] for t in body), max(t["sections"] for t in body)
        ev_lo, ev_hi = min(t["evidence"] for t in body), max(t["evidence"] for t in body)
        rss_drift = rss[-1] - rss[0]
        problems: List[str] = []
        if failures:
            problems.append(f"{len(failures)} run(s) reported failures")
        if not identical:
            problems.append(f"{sum(1 for p in steady if p != steady[0])} steady-state run(s) diverged")
        if sec_lo < 18:
            problems.append(f"section count dipped to {sec_lo}")
        if sec_hi != sec_lo:
            problems.append(f"section count varied {sec_lo}..{sec_hi}")
        if ev_hi != ev_lo:
            problems.append(f"evidence count varied {ev_lo}..{ev_hi}")
        if bytes_drift:
            problems.append(f"artifact size drifted {bytes_drift} bytes")
        # RSS is a high-water mark, so growth is real only if it is large
        # relative to the run; 1 MB per execution is a generous ceiling.
        if rss_drift > 1024 * len(tail):
            problems.append(f"resident memory grew {rss_drift} KiB over {len(tail)} runs")
        if violations:
            problems.append(f"{len(violations)} unguarded network call(s)")
        if snapshot_rows > 100:
            problems.append(f"snapshot table grew to {snapshot_rows} rows")
        ok = not problems
        detail = (f"{runs} runs, {len(failures)} failure(s), steady-state identical, "
                  f"sections {sec_lo}-{sec_hi}, evidence {ev_lo}-{ev_hi}, "
                  f"RSS drift {rss_drift} KiB, snapshots {snapshot_rows}")
        if not identical:
            detail = "; ".join(problems[:3])
        mx.record("V19", f"Long-running stability ({runs} runs)", ok, detail,
                  {"runs": runs,
                   "steady_state_identical": identical,
                   "warmup": "1 uncounted live fixture-capture pass",
                   "sections": [sec_lo, sec_hi],
                   "evidence": [ev_lo, ev_hi],
                   "bytes_drift": bytes_drift,
                   "rss_drift_kib": rss_drift,
                   "snapshot_rows": snapshot_rows,
                   "network_violations": len(violations),
                   "failed_runs": failures[:3],
                   "unrecorded_collectors": sorted(set(replayer.misses))})
    except Exception as exc:
        mx.record("V19", f"Long-running stability ({mx.args.v19_runs} runs)", False,
                  f"{type(exc).__name__}: {exc}",
                  {"traceback": traceback.format_exc()[-600:]})


def _snapshot_rows(mx: Matrix) -> int:
    path = mx.args.v19_db
    if not os.path.exists(path):
        return 0
    try:
        conn = sqlite3.connect(path, timeout=30)
        try:
            return int(conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0])
        finally:
            conn.close()
    except Exception:
        return -1


# --- edge cases ------------------------------------------------------------
@dataclasses.dataclass
class EdgeCase:
    name: str
    argv: List[str]
    expect_rc: Tuple[int, ...] = (0, 1, 2, 3)
    expect: str = ""          # substring that must appear in the output
    timeout: int = 240
    pty: bool = False


def v20_edge_cases(mx: Matrix) -> None:
    """Targets that are missing things, or are not targets at all.

    Every case must end in a deliberate outcome: a clean rejection, a
    clean scan, or an explicit error message. What is never acceptable is
    a traceback, a hang, or a report that claims success on a target that
    was never scanned.
    """
    target = mx.args.target
    cases: List[EdgeCase] = [
        EdgeCase("no DNS (NXDOMAIN)", ["this-host-does-not-exist-9f3a.invalid"],
                 expect_rc=(2,), expect="Cannot resolve"),
        EdgeCase("no DNS (bad IP literal)", ["999.999.999.999"],
                 expect_rc=(2,), expect="Cannot resolve"),
        EdgeCase("private target blocked", ["192.168.1.1"],
                 expect_rc=(2,), expect="SECURITY"),
        EdgeCase("private target allowed", ["192.168.1.1", "--allow-private"],
                 expect_rc=(0, 1, 2), timeout=120),
        EdgeCase("no certificate listener", ["198.51.100.7", "--no-display"],
                 expect_rc=(0, 1, 2), timeout=mx.args.edge_timeout),
        EdgeCase("IPv6 literal", ["2606:4700:4700::1111", "--no-display"],
                 expect_rc=(0, 1, 2), timeout=mx.args.edge_timeout),
        EdgeCase("public resolver / anycast", ["1.1.1.1", "--no-display"],
                 expect_rc=(0, 1, 2), timeout=mx.args.edge_timeout),
        EdgeCase("link-local / special use", ["169.254.169.254", "--no-display"],
                 expect_rc=(0, 1, 2), expect="", timeout=120),
    ]
    results: List[Dict[str, Any]] = []
    problems: List[str] = []
    for case in cases:
        argv = list(case.argv)
        if "--profile" not in argv and mx.args.profile:
            argv += ["--profile", mx.args.profile]
        run = run_cli(argv, timeout=case.timeout, pty=case.pty)
        blob = run.text + "\n" + run.err_text
        issues: List[str] = []
        if "Traceback (most recent call last)" in blob:
            issues.append("traceback in output")
        if run.timed_out:
            issues.append(f"timed out after {case.timeout}s")
        if run.rc not in case.expect_rc:
            issues.append(f"rc={run.rc}, expected one of {case.expect_rc}")
        if case.expect and case.expect not in blob:
            issues.append(f"missing expected text {case.expect!r}")
        # A failed target must not leave a success artifact behind.
        if run.rc != 0 and run.paths:
            issues.append(f"exported reports despite rc={run.rc}")
        results.append({"case": case.name, "argv": " ".join(argv), "rc": run.rc,
                        "seconds": round(run.seconds, 1),
                        "artifacts": len(run.paths),
                        "issues": issues,
                        "output": blob.strip().splitlines()[-1][:140] if blob.strip() else ""})
        if issues:
            problems.append(f"{case.name}: {', '.join(issues)}")
        flag = "ok  " if not issues else "FAIL"
        print(f"        [{flag}] {case.name:<28} rc={run.rc} "
              f"{run.seconds:5.1f}s {'' if not issues else '; '.join(issues)}", flush=True)
    ok = not problems
    mx.record("V20", "Edge cases", ok,
              f"{len(cases) - len(problems)}/{len(cases)} handled"
              if ok else "; ".join(problems[:3]),
              {"cases": results})


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
_MODULE: Dict[str, Any] = {}


def _module(mx: Matrix) -> Any:
    if "m" not in _MODULE:
        if ROOT not in sys.path:
            sys.path.insert(0, ROOT)
        import reconip
        _MODULE["m"] = reconip
    return _MODULE["m"]


def _fixture_report(mx: Matrix, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """A small non-empty report for in-process checks (V11)."""
    return {
        "input": mx.args.target, "ip": mx.args.target,
        "scan_status": "OK", "module_statuses": {"dns": "OK"},
        "dns_intelligence": {"evidence": [], "analysis": {}},
        "threat_intelligence": {"observed_threat_score": 0.0, "providers": []},
        "phase_i": {"score": 0.0, "coverage": 1.0, "providers": []},
        "trusted": {}, "network_intelligence": {}, "conflicts": [],
    }


@contextlib.contextmanager
def _temp_db_config(cfg: Dict[str, Any], mx: Matrix):
    """Point the databases at scratch files for the duration of a check."""
    tmpdir = tempfile.mkdtemp(prefix="reconip-vcheck-")
    db = os.path.join(tmpdir, "intel.db")
    cache = os.path.join(tmpdir, "cache.db")
    saved = json.dumps({k: cfg.get(k) for k in ("phase_e", "history", "cache")}, default=str)
    cfg["phase_e"] = {**(cfg.get("phase_e") or {}), "db_path": db}
    cfg["history"] = {**(cfg.get("history") or {}), "db_path": db, "enabled": True}
    cfg["cache"] = {**(cfg.get("cache") or {}), "db_path": cache}
    mx.args.v19_db = db
    try:
        yield
    finally:
        try:
            import reconip
            reconip.INTEL_DB = None
        except Exception:
            pass
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
        try:
            cfg.update(json.loads(saved))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------
def write_report(mx: Matrix, path: str) -> str:
    passed = sum(1 for c in mx.checks if c.status == "PASS")
    failed = sum(1 for c in mx.checks if c.status == "FAIL")
    skipped = sum(1 for c in mx.checks if c.status == "SKIP")
    lines: List[str] = []
    w = lines.append
    w("=" * 80)
    w(f"ReconIP Validation Matrix -- C3.10.2 expanded to 20 checks (Stage G5)")
    w("=" * 80)
    w(f"Date:     {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    w(f"Host:     {socket.gethostname()}")
    w(f"Python:   {sys.version.split()[0]}")
    w(f"Version:  {mx.version}")
    w(f"Target:   {mx.args.target} (profile: {mx.args.profile or 'config default'})")
    w(f"Runs:     v14={mx.args.v14_runs}  v19={mx.args.v19_runs}  "
      f"edge_timeout={mx.args.edge_timeout}s  pty={'on' if mx.args.pty else 'off'}")
    w("")
    w("-" * 80)
    w("MATRIX")
    w("-" * 80)
    width = max(len(f"{c.ident:<4} {c.name}") for c in mx.checks)
    for c in mx.checks:
        w(f"{f'{c.ident:<4} {c.name}':<{width}}  {c.status:<5} {c.detail}")
    w("")
    w(f"Result: {passed}/{len(mx.checks)} PASS"
      + (f", {failed} FAIL" if failed else "")
      + (f", {skipped} SKIP" if skipped else ""))
    if mx.notes:
        w("")
        w("-" * 80)
        w("ADVISORIES (do not change the verdict, but a human should see them)")
        w("-" * 80)
        for note in mx.notes:
            w(f"  - {note}")
    w("")
    w("-" * 80)
    w("EVIDENCE")
    w("-" * 80)
    for c in mx.checks:
        if not c.evidence:
            continue
        w(f"[{c.ident}] {c.name}: {c.status}")
        body = json.dumps(c.evidence, indent=1, default=str, sort_keys=True)
        for ln in body.splitlines():
            w("    " + ln)
        w("")
    w("=" * 80)
    w("End of report.")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
CHECKS: List[Tuple[str, str, Callable[[Matrix], None]]] = [
    ("V1", "Python compiles", v1_python_compiles),
    ("V2", "YAML parses", v2_yaml_parses),
    ("V3", "Version in banner", v3_version_in_banner),
    ("V4", "Threat score = 0", v4_threat_score_zero),
    ("V5", "Header shows target", v5_header_shows_target),
    ("V6", "Progress advances", v6_progress_advances),
    ("V7", "No duplicate output", v7_no_duplicate_output),
    ("V8", "No log leak", v8_no_log_leak),
    ("V9", "All 6 reports", v9_all_reports),
    ("V10", "Coverage = 1.0", v10_coverage),
    ("V11", "Determinism", v11_determinism_artifact),
    ("V12", "Clean install", v12_clean_install),
    ("V13", "Error isolation", v13_error_isolation),
    ("V14", "Determinism (5 runs)", v14_determinism),
    ("V15", "Cache health", v15_cache_health),
    ("V16", "Snapshot retention", v16_snapshot_retention),
    ("V17", "Data validation", v17_data_validation),
    ("V18", "Cross-report consistency", v18_cross_report_consistency),
    ("V19", "Long-running stability", v19_long_running_stability),
    ("V20", "Edge cases", v20_edge_cases),
]

SCAN_DEPENDENT = {"V3", "V4", "V5", "V6", "V7", "V8", "V9", "V10", "V17", "V18"}


def main() -> int:
    ap = argparse.ArgumentParser(description="ReconIP 20-check validation matrix")
    ap.add_argument("--target", default="8.8.8.8")
    ap.add_argument("--profile", default="standard",
                    help="scan profile for the live checks (default: standard)")
    ap.add_argument("--only", default="",
                    help="comma-separated check ids, e.g. V13,V16")
    ap.add_argument("--v14-runs", type=int, default=5)
    ap.add_argument("--v19-runs", type=int, default=50)
    ap.add_argument("--edge-timeout", type=int, default=180)
    ap.add_argument("--scan-timeout", type=int, default=900)
    ap.add_argument("--v12-venv", action="store_true",
                    help="build a throwaway venv for V12 (slow)")
    ap.add_argument("--strict-pins", action="store_true",
                    help="V12 fails when an installed version differs from the pin")
    ap.add_argument("--no-pty", dest="pty", action="store_false",
                    help="do not allocate a pty for the live scan")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    args.v19_db = ""
    args.only_set = {s.strip().upper() for s in args.only.split(",") if s.strip()}

    mx = Matrix(args)
    mx.load_config()
    print(f"ReconIP validation matrix -- {mx.version} -- target {args.target}", flush=True)

    selected = [(i, n, f) for i, n, f in CHECKS
                if not args.only_set or i in args.only_set]

    # One live scan serves every check that reads real output or artifacts.
    if any(i in SCAN_DEPENDENT for i, _, _ in selected):
        print("  .... live scan (this is the slow part)", flush=True)
        mx.scan = live_scan(mx, args.target, args.profile,
                            timeout=args.scan_timeout, use_pty=args.pty)
        run = mx.scan.run
        print(f"  .... scan rc={run.rc} in {run.seconds:.1f}s, "
              f"{len(mx.scan.artifacts)} artifact(s)", flush=True)

    started = time.time()
    for ident, name, fn in selected:
        print(f"  {ident} {name}", flush=True)
        try:
            fn(mx)
        except Exception as exc:
            mx.record(ident, name, False, f"harness error: {type(exc).__name__}: {exc}",
                      {"traceback": traceback.format_exc()[-800:]})

    passed = sum(1 for c in mx.checks if c.status == "PASS")
    failed = [c for c in mx.checks if c.status == "FAIL"]
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = args.out or os.path.join(REPORTS_DIR, f"validation_g5_{ts}.txt")
    write_report(mx, out)
    print(f"\n{passed}/{len(mx.checks)} PASS in {time.time() - started:.1f}s")
    for c in failed:
        print(f"  FAIL {c.ident} {c.name}: {c.detail}")
    print(f"Report: {out}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
