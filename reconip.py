#!/usr/bin/env python3
"""ReconIP v21.2 — OSINT/CTI Platform"""
import argparse, sys, os, re, json, time, logging, socket, ssl
import ipaddress, subprocess, hashlib, math, asyncio, sqlite3
import threading, uuid, random, shutil, signal, pathlib
import hmac, urllib.request, urllib.error, urllib.parse
import html as _html
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from abc import ABC, abstractmethod

import yaml, requests, dns.resolver, dns.reversename, dns.exception
try: import geoip2.database; GEOIP2 = True
except ImportError: geoip2 = None; GEOIP2 = False
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as _ch
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, ec as _ec, dsa as _dsa, ed25519 as _ed, ed448 as _ed4
    CRYPTO = True
except ImportError: CRYPTO = False

# ============================================================
#  ANSI COLOR ENGINE — HACKER THEME
# ============================================================
class C:
    RST = "\033[0m"; BLD = "\033[1m"; DIM = "\033[2m"; ITL = "\033[3m"; UND = "\033[4m"
    RED = "\033[91m"; DRED = "\033[31m"; GRN = "\033[92m"; DGRN = "\033[32m"
    YEL = "\033[93m"; ORG = "\033[38;5;208m"; BLU = "\033[94m"; MAG = "\033[95m"
    CYN = "\033[96m"; WHT = "\033[97m"; GRY = "\033[90m"
    BG_RED = "\033[41m"; BG_GRN = "\033[42m"; BG_BLK = "\033[40m"
    OK = "\033[1;92m"; FAIL = "\033[1;91m"; WARN = "\033[1;93m"; INFO = "\033[1;96m"
    KEY = "\033[1;91m"; VAL = "\033[1;92m"

def _w(): return shutil.get_terminal_size((100, 24)).columns
def _c(txt, *codes): return "".join(codes) + str(txt) + C.RST
def _vlen(s):
    return len(re.sub(r'\033\[[0-9;]*m', '', str(s)))
def _vpad(s, width):
    return s + ' ' * max(0, width - _vlen(s))

def _bar(pct, width=40, fill="█", empty="·", color=None):
    pct = max(0.0, min(100.0, float(pct or 0)))
    filled = int(round(pct / 100 * width))
    color = color or (C.GRN if pct < 40 else C.YEL if pct < 70 else C.RED)
    return f"[{color}{fill*filled}{C.DIM}{empty*(width-filled)}{C.RST}]"

def _badge(text, style="info"):
    styles = {"ok": (C.BG_GRN, C.WHT), "fail": (C.BG_RED, C.WHT),
              "warn": (C.YEL, C.RST), "info": (C.CYN, C.RST), "dim": (C.DIM, C.RST)}
    bg, fg = styles.get(style, styles["info"])
    return f"{bg}{C.BLD} {text} {C.RST}"

def _status_dot(status):
    s = str(status or "").upper()
    if s == "SUCCESS": return _c("●", C.OK) + " " + _c(s, C.OK)
    if s == "PARTIAL": return _c("●", C.WARN) + " " + _c(s, C.WARN)
    if s == "FAILED": return _c("●", C.FAIL) + " " + _c(s, C.FAIL)
    if s == "SKIPPED": return _c("○", C.GRY) + " " + _c(s, C.GRY)
    return _c("?", C.GRY) + " " + s

def _severity_color(sev):
    return {"HIGH": C.FAIL, "CRITICAL": C.FAIL, "MODERATE": C.WARN,
            "LOW": C.INFO, "INFORMATIONAL": C.GRY}.get(str(sev or "").upper(), C.GRY)

def _banner():
    art = [
        "██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██████╗ ",
        "██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║██╔══██╗",
        "██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║██████╔╝",
        "██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║██╔═══╝ ",
        "██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██║     ",
        "╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝     ",
    ]
    w = min(_w(), 100); lines = [C.DRED + "╔" + "═" * (w - 2) + "╗" + C.RST]
    for row in art:
        pad = (w - 4 - len(row)) // 2
        lines.append(C.DRED + "║ " + C.RST + C.BLD + C.GRN + " " * pad + row +
                     " " * (w - 4 - len(row) - pad) + C.RST + C.DRED + " ║" + C.RST)
    sub = "O S I N T   P L A T F O R M   •   v 3 0 . 1"
    pad = (w - 4 - len(sub)) // 2
    lines.append(C.DRED + "║ " + C.RST + C.RED + " " * pad + sub +
                 " " * (w - 4 - len(sub) - pad) + C.RST + C.DRED + " ║" + C.RST)
    lines.append(C.DRED + "╚" + "═" * (w - 2) + "╝" + C.RST)
    return "\n".join(lines)

def _kv(key, value, kw=12, vcolor=None):
    k = _c(str(key).ljust(kw), C.KEY)
    v = _c(str(value), vcolor or C.VAL)
    return f"   {k} {v}"

def _section_header(num, title):
    w = min(_w(), 100)
    badge = _c(f" {num} ", C.BLD, C.WHT, C.BG_RED)
    spacer = "─" * max(0, w - 12 - len(title))
    return (f"\n{C.DRED}╭─{C.RST} {badge} "
            f"{_c(title.upper(), C.BLD, C.GRN)} {C.DRED}{spacer}╮{C.RST}")

def _section_footer():
    w = min(_w(), 100)
    return f"{C.DRED}╰" + "─" * (w - 2) + f"╯{C.RST}"

# ============================================================
#  SECURE LOGGING
# ============================================================
_SECRETS = [re.compile(p, re.I) for p in (
    r"(api[_-]?key\s*[:=]\s*)\S+", r"(bearer\s+)\S+", r"(x-apikey\s*[:=]\s*)\S+",
    r"(x-otx-api-key\s*[:=]\s*)\S+", r"(authorization\s*[:=]\s*)\S+",
    r"(password\s*[:=]\s*)\S+", r"(token\s*[:=]\s*)\S+")]

def redact(s):
    if s is None: return s
    s = str(s)
    for p in _SECRETS: s = p.sub(lambda m: m.group(1) + "***", s)
    return s

class RF(logging.Formatter):
    def format(self, r):
        try: return redact(super().format(r))
        except Exception: return f"{r.levelname}: <?>"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
from logging.handlers import RotatingFileHandler


# v21.12: org cleaning helper (defined early so all collectors can use it)
def _clean_org(v):
    """Strip leading 'ASxxxxx ' from organization names."""
    if not v:
        return v
    return re.sub(r"^AS\d+\s+", "", str(v)).strip()

_rfh = RotatingFileHandler("reconip.log", maxBytes=10*1024*1024, backupCount=5)
for h in logging.getLogger().handlers + [_rfh]:
    h.setFormatter(RF("%(asctime)s [%(levelname)s] %(message)s"))
logging.getLogger().addHandler(_rfh)
log = logging.getLogger("ReconIP")
socket.setdefaulttimeout(3.0)

# ============================================================
#  CONFIG
# ============================================================
def load_cfg(p="config.yaml"):
    if not os.path.exists(p): return {}
    try: return yaml.safe_load(open(p, encoding="utf-8")) or {}
    except Exception as e: log.error(f"config: {e}"); return {}

DEFAULTS = {
    "general": {"timeout": 5, "max_retries": 2, "user_agent": "ReconIP/21.2", "proxy": ""},
    "api_keys": {}, "source_reliability": {},
    "freshness": {"thresholds": {"fresh":300,"recent":3600,"aging":86400,"stale":604800},
                  "weights": {"fresh":1.0,"recent":0.9,"aging":0.7,"stale":0.4,"unknown":0.5}},
    "validation": {"min_sources_for_trusted": 2, "min_agreement_for_trusted": 60.0,
                   "geo_conflict_km": {"low": 25, "moderate": 100, "high": 500}},
    "geo_validation": {"anycast_ips": []},
    "sources": {"geo": {"enabled": ["ip_api","ipinfo","freegeoip","maxmind_local"], "maxmind_db_path": ""},
                "network": {"asn_sources": ["ripe","bgpview","bgp_he","whois"]},
                "dns": {"nameservers": ["1.1.1.1","9.9.9.9"], "record_types": ["PTR","CNAME","MX","NS","TXT"]},
                "certificate": {"ports": [443, 8443], "max_historical_certs": 30},
                "threat_intel": {"sources": []}},
    "phase_b": {"threat_score": {"weights": {"abuse_report":10,"malicious_reputation":15,"malware_association":20,
                                              "phishing":20,"botnet":25,"blacklist":30},
                                 "thresholds": {"no_evidence":20,"low":40,"moderate":60,"high":80}},
                "infrastructure_risk": {"weights": {"tor_exit":40,"vpn":20,"proxy":20,"cloud":15,"hosting":10,
                                                     "datacenter":12,"shared_hosting":8,"public_dns":5,"anycast":5,
                                                     "cdn":3,"residential":2,"carrier_nat":3}},
                "data_confidence": {"weights": {"reliability":0.30,"agreement":0.25,"completeness":0.20,
                                                 "freshness":0.15,"validation":0.10},
                                    "conflict_penalty": {"high":25,"moderate":15,"low":5}},
                "evidence_quality": {"weights": {"reliability":0.30,"independence":0.25,"freshness":0.20,
                                                  "consistency":0.15,"specificity":0.10}},
                "assessment_confidence": {"guardrails": {"min_coverage_for_high":70,
                                                          "min_data_confidence_for_high":70,
                                                          "min_coverage_for_moderate":40,
                                                          "max_high_conflicts":0,"max_moderate_conflicts":2,
                                                          "min_successful_providers":2,
                                                          "min_evidence_quality_for_high":60}},
                "classification": {"concern_levels": {"critical":80,"high":60,"moderate":40,"low":20}}},
    "phase_c": {"relationship_confidence": {"base_per_source": 20.0, "min_base": 40.0, "max_confidence": 100.0}},
    "phase_d": {"workers": 8, "cache": {"enabled": True, "db_path": "./reconip_cache.db", "ttl": {}},
                "rate_limits_per_minute": {"default": 60}},
    "phase_e": {"enabled": True, "db_path": "./reconip.db", "retention": {}},
    "phase_f": {"retry": {"max_attempts": 3, "base_delay": 0.5, "max_delay": 5.0, "jitter": 0.2},
                "circuit": {"fail_threshold": 5, "recovery_timeout": 60}},
    "phase_g": {"dns": {"record_types": ["A","AAAA","PTR","CNAME","MX","NS","TXT","CAA"],
                        "forward_lookup_from_ptr": True},
                "anomaly_severity": {"forward_reverse_mismatch":"moderate","multiple_ptrs":"low",
                                     "ptr_without_forward":"low","asn_inconsistency":"moderate",
                                     "organization_inconsistency":"low","prefix_inconsistency":"low",
                                     "hostname_churn":"moderate","dns_provider_relationship":"informational"},
                "dns_providers": {"cloudflare":["ns.cloudflare.com"],"route53":["awsdns"],
                                  "google":["googledomains.com","google.com"],"azure":["azure-dns"]}},
    "phase_h": {"ports": [443,8443], "max_historical_certs": 30, "near_expiry_days": 30,
                "san_max_per_cert": 200,
                "weak_algorithms": {"signature": ["md5","sha1"], "min_rsa_bits": 2048, "min_ecdsa_bits": 256}},
    "phase_i": {"providers": {}, "disagreement": {"confidence_penalty_per_conflict": 15.0, "max_penalty": 40.0}},
    "phase_j": {"window_days": 90, "rapid_changes_threshold": 3, "rapid_window_hours": 24,
                "stability": {"normal_changes_per_30d": 2, "volatile_changes_per_30d": 8}},
    "phase_k": {"max_depth": 4, "max_paths": 100, "min_confidence": 0.0,
                "confidence": {"base": 40.0, "per_source": 20.0, "cap": 95.0},
                "conflicts": {"min_confidence_for_conflict": 50.0}},
    "phase_m": {"enabled": True, "host": "127.0.0.1", "port": 8787, "require_auth": True,
                "token_env_var": "RECONIP_API_TOKEN", "tokens": [], "rate_limit_per_min": 60,
                "max_batch": 100, "max_body_bytes": 1000000, "cors_origin": ""},
    "phase_n": {"allow_private_targets": False, "max_batch": 100, "max_concurrent_jobs": 8,
                "subprocess_timeout": 6.0, "max_body_bytes": 1000000},
    "evidence": {"freshness_ttl": {"dns": 3600, "whois": 86400, "threat": 1800, "ct": 86400, "passive_dns": 3600},
                 "default_ttl": 3600,
                 "confidence_defaults": {"dns": 0.95, "whois": 0.85, "ct": 0.9, "threat": 0.5, "passive_dns": 0.6}}
}

def deep_merge(a, b):
    for k, v in b.items():
        if k in a and isinstance(a[k], dict) and isinstance(v, dict): a[k] = deep_merge(a[k], v)
        else: a[k] = v
    return a

CFG = deep_merge(DEFAULTS, load_cfg())
PB, PC, PD, PE, PF, PG, PH, PI, PJ, PK = (CFG[k] for k in
    ("phase_b","phase_c","phase_d","phase_e","phase_f","phase_g","phase_h",
     "phase_i","phase_j","phase_k"))
PM, PN = CFG["phase_m"], CFG["phase_n"]

# ============================================================
#  ENUMS
# ============================================================
class DS(str, Enum): AVAILABLE="AVAILABLE"; NOT_FOUND="NOT_FOUND"; NOT_CONFIGURED="NOT_CONFIGURED"; ERROR="ERROR"
class FR(str, Enum): FRESH="FRESH"; RECENT="RECENT"; AGING="AGING"; STALE="STALE"; UNKNOWN="UNKNOWN"
class SEV(str, Enum): LOW="LOW"; MODERATE="MODERATE"; HIGH="HIGH"
class ET(str, Enum): IP="IP"; CIDR="CIDR"; ASN="ASN"; ORG="Organization"; ISP="ISP"
class TS(str, Enum): NO_DATA="NO_DATA"; NOT_CONFIGURED="NOT_CONFIGURED"; NO_THREAT="NO_THREAT_FOUND"
class TS2:
    PROVIDER_ERROR="PROVIDER_ERROR"; RATE_LIMITED="RATE_LIMITED"; POSITIVE="POSITIVE_EVIDENCE"
class EC(str, Enum): TRANSIENT="TRANSIENT"; PERMANENT="PERMANENT"; RATE_LIMITED="RATE_LIMITED"
class EC2: AUTH="AUTHENTICATION"; NETWORK="NETWORK"; TIMEOUT="TIMEOUT"
class EC3: INVALID="INVALID_RESPONSE"; CONFIG="CONFIGURATION"; INTERNAL="INTERNAL"
class MS(str, Enum): SUCCESS="SUCCESS"; PARTIAL="PARTIAL"; FAILED="FAILED"; SKIPPED="SKIPPED"
class CS(str, Enum): CLOSED="CLOSED"; OPEN="OPEN"; HALF_OPEN="HALF_OPEN"
class SecurityError(Exception): pass

_RETRYABLE = {EC.TRANSIENT.value, EC2.NETWORK, EC2.TIMEOUT}

def http_class(s):
    if s == 429: return EC.RATE_LIMITED.value
    if s in (401, 403): return EC2.AUTH
    if 500 <= s < 600: return EC.TRANSIENT.value
    if 400 <= s < 500: return EC.PERMANENT.value
    return EC.TRANSIENT.value

def exc_class(e):
    if isinstance(e, requests.exceptions.Timeout): return EC2.TIMEOUT
    if isinstance(e, requests.exceptions.ConnectionError): return EC2.NETWORK
    if isinstance(e, json.JSONDecodeError): return EC3.INVALID
    if isinstance(e, socket.gaierror): return EC2.NETWORK
    if isinstance(e, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)): return EC.PERMANENT.value
    if isinstance(e, ssl.SSLError): return EC2.NETWORK
    return EC3.INTERNAL

def backoff(a):
    c = PF["retry"]; d = min(c["max_delay"], c["base_delay"] * (2 ** a))
    if c["jitter"]: d += random.uniform(0, d * c["jitter"])
    return d

def now(): return datetime.now(timezone.utc).isoformat()

def hav(a, b, c, d):
    R = 6371.0; p1, p2 = math.radians(a), math.radians(c)
    dp, dl = math.radians(c-a), math.radians(d-b)
    x = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return R * 2 * math.atan2(math.sqrt(x), math.sqrt(1-x))


# v21.9: country normalization helpers (added)
if "_COUNTRY_ALIASES_V21" not in globals():
    _COUNTRY_ALIASES_V21 = {
        "us": "United States", "usa": "United States",
        "united states of america": "United States",
        "uk": "United Kingdom", "gb": "United Kingdom",
        "great britain": "United Kingdom",
        "ru": "Russia", "russian federation": "Russia",
        "kr": "South Korea", "korea": "South Korea",
        "republic of korea": "South Korea",
        "cn": "China", "prc": "China",
        "ir": "Iran", "irn": "Iran",
        "tr": "Turkey", "turkiye": "Turkey",
        "de": "Germany", "fr": "France", "nl": "Netherlands",
        "jp": "Japan", "br": "Brazil", "in": "India",
        "au": "Australia", "ca": "Canada",
        "it": "Italy", "es": "Spain",
    }

if "_normalize_country" not in globals():
    def _normalize_country(v):
        if not v: return ""
        s = str(v).strip()
        if not s: return ""
        return _COUNTRY_ALIASES_V21.get(s.lower(), s)

if "_canon_country" not in globals():
    def _canon_country(v):
        return _normalize_country(v).lower()

def fnum(v):
    try: return float(v) if v not in (None,"") else None
    except: return None

# ============================================================
#  DATA MODELS
# ============================================================
@dataclass
class Ev:
    id: str
    target: str
    data_type: str
    field: str
    provider: str
    value: Any
    raw_value: Any
    timestamp: str
    reliability: float
    status: str
    freshness: str = FR.UNKNOWN.value
    weight: float = 1.0
    def to_dict(self): return asdict(self)

@dataclass
class TF:
    field: str
    value: Any
    confidence: float
    evidence_ids: List[str]
    providers: List[str]
    reason: str
    status: str = "TRUSTED"

@dataclass
class CFL:
    field: str
    severity: str
    description: str
    sources: List[str]
    observations: List[Dict]
    resolution: str = ""
    confidence_impact: float = 0.0
    distance_km: Optional[float] = None

_evc = 0
_evc_lock = threading.Lock()

def eid(p):
    global _evc
    with _evc_lock:
        _evc += 1
        n = _evc
    return f"EV-{p[:3].upper()}-{n:06d}"

def mk_ev(t, dt, f, prov, v, raw, status=DS.AVAILABLE.value, ts=None):
    base = prov.split(":")[0] if ":" in prov else prov
    rel = CFG["source_reliability"].get(base, {}).get("reliability", 0.5)
    ts = ts or now()
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(ts.replace("Z","+00:00"))).total_seconds()
    except Exception:
        age = None
    th, w = CFG["freshness"]["thresholds"], CFG["freshness"]["weights"]
    if age is None: fr, wt = FR.UNKNOWN.value, w["unknown"]
    elif age < th["fresh"]: fr, wt = FR.FRESH.value, w["fresh"]
    elif age < th["recent"]: fr, wt = FR.RECENT.value, w["recent"]
    elif age < th["aging"]: fr, wt = FR.AGING.value, w["aging"]
    else: fr, wt = FR.STALE.value, w["stale"]
    return Ev(id=eid(dt), target=t, data_type=dt, field=f, provider=prov,
              value=v, raw_value=raw, timestamp=ts, reliability=rel, status=status,
              freshness=fr, weight=rel*wt)

# ============================================================
#  EVIDENCE ENGINE — v31 (Stage 2)
# ============================================================
@dataclass
class Evidence:
    source: str
    timestamp: str
    value: Any
    normalized_value: Any
    confidence: float
    freshness: str
    status: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Stage 2: expose legacy keys for DB persist and report compat
        meta = self.metadata or {}
        d["provider"] = self.source
        d["data_type"] = meta.get("data_type", "unknown")
        d["field"] = meta.get("field", "unknown")
        d["reliability"] = self.confidence
        d["raw_value"] = meta.get("raw_value", self.value)
        d["target"] = meta.get("target", "")
        d["id"] = meta.get("id", f"EV-{self.source[:3].upper()}-000000")
        # Keep original for traceability
        return d

    # Compatibility aliases for legacy Ev consumers (Stage 2 bridge)
    @property
    def provider(self): return self.source
    @property
    def reliability(self): return self.confidence
    @property
    def field(self): return self.metadata.get("field", "")
    @property
    def data_type(self): return self.metadata.get("data_type", "")
    @property
    def target(self): return self.metadata.get("target", "")
    @property
    def raw_value(self): return self.metadata.get("raw_value", self.value)
    @property
    def weight(self): return self.metadata.get("weight", self.confidence)
    @property
    def id(self): return self.metadata.get("id", f"EV-{self.source[:3].upper()}-000000")

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def compute_freshness(timestamp_iso: str, ttl_seconds: int) -> str:
        """
        FRESH   → age <= ttl
        STALE   → ttl < age <= 2 * ttl
        EXPIRED → age > 2 * ttl
        UNKNOWN → timestamp invalid or missing
        """
        try:
            ts = datetime.strptime(timestamp_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except Exception:
            return "UNKNOWN"
        age = (datetime.now(timezone.utc) - ts).total_seconds()
        if age <= ttl_seconds:
            return "FRESH"
        if age <= 2 * ttl_seconds:
            return "STALE"
        return "EXPIRED"

def make_evidence(source, value, normalized_value=None, confidence=1.0,
                  status="OK", ttl_key=None, metadata=None):
    """
    Create an Evidence object with automatic timestamp and freshness.
    ttl_key: one of 'dns', 'whois', 'threat', 'ct', 'passive_dns' — resolved via config.
    """
    ttl_cfg = CFG.get("evidence", {}) if isinstance(CFG, dict) else {}
    ttl_map = ttl_cfg.get("freshness_ttl", {}) if isinstance(ttl_cfg, dict) else {}
    default_ttl = ttl_cfg.get("default_ttl", 3600) if isinstance(ttl_cfg, dict) else 3600
    ttl_seconds = ttl_map.get(ttl_key, default_ttl) if ttl_key else default_ttl
    # Fallback to confidence_defaults if confidence not provided
    if confidence is None:
        conf_defaults = ttl_cfg.get("confidence_defaults", {})
        confidence = conf_defaults.get(ttl_key, 0.5) if ttl_key else 0.5
    ts = Evidence.now_iso()
    freshness = Evidence.compute_freshness(ts, ttl_seconds)
    return Evidence(
        source=source,
        timestamp=ts,
        value=value,
        normalized_value=normalized_value if normalized_value is not None else value,
        confidence=float(confidence),
        freshness=freshness,
        status=status,
        metadata=metadata or {}
    )

def format_evidence(ev: Evidence) -> str:
    """Render a single Evidence object as a compact string (Stage 2)."""
    try:
        return (
            f"[{ev.source}] "
            f"value={ev.value} "
            f"norm={ev.normalized_value} "
            f"conf={ev.confidence:.2f} "
            f"fresh={ev.freshness} "
            f"status={ev.status}"
        )
    except Exception:
        return str(ev)

def merge_evidence(evidence_list):
    """
    Merge multiple Evidence objects into a single aggregated Evidence (Stage 2).
    Strategy:
      - Pick the highest-confidence non-FAILED evidence as the primary.
      - Collect all sources and statuses in metadata.
      - Recompute aggregate confidence (weighted average).
    """
    if not evidence_list:
        return None
    valid = [e for e in evidence_list if getattr(e, 'status', '') == "OK"]
    if not valid:
        # All failed — return a FAILED aggregate
        sources = [getattr(e, 'source', str(e)) for e in evidence_list]
        return make_evidence(
            source="aggregate",
            value=None,
            normalized_value=None,
            confidence=0.0,
            status="FAILED",
            metadata={"sources": sources}
        )
    primary = max(valid, key=lambda e: float(getattr(e, 'confidence', 0)))
    avg_conf = sum(float(getattr(e, 'confidence', 0)) for e in valid) / len(valid)
    sources = sorted({getattr(e, 'source', '') for e in evidence_list if getattr(e, 'source', '')})
    statuses = {getattr(e, 'source', ''): getattr(e, 'status', '') for e in evidence_list}
    return make_evidence(
        source="aggregate",
        value=getattr(primary, 'value', None),
        normalized_value=getattr(primary, 'normalized_value', None),
        confidence=round(avg_conf, 3),
        status="OK",
        metadata={
            "sources": sources,
            "statuses": statuses,
            "primary_source": getattr(primary, 'source', ''),
            "count": len(valid)
        }
    )

def ev_to_evidence(ev: Ev) -> Evidence:
    """Convert legacy Ev to new Evidence (Stage 2 bridge, v31)."""
    try:
        # Map freshness from Ev (FRESH/RECENT/AGING/STALE) to new (FRESH/STALE/EXPIRED)
        fr = ev.freshness
        # Keep original freshness value; new logic will compute via TTL but preserve
        new_fresh = fr if fr in ("FRESH", "STALE", "EXPIRED", "UNKNOWN") else "UNKNOWN"
        if fr == FR.RECENT.value: new_fresh = "FRESH"
        elif fr == FR.AGING.value: new_fresh = "STALE"
        return Evidence(
            source=ev.provider,
            timestamp=ev.timestamp,
            value=ev.value,
            normalized_value=ev.value,
            confidence=float(ev.reliability),
            freshness=new_fresh,
            status=ev.status,
            metadata={"id": ev.id, "target": ev.target, "data_type": ev.data_type,
                      "field": ev.field, "raw_value": ev.raw_value, "weight": ev.weight,
                      "reliability": ev.reliability}
        )
    except Exception:
        return make_evidence(source=getattr(ev, 'provider', 'unknown'), value=getattr(ev, 'value', None), confidence=0.5, status="FAILED")

def evidence_to_ev(ev: Evidence, target="", data_type="", field="") -> Ev:
    """Convert new Evidence back to legacy Ev for pipeline compatibility."""
    try:
        return Ev(
            id=ev.metadata.get("id", eid(ev.source)),
            target=ev.metadata.get("target", target),
            data_type=ev.metadata.get("data_type", data_type),
            field=ev.metadata.get("field", field),
            provider=ev.source,
            value=ev.value,
            raw_value=ev.metadata.get("raw_value", ev.value),
            timestamp=ev.timestamp,
            reliability=float(ev.confidence),
            status=ev.status,
            freshness=ev.freshness if ev.freshness in [FR.FRESH.value, FR.STALE.value, FR.UNKNOWN.value] else FR.UNKNOWN.value,
            weight=float(ev.confidence)
        )
    except Exception:
        return mk_ev(target or "unknown", data_type or "unknown", field or "unknown", ev.source, ev.value, ev.value, status=ev.status)

# Stage 2: Evidence-based collector wrappers (spec examples, v31)
def collect_threat_intel(target, providers=None):
    """
    Threat Intelligence collector — Stage 2 Evidence version (v31).
    Wraps each provider result in Evidence with proper status.
    """
    evidences = []
    provs = providers or {p.name: p for p in PROVIDERS}  # fallback
    # If providers is list of provider instances, handle
    if isinstance(provs, dict):
        items = provs.items()
    else:
        items = [(p.name if hasattr(p, 'name') else str(p), p) for p in provs]
    for name, provider in items:
        try:
            result = provider.query(target) if hasattr(provider, 'query') else None
        except Exception as e:
            result = None
            err = str(e)
        else:
            err = getattr(result, 'error', None) or getattr(provider, 'last_error', None)
        if result is None or getattr(result, 'status', '') in (TS2.PROVIDER_ERROR, TS.NOT_CONFIGURED.value, "FAILED"):
            evidences.append(make_evidence(
                source=name, value=None, normalized_value=None,
                confidence=0.0, status="FAILED",
                ttl_key="threat",
                metadata={"reason": err or "provider error", "provider": name}
            ))
            continue
        # Success case: handle Obs
        if hasattr(result, 'to_dict'):
            d = result.to_dict() if callable(getattr(result, 'to_dict')) else {}
        elif isinstance(result, dict):
            d = result
        else:
            d = {}
        # Extract raw_score etc. for compatibility
        raw_score = d.get("score") or getattr(result, 'score', None)
        norm_score = d.get("score") or raw_score
        conf = d.get("confidence") or getattr(result, 'confidence', 0.5)
        evidences.append(make_evidence(
            source=name,
            value=raw_score,
            normalized_value=norm_score,
            confidence=conf,
            status="OK",
            ttl_key="threat",
            metadata={
                "tags": d.get("categories", []) or getattr(result, 'categories', []),
                "first_seen": d.get("first_seen") or getattr(result, 'first_seen', None),
                "last_seen": d.get("last_seen") or getattr(result, 'last_seen', None),
                "evidence": d.get("evidence") or str(result)
            }
        ))
    return evidences

def collect_certificates(target):
    """
    Certificate collector — Stage 2 Evidence version (v31).
    """
    evidences = []
    # Use existing collect_certs logic but wrap via Evidence
    try:
        # reuse ct_parse if available and cert data
        domain = target if isinstance(target, str) and "." in target else target
        # Attempt to get CT entries via existing functions if domain
        if domain:
            # Try to use collect_certs existing but we create Evidence directly
            # For now, create dummy to show pattern; real impl delegates to collect_certs
            pass
        # Example pattern: for each cert in get_ct_entries
        # (Placeholder - actual certs handled via collect_certs Evidence already)
    except Exception:
        pass
    # Fallback: create Evidence for each cert via ct_parse
    try:
        from reconip import ct_parse as _ct_parse  # local
    except Exception:
        _ct_parse = ct_parse
    # If we have cert records in evidence, they will be handled elsewhere
    return evidences

def collect_passive_dns(target):
    """
    Passive DNS collector — Stage 2 Evidence version (v31).
    """
    evidences = []
    try:
        # Use merge_passive_dns to get records
        recs = merge_passive_dns(target, [])
        for rec in recs:
            evidences.append(make_evidence(
                source=rec.get("source", "passive_dns"),
                value=rec.get("domain") or rec.get("hostname"),
                normalized_value=(rec.get("domain") or rec.get("hostname") or "").lower(),
                confidence=rec.get("confidence", 0.6),
                status="OK",
                ttl_key="passive_dns",
                metadata={
                    "first_seen": rec.get("first_seen") or rec.get("first"),
                    "last_seen": rec.get("last_seen") or rec.get("last"),
                    "hostname": rec.get("hostname")
                }
            ))
    except Exception as e:
        evidences.append(make_evidence(source="passive_dns", value=None, normalized_value=None, confidence=0.0, status="FAILED", ttl_key="passive_dns", metadata={"reason": str(e)}))
    return evidences

# ============================================================
#  SOURCE RELIABILITY ENGINE — v32 (Stage 3)
# ============================================================
class BaseProvider(ABC):
    """
    Abstract base class for all threat intelligence providers (Stage 3).
    Each provider must implement query(target) -> Optional[Dict].
    """
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.api_key_env = self.config.get("api_key_env")
        self.api_key = os.getenv(self.api_key_env) if self.api_key_env else None
        # Reliability metrics
        self.reliability = float(self.config.get("reliability", 0.5))
        self.weight = float(self.config.get("weight", 1.0))
        # Runtime metrics
        self.latency = None
        self.last_success = None
        self.error_rate = 0.0
        self.total_queries = 0
        self.failed_queries = 0
        # Freshness
        self.freshness_ttl = int(self.config.get("freshness_ttl", 1800))
        self.logger = logging.getLogger(f"provider.{self.name}")

    def is_configured(self) -> bool:
        """Return True if the provider has all required configuration (e.g., API key)."""
        if self.api_key_env and not self.api_key:
            return False
        return True

    def record_success(self, latency: float):
        self.latency = latency
        self.last_success = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.total_queries += 1

    def record_failure(self, error: str):
        self.total_queries += 1
        self.failed_queries += 1
        self.error_rate = self.failed_queries / self.total_queries if self.total_queries else 0.0
        self.logger.warning(f"Provider {self.name} failed: {error}")

    def compute_confidence(self) -> float:
        """Dynamic confidence based on reliability, error_rate, freshness."""
        base = self.reliability
        base *= (1.0 - self.error_rate)
        if self.last_success is None:
            base *= 0.5
        return max(0.0, min(1.0, round(base, 3)))

    @abstractmethod
    def query(self, target: str) -> Optional[Dict[str, Any]]:
        """Query provider for target. Must return dict with threat_score, tags, etc. Return None on failure."""
        pass

# Provider registry for Stage 3 (kept separate from legacy PROVIDERS list for compat)
PROVIDERS: Dict[str, type] = {}
PROVIDERS_REGISTRY: Dict[str, type] = {}

class HTTPProvider(BaseProvider):
    """
    Generic provider that performs HTTP GET/POST to a configured URL (Stage 3).
    Response expected JSON. Mapping via response_map dot notation.
    """
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.url_template = config.get("url", "")
        self.method = config.get("method", "GET").upper()
        self.headers = dict(config.get("headers", {}))
        self.params = dict(config.get("params", {}))
        self.timeout = int(config.get("timeout", 10))
        self.response_map = dict(config.get("response_map", {}))

    def query(self, target: str) -> Optional[Dict[str, Any]]:
        if not self.is_configured():
            self.logger.warning(f"Provider {self.name} not configured (missing API key).")
            return None
        url = self.url_template.format(target=target) if self.url_template else ""
        if not url:
            self.record_failure("no url")
            return None
        headers = self.headers.copy()
        params = self.params.copy()
        if self.api_key:
            if self.config.get("api_key_header"):
                headers[self.config["api_key_header"]] = self.api_key
            elif self.config.get("api_key_param"):
                params[self.config["api_key_param"]] = self.api_key
        start = time.time()
        try:
            if self.method == "GET":
                resp = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            else:
                resp = requests.post(url, headers=headers, json=params, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            latency = time.time() - start
            self.record_success(latency)
            result = {}
            for key, path in self.response_map.items():
                result[key] = self._extract(data, path)
            return result
        except Exception as e:
            self.record_failure(str(e))
            return None

    def _extract(self, data: Any, path: str) -> Any:
        """Extract nested value via dot notation."""
        cur = data
        for part in path.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            elif isinstance(cur, list) and part.isdigit():
                try:
                    cur = cur[int(part)]
                except Exception:
                    return None
            else:
                return None
            if cur is None:
                return None
        return cur

def load_providers(config: Dict[str, Any]) -> Dict[str, BaseProvider]:
    """Instantiate all enabled providers from config (Stage 3)."""
    providers: Dict[str, BaseProvider] = {}
    for name, pconfig in (config.get("providers", {}) or {}).items():
        if not pconfig.get("enabled", True):
            continue
        ptype = pconfig.get("type", "http")
        if ptype == "http":
            providers[name] = HTTPProvider(name, pconfig)
            PROVIDERS_REGISTRY[name] = HTTPProvider
        else:
            logging.warning(f"Unknown provider type '{ptype}' for {name}")
    return providers

def load_api_keys(providers: Dict[str, BaseProvider]) -> None:
    """Check required API keys and log warnings (Stage 3)."""
    for name, provider in providers.items():
        if provider.api_key_env and not provider.api_key:
            logging.warning(f"API key for {name} not set. Set {provider.api_key_env} to enable.")

def run_providers(target: str, providers: Dict[str, BaseProvider]) -> List[Evidence]:
    """
    Run all enabled providers and return List[Evidence] (Stage 3).
    Each Evidence represents provider result with status OK/FAILED/NOT_CONFIGURED.
    """
    evidences: List[Evidence] = []
    for name, provider in providers.items():
        if not provider.enabled:
            continue
        if not provider.is_configured():
            evidences.append(make_evidence(
                source=name,
                value=None,
                normalized_value=None,
                confidence=0.0,
                status="NOT_CONFIGURED",
                ttl_key="threat",
                metadata={"reason": "missing API key", "api_key_env": provider.api_key_env, "data_type": "threat", "field": name}
            ))
            continue
        result = provider.query(target)
        if result is None:
            evidences.append(make_evidence(
                source=name,
                value=None,
                normalized_value=None,
                confidence=0.0,
                status="FAILED",
                ttl_key="threat",
                metadata={"error_rate": provider.error_rate, "latency": provider.latency, "data_type": "threat", "field": name}
            ))
            continue
        conf = provider.compute_confidence()
        evidences.append(make_evidence(
            source=name,
            value=result.get("threat_score"),
            normalized_value=result.get("threat_score"),
            confidence=conf,
            status="OK",
            ttl_key="threat",
            metadata={
                "reliability": provider.reliability,
                "weight": provider.weight,
                "latency": provider.latency,
                "tags": result.get("tags", []),
                "first_seen": result.get("first_seen"),
                "last_seen": result.get("last_seen"),
                "evidence": result.get("evidence", ""),
                "error_rate": provider.error_rate,
                "data_type": "threat",
                "field": name
            }
        ))
    return evidences

def calculate_provider_confidence(provider: BaseProvider) -> float:
    """Helper to compute provider confidence (Stage 3)."""
    return provider.compute_confidence() if hasattr(provider, 'compute_confidence') else 0.5

# ============================================================
#  HEALTH + CIRCUIT + RATE LIMIT
# ============================================================
class Health:
    def __init__(s, n):
        s.name = n; s.ok = 0; s.fail = 0; s.to = 0; s.rl = 0
        s.lat = 0.0; s.samples = 0
        s.last_ok = None; s.last_fail = None; s.last_ec = None
        s._l = threading.Lock()
    def success(s, ms):
        with s._l:
            s.ok += 1; s.lat += ms; s.samples += 1; s.last_ok = now()
    def failure(s, ec, ms):
        with s._l:
            s.fail += 1; s.lat += ms; s.samples += 1
            s.last_fail = now(); s.last_ec = ec
            if ec == EC2.TIMEOUT: s.to += 1
            if ec == EC.RATE_LIMITED.value: s.rl += 1
    def to_dict(s):
        cb = _cb.get(s.name)
        return {"name": s.name, "ok": s.ok, "fail": s.fail, "timeout": s.to,
                "rate_limited": s.rl,
                "avg_ms": round(s.lat/s.samples, 1) if s.samples else 0.0,
                "last_ok": s.last_ok, "last_fail": s.last_fail,
                "last_error": s.last_ec,
                "circuit": cb.state if cb else "N/A"}

_health = {}
_hl = threading.Lock()

def H(n):
    with _hl:
        if n not in _health: _health[n] = Health(n)
        return _health[n]

class CB:
    def __init__(s, n, ft, rt):
        s.name = n; s.ft = ft; s.rt = rt
        s.state = CS.CLOSED.value; s.fails = 0; s.opened = 0.0
        s._l = threading.Lock()
    def ok(s):
        with s._l:
            if s.state == CS.OPEN.value and time.time() - s.opened > s.rt:
                s.state = CS.HALF_OPEN.value; return True
            return s.state != CS.OPEN.value
    def good(s):
        with s._l: s.fails = 0; s.state = CS.CLOSED.value
    def bad(s):
        with s._l:
            s.fails += 1
            if s.fails >= s.ft or s.state == CS.HALF_OPEN.value:
                s.state = CS.OPEN.value; s.opened = time.time()

_cb = {}
def CBget(n):
    with _hl:
        if n not in _cb:
            _cb[n] = CB(n, PF["circuit"]["fail_threshold"], PF["circuit"]["recovery_timeout"])
        return _cb[n]

class RL:
    def __init__(s, rpm):
        s.rate = rpm; s.iv = 60.0/rpm if rpm else 0
        s.last = 0.0; s._l = threading.Lock()
    def acquire(s):
        if not s.iv: return
        with s._l:
            d = time.monotonic() - s.last
            if d < s.iv: time.sleep(s.iv - d)
            s.last = time.monotonic()

_rl = {}
def RLget(h):
    with _hl:
        if h not in _rl:
            lim = PD.get("rate_limits_per_minute", {})
            rpm = lim.get(h, lim.get("default", 60))
            _rl[h] = RL(rpm) if rpm else None
        return _rl[h]

# ============================================================
#  CACHE
# ============================================================
class Cache:
    def __init__(s, p):
        s.l1 = {}; s.p = p; s._l = threading.Lock()
        s.h1 = s.h2 = s.m = 0
        try:
            c = sqlite3.connect(p)
            c.execute("CREATE TABLE IF NOT EXISTS cache(k TEXT PRIMARY KEY,d TEXT,e REAL)")
            c.commit(); c.close()
        except Exception: pass
    def get(s, k):
        t = time.time()
        with s._l:
            v = s.l1.get(k)
            if v and t < v[0]: s.h1 += 1; return v[1]
            if v: del s.l1[k]
        try:
            c = sqlite3.connect(s.p)
            r = c.execute("SELECT d,e FROM cache WHERE k=?", (k,)).fetchone()
            if r and t < r[1]:
                v = json.loads(r[0])
                with s._l: s.l1[k] = (r[1], v)
                s.h2 += 1; c.close(); return v
            if r:
                c.execute("DELETE FROM cache WHERE k=?", (k,)); c.commit()
            c.close()
        except Exception: pass
        with s._l: s.m += 1
        return None
    def set(s, k, v, ttl):
        e = time.time() + ttl
        with s._l: s.l1[k] = (e, v)
        try:
            c = sqlite3.connect(s.p)
            c.execute("INSERT OR REPLACE INTO cache VALUES(?,?,?)", (k, json.dumps(v), e))
            c.commit(); c.close()
        except Exception: pass
    def stats(s):
        with s._l:
            t = s.h1 + s.h2 + s.m
            return {"hit_rate": round((s.h1 + s.h2) / t * 100, 1) if t else 0.0,
                    "size": len(s.l1)}

CACHE = Cache(PD["cache"]["db_path"]) if PD["cache"]["enabled"] else None

def ttl_for(h):
    t = PD["cache"]["ttl"]
    if any(k in h for k in ("ip-api", "ipinfo", "freegeoip")): return t.get("geo", 7200)
    if any(k in h for k in ("ripe", "whois", "bgpview", "bgp.he.net")): return t.get("asn", 3600)
    if "rdap" in h: return t.get("rdap", 7200)
    if "crt.sh" in h: return t.get("cert", 3600)
    if any(k in h for k in ("abuse", "virustotal", "otx", "urlhaus",
                             "threatfox", "feodo", "sslbl", "greynoise", "cins", "spamhaus")):
        return t.get("threat", 900)
    return 600

# ============================================================
#  HTTP CLIENT
# ============================================================
class HTTP:
    def __init__(s):
        s.s = requests.Session()
        s.s.headers["User-Agent"] = CFG["general"]["user_agent"]
        s.to = (2, 4)
        s.s.mount("https://", requests.adapters.HTTPAdapter(max_retries=0))
        s.s.mount("http://", requests.adapters.HTTPAdapter(max_retries=0))
    def get(s, url, provider=None, **kw):
        host = urlparse(url).netloc
        pn = provider or host
        h = H(pn)
        if CACHE:
            raw = url + "|" + json.dumps(kw.get("params") or {}, sort_keys=True)
            ck = "http:" + hashlib.sha1(raw.encode()).hexdigest()
            c = CACHE.get(ck)
            if c is not None: return c
        else:
            ck = None
        for a in range(PF["retry"]["max_attempts"]):
            cb = CBget(pn)
            if not cb.ok():
                h.failure(EC.TRANSIENT.value, 0); return None
            rl = RLget(host)
            if rl: rl.acquire()
            t0 = time.monotonic()
            try:
                r = s.s.get(url, timeout=s.to, **kw)
                ms = (time.monotonic() - t0) * 1000
                if r.status_code == 200:
                    cb.good()
                    try: d = r.json()
                    except ValueError:
                        h.failure(EC3.INVALID, ms); return None
                    h.success(ms)
                    if CACHE and ck: CACHE.set(ck, d, ttl_for(host))
                    return d
                ec = http_class(r.status_code)
                cb.bad(); h.failure(ec, ms)
                if ec not in _RETRYABLE or a + 1 >= PF["retry"]["max_attempts"]:
                    return None
                time.sleep(backoff(a))
            except Exception as e:
                ms = (time.monotonic() - t0) * 1000
                ec = exc_class(e)
                cb.bad(); h.failure(ec, ms)
                if ec not in _RETRYABLE or a + 1 >= PF["retry"]["max_attempts"]:
                    return None
                time.sleep(backoff(a))
        return None

http = HTTP()
# ============================================================
#  TARGET VALIDATION
# ============================================================
_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f<>\"'`$;&|]")
_RESERVED = [
    ipaddress.ip_network(n) for n in (
        "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4",
        "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32")
]

def validate_target(t, allow_private=False):
    if not isinstance(t, str): raise SecurityError("target must be string")
    s = t.strip()
    if not s or len(s) > 255: raise SecurityError("empty or too long")
    if _FORBIDDEN.search(s): raise SecurityError("forbidden characters")
    if ".." in s or s.startswith("-"): raise SecurityError("unsafe sequence")
    try:
        ip = ipaddress.ip_address(s)
        if ip.is_loopback and not allow_private: raise SecurityError(f"loopback: {ip}")
        if ip.is_private and not allow_private: raise SecurityError(f"private: {ip}")
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise SecurityError(f"non-routable: {ip}")
        for net in _RESERVED:
            if ip.version == net.version and ip in net:
                raise SecurityError(f"reserved: {ip}")
        return str(ip), "ipv6" if ip.version == 6 else "ip"
    except SecurityError: raise
    except ValueError: pass
    try:
        net = ipaddress.ip_network(s, strict=False)
        if net.prefixlen < 24: raise SecurityError("CIDR too broad")
        if net.network_address.is_private and not allow_private:
            raise SecurityError("private CIDR")
        return str(net), "cidr"
    except SecurityError: raise
    except ValueError: pass
    if not re.match(r"^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))+$", s.lower()):
        raise SecurityError("not a valid hostname")
    if len(s) > 253: raise SecurityError("hostname too long")
    if any(len(lb) == 0 or len(lb) > 63 for lb in s.split(".")):
        raise SecurityError("label out of bounds")
    return s.lower(), "domain"

def safe_subprocess(binary, args, timeout=6):
    allowed = {"whois"}
    if binary not in allowed: raise SecurityError(f"binary not allowed: {binary}")
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise SecurityError("args must be list of strings")
    for a in args:
        if _FORBIDDEN.search(a): raise SecurityError(f"unsafe arg: {a!r}")
    bp = shutil.which(binary)
    if not bp: raise SecurityError(f"not found: {binary}")
    try:
        r = subprocess.run([bp, *args], capture_output=True, text=True,
                            timeout=timeout, shell=False)
        return r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        raise SecurityError(f"{binary} timeout")

# ============================================================
#  GEO PROVIDERS
# ============================================================
def norm_geo(raw, prov, target):
    # Stage 2: Evidence via make_evidence (v31) — traceable source, confidence, freshness
    out = []
    country = raw.get("country") or raw.get("country_name") or ""
    cc = raw.get("countryCode") or raw.get("country_code") or ""
    lat, lon = raw.get("lat"), raw.get("lon")
    if (lat is None or lon is None) and isinstance(raw.get("loc"), str):
        p = raw["loc"].split(",")
        if len(p) == 2: lat, lon = p[0], p[1]
    fields = {"country": country, "country_code": cc,
              "region": raw.get("regionName") or raw.get("region_name") or raw.get("region") or "",
              "city": raw.get("city") or "",
              "latitude": fnum(lat), "longitude": fnum(lon),
              "timezone": raw.get("timezone") or "",
              "isp": raw.get("isp") or "",
              "organization": raw.get("org") or "",
              "asn": raw.get("as") or raw.get("asn") or ""}
    for f, v in fields.items():
        if v not in (None, ""):
            # Stage 2: create Evidence with source, confidence, freshness
            rel = CFG.get("source_reliability", {}).get(prov, {}).get("reliability", 0.5)
            ev = make_evidence(
                source=prov,
                value=v,
                normalized_value=str(v).strip() if isinstance(v, str) else v,
                confidence=rel,
                status="OK",
                ttl_key="passive_dns",  # geo approx uses passive_dns TTL
                metadata={"field": f, "data_type": "geo", "target": target, "raw_value": v, "provider": prov}
            )
            out.append(ev)
    return out

def geo_ipapi(ip):
    d = http.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,"
                 "city,lat,lon,timezone,isp,org,as", provider="ip_api")
    return d if d and d.get("status") == "success" else None

def geo_ipinfo(ip):
    k = CFG["api_keys"].get("ipinfo", "")
    url = f"https://ipinfo.io/{ip}/json" + (f"?token={k}" if k else "")
    d = http.get(url, provider="ipinfo")
    return d if d and "country" in d else None

def geo_freegeoip(ip):
    d = http.get(f"https://freegeoip.app/json/{ip}", provider="freegeoip")
    return d if d and "country_code" in d else None

def geo_maxmind(ip):
    if not GEOIP2: return None
    p = CFG["sources"]["geo"].get("maxmind_db_path", "")
    if not p or not os.path.exists(p): return None
    try:
        with geoip2.database.Reader(p) as r:
            c = r.city(ip)
            return {"country": c.country.name or "", "country_code": c.country.iso_code or "",
                    "region": c.subdivisions.most_specific.iso_code or "",
                    "regionName": c.subdivisions.most_specific.name or "",
                    "city": c.city.name or "", "lat": c.location.latitude,
                    "lon": c.location.longitude, "timezone": c.location.time_zone or "",
                    "as": c.traits.autonomous_system_organization or ""}
    except Exception as e:
        log.warning(f"maxmind: {e}"); return None

GEO = {"ip_api": geo_ipapi, "ipinfo": geo_ipinfo,
       "freegeoip": geo_freegeoip, "maxmind_local": geo_maxmind}

def collect_geo(ip):
    evs, att, resp = [], 0, 0
    for name in CFG["sources"]["geo"]["enabled"]:
        fn = GEO.get(name)
        if not fn: continue
        att += 1
        try:
            r = fn(ip)
            if r is not None:
                resp += 1
                evs.extend(norm_geo(r, name, ip))
        except Exception as e:
            log.warning(f"geo {name}: {e}")
            H(name).failure(exc_class(e), 0)
    return evs, module_status(att, resp)

# ============================================================
#  ASN PROVIDERS — v21.2 (RIPE fixed + BGPView + bgp.he.net + WHOIS)
# ============================================================
def asn_ripe(ip):
    """RIPE Stat — correct parsing of data.asns[0]."""
    d = http.get(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}",
                 provider="ripe")
    if not d or d.get("status") != "ok":
        return None
    x = d.get("data", {}) or {}
    asns = x.get("asns", []) or []
    if not asns:
        return None
    a = asns[0]
    asn_num = a.get("asn")
    if not asn_num:
        return None
    return {
        "asn": f"AS{asn_num}",
        "organization": a.get("holder", "") or "",
        "prefix": x.get("resource", "") or "",
        "rir": x.get("rir", "") or "",
    }

def asn_bgpview(ip):
    """BGPView — v21.6: pick origin ASN (largest prefix length = most specific)."""
    d = http.get(f"https://api.bgpview.io/ip/{ip}", provider="bgpview")
    if not d or d.get("status") != "ok":
        return None
    data = d.get("data", {}) or {}
    prefixes = data.get("prefixes", []) or []
    if not prefixes: return None
    def _plen(p):
        try: return int(str(p.get("prefix","")).split("/")[-1])
        except Exception: return 0
    # Most specific prefix = origin ASN (higher /XX = more specific)
    prefixes_sorted = sorted(prefixes, key=_plen, reverse=True)
    p0 = prefixes_sorted[0]
    asn_info = p0.get("asn", {}) or {}
    if not asn_info.get("asn"): return None
    rir_info = asn_info.get("rir_allocation") or {}
    return {
        "asn": f"AS{asn_info['asn']}",
        "organization": asn_info.get("name", "") or asn_info.get("description", ""),
        "prefix": p0.get("prefix", ""),
        "rir": rir_info.get("rir_name", "") if isinstance(rir_info, dict) else "",
        "country": asn_info.get("country_code", ""),
    }

def asn_bgp_he(ip):
    """bgp.he.net — v21.6: skip entirely (unreliable, adds upstream ASNs).
    Kept as stub for compatibility; returns None always."""
    # bgp.he.net returns upstream transit ASNs (Level3 AS3356, Cogent etc)
    # which pollute results. RIPE + BGPView cover the same data cleanly.
    return None

def asn_whois(ip):
    """WHOIS with improved parsing (NetRange, CIDR, dates)."""
    try:
        t0 = time.monotonic()
        out, _ = safe_subprocess("whois", [ip], timeout=PN["subprocess_timeout"])
        ms = (time.monotonic() - t0) * 1000
        out = out or ""
        m = re.search(r"\bAS(\d+)", out)
        if not m:
            H("whois").failure(EC.PERMANENT.value, ms); return None
        H("whois").success(ms)

        def grab(*patterns):
            for pat in patterns:
                r = re.search(pat, out, re.I)
                if r:
                    try: return r.group(2).strip()
                    except Exception:
                        try: return r.group(1).strip()
                        except Exception: return ""
            return ""

        org = grab(r"(OrgName|org-name|organisation):\s*([^\n]+)",
                   r"(netname):\s*([^\n]+)")
        country = grab(r"(Country|country):\s*([^\n]+)")
        abuse = grab(r"(abuse-mailbox|OrgAbuseEmail):\s*([^\n]+)")
        cidr = grab(r"(CIDR):\s*([^\n]+)")
        netrange = grab(r"(NetRange):\s*([^\n]+)")
        created = grab(r"(Created|RegDate|created):\s*([^\n]+)")
        updated = grab(r"(Updated|Updated Date|last-modified):\s*([^\n]+)")
        return {
            "asn": f"AS{m.group(1)}",
            "organization": org,
            "country": country,
            "abuse_contact": abuse,
            "prefix": cidr or netrange,
            "rir": "",
            "created": created,
            "updated": updated,
        }
    except Exception as e:
        H("whois").failure(EC2.TIMEOUT if isinstance(e, SecurityError) else EC3.INTERNAL, 0)
        return None

ASN = {"ripe": asn_ripe, "bgpview": asn_bgpview,
       "bgp_he": asn_bgp_he, "whois": asn_whois}

def collect_asn(ip):
    """
    ASN/WHOIS collector — Stage 2 refactored to Evidence (v31).
    Wraps each field via make_evidence for traceability.
    """
    evs, att, resp = [], 0, 0
    for name in CFG["sources"]["network"]["asn_sources"]:
        fn = ASN.get(name)
        if not fn: continue
        att += 1
        try:
            r = fn(ip)
            if r is not None:
                resp += 1
                for f in ("asn", "organization", "prefix", "rir", "country",
                          "abuse_contact", "created", "updated"):
                    v = r.get(f)
                    if f == "organization" and v: v = _clean_org(v)
                    if v:
                        # Stage 2: Evidence
                        ev = make_evidence(
                            source=name,
                            value=v,
                            normalized_value=str(v).strip(),
                            confidence=CFG.get("evidence", {}).get("confidence_defaults", {}).get("whois", 0.85) if name == "whois" else 0.9,
                            status="OK",
                            ttl_key="whois",
                            metadata={"field": f, "data_type": "asn", "target": ip, "raw_value": v, "provider": name}
                        )
                        evs.append(ev)
        except Exception as e:
            log.warning(f"asn {name}: {e}")
            H(name).failure(exc_class(e), 0)
    if not att: st = MS.SKIPPED.value
    elif resp == 0: st = MS.FAILED.value
    elif len(evs) > 0: st = MS.SUCCESS.value
    else: st = MS.PARTIAL.value
    return evs, st

def collect_whois(target):
    """
    WHOIS collector — Stage 2 Evidence wrapper (v31).
    Returns List[Evidence] for each WHOIS field.
    """
    evidences = []
    data = whois_enhanced(target)
    if not data:
        evidences.append(make_evidence(source="whois", value=None, normalized_value=None, confidence=0.0, status="FAILED", ttl_key="whois", metadata={"reason": "whois lookup failed", "field": "whois"}))
        return evidences
    for key in ("org", "organization", "netrange", "cidr", "country", "name", "handle"):
        if data.get(key):
            evidences.append(make_evidence(source="whois", value=data[key], normalized_value=str(data[key]).strip(), confidence=0.9, status="OK", ttl_key="whois", metadata={"field": key, "data_type": "whois", "target": target}))
    # RegDate vs Updated — each as its own Evidence (B3)
    if data.get("created"):
        evidences.append(make_evidence(source="whois", value=data["created"], normalized_value=data["created"], confidence=0.85, status="OK", ttl_key="whois", metadata={"field": "reg_date", "data_type": "whois", "target": target}))
    if data.get("updated"):
        evidences.append(make_evidence(source="whois", value=data["updated"], normalized_value=data["updated"], confidence=0.85, status="OK", ttl_key="whois", metadata={"field": "updated_date", "data_type": "whois", "target": target}))
    # Also include parsed version via whois_parse if available
    try:
        parsed = whois_parse(data)
        for k, v in parsed.items():
            if k in ("reg_date", "updated_date") and v and v not in [e.value for e in evidences]:
                evidences.append(make_evidence(source="whois", value=v, normalized_value=str(v).strip(), confidence=0.8, status="OK", ttl_key="whois", metadata={"field": k, "data_type": "whois", "target": target}))
    except Exception:
        pass
    return evidences

# ============================================================
#  RDAP
# ============================================================
def collect_rdap(ip):
    # Stage 2: Evidence via make_evidence (v31)
    d = None
    for base in ("https://rdap.arin.net/registry/ip/",
                 "https://rdap.db.ripe.net/ip/",
                 "https://rdap.apnic.net/ip/"):
        d = http.get(f"{base}{ip}", provider="rdap")
        if d and (d.get("handle") or d.get("startAddress")):
            break
        d = None
    if not d:
        # Stage 2: FAILED evidence
        ev_fail = make_evidence(source="rdap", value=None, normalized_value=None, confidence=0.0, status="FAILED", ttl_key="whois", metadata={"field": "rdap", "data_type": "rdap", "target": ip, "reason": "no data"})
        return [ev_fail], MS.FAILED.value
    evs = []
    fields = {"handle": d.get("handle", ""), "name": d.get("name", ""),
              "country_rdap": d.get("country", ""), "start_addr": d.get("startAddress", ""),
              "end_addr": d.get("endAddress", ""), "type": d.get("type", "")}
    for f, v in fields.items():
        if v:
            ev = make_evidence(source="rdap", value=v, normalized_value=str(v).strip(), confidence=0.9, status="OK", ttl_key="whois", metadata={"field": f, "data_type": "rdap", "target": ip, "raw_value": v})
            evs.append(ev)
    for e in d.get("events", []):
        a, dt = e.get("eventAction", ""), e.get("eventDate", "")
        if a and dt:
            ev = make_evidence(source="rdap", value=dt, normalized_value=str(dt).strip(), confidence=0.85, status="OK", ttl_key="whois", metadata={"field": f"event_{a}", "data_type": "rdap", "target": ip, "raw_value": dt})
            evs.append(ev)
    for ent in d.get("entities", []):
        if "abuse" in ent.get("roles", []):
            vc = ent.get("vcardArray", [])
            if len(vc) > 1:
                for it in vc[1]:
                    if it and it[0] == "email":
                        ev = make_evidence(source="rdap", value=it[3], normalized_value=str(it[3]).strip().lower(), confidence=0.9, status="OK", ttl_key="whois", metadata={"field": "abuse_email", "data_type": "rdap", "target": ip, "raw_value": it[3]})
                        evs.append(ev)
    return evs, MS.SUCCESS.value if evs else MS.PARTIAL.value

# ============================================================
#  DNS
# ============================================================
def dns_val(rt, ans):
    if rt == "MX":
        try: return f"{ans.preference} {str(ans.exchange).rstrip('.')}"
        except: return str(ans.exchange).rstrip(".")
    if rt in ("NS", "CNAME"):
        try: return str(ans.target).rstrip(".")
        except: return str(ans).rstrip(".")
    if rt == "CAA":
        try:
            tag = ans.tag.decode('utf-8', errors='replace') if isinstance(ans.tag, bytes) else str(ans.tag)
            val = ans.value.decode('utf-8', errors='replace') if isinstance(ans.value, bytes) else str(ans.value)
            return f"{ans.flags} {tag} {val}"
        except: return str(ans)
    if rt == "TXT":
        try: return b"".join(ans.strings).decode("utf-8", errors="replace")
        except: return str(ans)
    return str(ans)

def format_caa(caa_records):
    """
    Convert CAA records from bytes to human-readable strings (B1 fix).
    Input: list of tuples like (flags, tag, value)
    Output: list of dicts {'flags': int, 'tag': str, 'value': str}
    """
    formatted = []
    for flags, tag, value in caa_records:
        if isinstance(tag, bytes):
            tag = tag.decode('utf-8', errors='replace')
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='replace')
        formatted.append({'flags': flags, 'tag': tag, 'value': value})
    return formatted

def collect_dns(ip, domain=None):
    """
    DNS collector — Stage 2 refactored to return Evidence objects (v31).
    Every record is wrapped via make_evidence with source, timestamp, confidence, freshness.
    Returns List[Evidence] for traceability while remaining compatible with legacy Ev pipeline.
    """
    evs, att, resp = [], 0, 0
    rtypes = tuple(PG["dns"].get("record_types", ["A","AAAA","PTR","CNAME","MX","NS","TXT","CAA"]))
    try: rev = dns.reversename.from_address(ip)
    except Exception: rev = None
    for ns in CFG["sources"]["dns"]["nameservers"]:
        att += 1; found = False
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [ns]; r.timeout = 2; r.lifetime = 2
            ptr_hosts = []
            if "PTR" in rtypes and rev:
                try:
                    for a in r.resolve(rev, "PTR"):
                        v = str(a.target).rstrip(".")
                        ptr_hosts.append(v)
                        # Stage 2: Evidence via make_evidence (with dict raw_value for network_intel)
                        ev = make_evidence(
                            source=f"dns:{ns}",
                            value=v,
                            normalized_value=v.strip().lower(),
                            confidence=CFG.get("evidence", {}).get("confidence_defaults", {}).get("dns", 0.95),
                            status="OK",
                            ttl_key="dns",
                            metadata={"record_type": "PTR", "ns": ns, "direction": "reverse",
                                      "data_type": "dns", "field": "PTR", "target": ip, "raw_value": {"ns": ns, "direction": "reverse", "value": v}}
                        )
                        evs.append(ev)
                        found = True
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers):
                    pass
            queries = []
            if domain: queries.append(domain)
            if PG["dns"].get("forward_lookup_from_ptr"):
                for h in ptr_hosts:
                    if h not in queries: queries.append(h)
            for name in queries:
                direction = "forward" if (domain and name == domain) else "forward_from_ptr"
                for rt in rtypes:
                    if rt == "PTR": continue
                    try:
                        for ans in r.resolve(name, rt):
                            v = dns_val(rt, ans)
                            ev = make_evidence(
                                source=f"dns:{ns}",
                                value=v,
                                normalized_value=str(v).strip().lower() if isinstance(v, str) else str(v).lower(),
                                confidence=CFG.get("evidence", {}).get("confidence_defaults", {}).get("dns", 0.95),
                                status="OK",
                                ttl_key="dns",
                                metadata={"record_type": rt, "ns": ns, "name": name, "direction": direction,
                                          "data_type": "dns", "field": rt, "target": ip, "raw_value": {"ns": ns, "name": name, "direction": direction, "value": v}}
                            )
                            evs.append(ev)
                            found = True
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                            dns.resolver.NoNameservers, dns.exception.Timeout):
                        continue
                    except Exception:
                        continue
            if found:
                resp += 1; H(f"dns:{ns}").success(0)
            else:
                H(f"dns:{ns}").failure(EC.PERMANENT.value, 0)
        except dns.exception.Timeout:
            H(f"dns:{ns}").failure(EC2.TIMEOUT, 0)
        except Exception as e:
            H(f"dns:{ns}").failure(exc_class(e), 0)
    return evs, module_status(att, resp)

# ============================================================
#  CERTIFICATE INTELLIGENCE
# ============================================================
@dataclass
class CertRec:
    id: str
    fp: str = ""
    crtsh_id: str = ""
    serial: str = ""
    issuer: str = ""
    subject: str = ""
    valid_from: str = ""
    valid_to: str = ""
    sans: List[str] = field(default_factory=list)
    wildcards: List[str] = field(default_factory=list)
    key_type: str = ""
    key_bits: Optional[int] = None
    sig_alg: str = ""
    status: str = "UNKNOWN"
    first_seen: str = ""
    last_seen: str = ""
    sources: List[str] = field(default_factory=list)
    ev_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    is_expired: bool = False
    is_near: bool = False
    days_left: Optional[int] = None
    weak: List[str] = field(default_factory=list)

def norm_san(s):
    if not s: return None
    s = s.strip().rstrip(".").lower()
    if not s: return None
    wc = ""
    if s.startswith("*."):
        wc = "*."; s = s[2:]
    try: s = s.encode("idna").decode("ascii")
    except: pass
    if not re.match(r"^[a-z0-9._-]+\.[a-z]{2,}$", s): return None
    return wc + s

def parse_der(der):
    if not CRYPTO or not der: return None
    try:
        c = x509.load_der_x509_certificate(der)
        pub = c.public_key()
        kt, kb = "unknown", None
        if isinstance(pub, _rsa.RSAPublicKey): kt, kb = "RSA", pub.key_size
        elif isinstance(pub, _ec.EllipticCurvePublicKey): kt, kb = "ECDSA", pub.curve.key_size
        elif isinstance(pub, _dsa.DSAPublicKey): kt, kb = "DSA", pub.key_size
        elif isinstance(pub, _ed.Ed25519PublicKey): kt, kb = "Ed25519", 256
        elif isinstance(pub, _ed4.Ed448PublicKey): kt, kb = "Ed448", 456
        sans = []
        try:
            ext = c.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = list(ext.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass
        sig = ""
        try:
            if c.signature_hash_algorithm: sig = c.signature_hash_algorithm.name
        except Exception: pass
        return {"fp": c.fingerprint(_ch.SHA256()).hex(),
                "subject": c.subject.rfc4514_string(),
                "issuer": c.issuer.rfc4514_string(),
                "serial": format(c.serial_number, "x"),
                "valid_from": c.not_valid_before_utc.isoformat(),
                "valid_to": c.not_valid_after_utc.isoformat(),
                "sans": sans, "key_type": kt, "key_bits": kb, "sig_alg": sig}
    except Exception as e:
        log.debug(f"der: {e}"); return None

def fetch_cert(domain, port, timeout=5.0):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ss:
                return ss.getpeercert(binary_form=True), ss.getpeercert(), None
    except Exception as e:
        return None, None, e

def cert_expiry_check(rec):
    if not rec.valid_to: return
    try:
        v = rec.valid_to
        try: dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except: dt = datetime.strptime(v, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        d = (dt - datetime.now(timezone.utc)).total_seconds()
        rec.days_left = int(d // 86400)
        rec.is_expired = d < 0
        rec.is_near = 0 <= d < PH["near_expiry_days"] * 86400
    except Exception:
        pass

def cert_weak_check(rec):
    w = []
    cfg = PH["weak_algorithms"]
    if rec.sig_alg and any(s in rec.sig_alg.lower() for s in cfg["signature"]):
        w.append(f"signature:{rec.sig_alg}")
    if rec.key_type == "RSA" and rec.key_bits and rec.key_bits < cfg["min_rsa_bits"]:
        w.append(f"rsa:{rec.key_bits}")
    if rec.key_type == "ECDSA" and rec.key_bits and rec.key_bits < cfg["min_ecdsa_bits"]:
        w.append(f"ecdsa:{rec.key_bits}")
    return w

def collect_certs(domain):
    ci = {"records": {}}
    evs = []; att, resp = 0, 0
    now_ts = now()
    for port in PH["ports"]:
        att += 1
        der, peer, err = fetch_cert(domain, port)
        if not der and not peer:
            H(f"tls:{port}").failure(exc_class(err) if err else "UNREACHABLE", 0)
            continue
        parsed = parse_der(der) if der else None
        if not parsed:
            H(f"tls:{port}").failure(EC3.INVALID, 0); continue
        fp = (parsed.get("fp") or "").lower()
        rec = CertRec(id=fp or f"tls:{domain}:{port}", fp=fp,
                      serial=parsed.get("serial", ""),
                      issuer=parsed.get("issuer", ""),
                      subject=parsed.get("subject", ""),
                      valid_from=parsed.get("valid_from", ""),
                      valid_to=parsed.get("valid_to", ""),
                      key_type=parsed.get("key_type", ""),
                      key_bits=parsed.get("key_bits"),
                      sig_alg=parsed.get("sig_alg", ""),
                      status="CURRENT", first_seen=now_ts, last_seen=now_ts,
                      sources=[f"tls:{port}"], confidence=95.0)
        max_san = PH["san_max_per_cert"]
        for s in parsed.get("sans", [])[:max_san]:
            n = norm_san(s)
            if not n: continue
            if n.startswith("*."): rec.wildcards.append(n)
            rec.sans.append(n)
        cert_expiry_check(rec)
        rec.weak = cert_weak_check(rec)

        def add_ev(f, v):
            # Stage 2: Evidence via make_evidence (v31)
            ev = make_evidence(
                source="ct",
                value=v,
                normalized_value=str(v).lower() if isinstance(v, str) else v,
                confidence=0.9,
                status="OK",
                ttl_key="ct",
                metadata={"field": f, "data_type": "cert", "target": domain, "fingerprint": fp, "raw_value": v, "port": port}
            )
            evs.append(ev); rec.ev_ids.append(ev.metadata.get("id", fp or f))

        if fp: add_ev("current_fingerprint", fp)
        add_ev("current_status", "CURRENT")
        for f in ("subject", "issuer", "valid_from", "valid_to", "serial",
                  "key_type", "sig_alg"):
            v = getattr(rec, f) if hasattr(rec, f) else parsed.get(f)
            if v: add_ev(f, v)
        if rec.key_bits is not None: add_ev("key_bits", rec.key_bits)
        for san in rec.sans: add_ev("san", san)
        for w in rec.wildcards: add_ev("wildcard", w)
        if rec.is_expired: add_ev("expired", True)
        if rec.is_near: add_ev("near_expiry", True)
        for w in rec.weak: add_ev("weak_algorithm", w)
        ci["records"][rec.id] = rec
        H(f"tls:{port}").success(0); resp += 1
        break

    att += 1
    max_hist = PH["max_historical_certs"]
    data = http.get(f"https://crt.sh/?q={domain}&output=json", provider="crtsh")
    if isinstance(data, list):
        resp += 1
        seen = set()
        for entry in data[:max_hist]:
            cid = str(entry.get("id", ""))
            if not cid or cid in seen: continue
            seen.add(cid)
            rec = CertRec(id=f"crtsh:{cid}", crtsh_id=cid,
                          issuer=entry.get("issuer_name", ""),
                          subject=entry.get("common_name", "") or entry.get("name_value", ""),
                          valid_from=entry.get("not_before", ""),
                          valid_to=entry.get("not_after", ""),
                          serial=entry.get("serial_number", ""),
                          status="HISTORICAL",
                          first_seen=entry.get("entry_timestamp", now_ts),
                          last_seen=entry.get("entry_timestamp", now_ts),
                          sources=["crtsh"], confidence=70.0)
            for s in (entry.get("name_value", "") or "").split("\n"):
                n = norm_san(s)
                if not n: continue
                if n.startswith("*."): rec.wildcards.append(n)
                rec.sans.append(n)
            # Stage 2: Evidence for historical cert
            e = make_evidence(source="crtsh", value=cid, normalized_value=str(cid).lower(), confidence=0.85, status="OK", ttl_key="ct", metadata={"field": "historical_cert_id", "data_type": "cert", "target": domain, "crtsh_id": cid, "raw_value": cid})
            evs.append(e); rec.ev_ids.append(e.metadata.get("id", cid))
            for san in rec.sans:
                es = make_evidence(source="crtsh", value=san, normalized_value=str(san).lower(), confidence=0.8, status="OK", ttl_key="ct", metadata={"field": "historical_san", "data_type": "cert", "target": domain, "crtsh_id": cid, "raw_value": san})
                evs.append(es); rec.ev_ids.append(es.metadata.get("id", san))
            ci["records"][rec.id] = rec
        H("crtsh").success(0)
    else:
        H("crtsh").failure(EC3.INVALID, 0)

    has_cur = any(r.status == "CURRENT" for r in ci["records"].values())
    has_hist = any(r.status == "HISTORICAL" for r in ci["records"].values())
    if has_cur: st = MS.SUCCESS.value
    elif has_hist: st = MS.PARTIAL.value
    else: st = MS.FAILED.value
    return evs, st, ci

def cert_summary(ci):
    recs = list(ci["records"].values())
    by_status = {"CURRENT": 0, "HISTORICAL": 0, "UNREACHABLE": 0, "UNKNOWN": 0}
    expired = near = weak = 0
    wildcards = set(); all_sans = set()
    for r in recs:
        by_status[r.status] = by_status.get(r.status, 0) + 1
        if r.is_expired: expired += 1
        if r.is_near: near += 1
        if r.weak: weak += 1
        wildcards.update(r.wildcards); all_sans.update(r.sans)
    timeline = sorted([
        {"identity_key": r.id, "fingerprint_sha256": r.fp, "status": r.status,
         "issuer": r.issuer, "subject": r.subject, "valid_from": r.valid_from,
         "valid_to": r.valid_to, "san_count": len(r.sans), "sans": r.sans[:20],
         "wildcards": r.wildcards, "fingerprint": r.fp, "sources": r.sources,
         "key_type": r.key_type, "sig_alg": r.sig_alg}
        for r in recs], key=lambda x: x.get("valid_from") or "")
    return {"total": len(recs), "by_status": by_status, "expired": expired,
            "near_expiry": near, "weak": weak,
            "wildcards": sorted(wildcards), "sans": sorted(all_sans),
            "timeline": timeline}

def ct_parse(ct_entries):
    """
    Parse CT log entries into structured certificate info (B6 fix).
    Input: list of certificate dicts from CT provider or CertRec records.
    Output: list of dicts with fields: 'san', 'issuer', 'validity', 'fingerprint', 'wildcard'
    """
    parsed = []
    for entry in ct_entries or []:
        # Handle both dict entries and CertRec objects
        if hasattr(entry, 'sans'):
            san_list = getattr(entry, 'sans', []) or []
            issuer = getattr(entry, 'issuer', '') or ""
            fp = getattr(entry, 'fp', '') or getattr(entry, 'fingerprint', '') or ""
            vf = getattr(entry, 'valid_from', '') or ""
            vt = getattr(entry, 'valid_to', '') or ""
        else:
            san_list = entry.get('sans') or entry.get('san') or entry.get('name_value', '').split("\n") if isinstance(entry, dict) else []
            if isinstance(san_list, str):
                san_list = [san_list]
            issuer = entry.get('issuer', '') or entry.get('issuer_name', '') if isinstance(entry, dict) else ""
            fp = entry.get('fingerprint', '') or entry.get('fp', '') if isinstance(entry, dict) else ""
            vf = entry.get('not_before', '') or entry.get('valid_from', '') if isinstance(entry, dict) else ""
            vt = entry.get('not_after', '') or entry.get('valid_to', '') if isinstance(entry, dict) else ""
        cert = {
            'san': san_list,
            'issuer': issuer,
            'validity': {'not_before': vf, 'not_after': vt},
            'fingerprint': fp,
            'wildcard': any('*' in str(s) for s in san_list)
        }
        parsed.append(cert)
    return parsed
# ============================================================
#  THREAT INTEL PROVIDERS
# ============================================================
@dataclass
class Obs:
    provider: str
    status: str
    score: Optional[float] = None
    confidence: float = 0.0
    categories: List[str] = field(default_factory=list)
    reports: int = 0
    malware: bool = False
    phishing: bool = False
    botnet: bool = False
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    timestamp: str = ""
    error: Optional[str] = None
    weight: float = 1.0
    reliability: float = 0.5
    def to_dict(s): return asdict(s)

def resolve_key(env, cfg):
    if env:
        v = os.environ.get(env)
        if v and v.strip(): return v.strip()
    if cfg:
        v = CFG.get("api_keys", {}).get(cfg, "")
        if v and str(v).strip(): return str(v).strip()
    return None

class Provider:
    name = ""
    env_var = ""
    cfg_key = ""
    def __init__(s):
        c = PI["providers"].get(s.name, {})
        s.enabled = bool(c.get("enabled", True))
        s.weight = float(c.get("weight", 1.0))
        s.reliability = float(c.get("reliability", 0.5))
        s.env_var = c.get("env_var", s.env_var)
        s.cfg_key = c.get("config_key", s.cfg_key)
    def configured(s):
        return bool(resolve_key(s.env_var, s.cfg_key)) or not s.env_var
    def query(s, ip): raise NotImplementedError

# ---------------- AbuseIPDB ----------------
class AbuseIPDB(Provider):
    name = "abuseipdb"; env_var = "ABUSEIPDB_API_KEY"; cfg_key = "abuseipdb"
    def __init__(s):
        super().__init__()
        s.weight = float(PI["providers"].get(s.name, {}).get("weight", 1.0))
        s.reliability = float(PI["providers"].get(s.name, {}).get("reliability", 0.85))
    def query(s, ip):
        o = Obs(provider=s.name, status=TS.NO_DATA.value, timestamp=now(),
                weight=s.weight, reliability=s.reliability)
        k = resolve_key(s.env_var, s.cfg_key)
        if not k:
            o.status = TS.NOT_CONFIGURED.value; return o
        try:
            r = http.s.get("https://api.abuseipdb.com/api/v2/check",
                           headers={"Key": k, "Accept": "application/json"},
                           params={"ipAddress": ip, "maxAgeInDays": 90},
                           timeout=http.to)
        except Exception as e:
            o.status = TS2.PROVIDER_ERROR; o.error = str(e); return o
        if r.status_code == 429: o.status = TS2.RATE_LIMITED; return o
        if r.status_code != 200:
            o.status = TS2.PROVIDER_ERROR; o.error = f"HTTP {r.status_code}"; return o
        try: d = (r.json() or {}).get("data", {})
        except Exception: o.status = TS2.PROVIDER_ERROR; return o
        sc = int(d.get("abuseConfidenceScore", 0) or 0)
        rp = int(d.get("totalReports", 0) or 0)
        o.score = float(sc); o.reports = rp
        o.last_seen = d.get("lastReportedAt"); o.first_seen = d.get("firstReportedAt")
        if rp == 0 and sc == 0:
            o.status = TS.NO_THREAT.value; o.confidence = 70.0; return o
        o.categories = [f"abuse_{'high' if sc>=75 else 'moderate' if sc>=25 else 'low'}"]
        if rp > 0: o.categories.append("abuse_reports")
        o.status = TS2.POSITIVE; o.confidence = min(100, 60 + sc * 0.4)
        return o

# ---------------- VirusTotal ----------------
class VirusTotal(Provider):
    name = "virustotal"; env_var = "VIRUSTOTAL_API_KEY"; cfg_key = "virustotal"
    def __init__(s):
        super().__init__()
        s.weight = float(PI["providers"].get(s.name, {}).get("weight", 1.0))
        s.reliability = float(PI["providers"].get(s.name, {}).get("reliability", 0.90))
    def query(s, ip):
        o = Obs(provider=s.name, status=TS.NO_DATA.value, timestamp=now(),
                weight=s.weight, reliability=s.reliability)
        k = resolve_key(s.env_var, s.cfg_key)
        if not k: o.status = TS.NOT_CONFIGURED.value; return o
        try:
            r = http.s.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                           headers={"x-apikey": k}, timeout=http.to)
        except Exception as e:
            o.status = TS2.PROVIDER_ERROR; o.error = str(e); return o
        if r.status_code == 429: o.status = TS2.RATE_LIMITED; return o
        if r.status_code == 404: o.status = TS.NO_DATA.value; return o
        if r.status_code != 200: o.status = TS2.PROVIDER_ERROR; return o
        try:
            attrs = (r.json().get("data", {}) or {}).get("attributes", {}) or {}
        except Exception:
            o.status = TS2.PROVIDER_ERROR; return o
        st = attrs.get("last_analysis_stats", {}) or {}
        mal = int(st.get("malicious", 0) or 0)
        sus = int(st.get("suspicious", 0) or 0)
        o.reports = mal + sus
        tot = sum(int(v or 0) for v in st.values())
        if not tot: o.status = TS.NO_DATA.value; return o
        o.score = round((mal + 0.5 * sus) / tot * 100, 1)
        cats = []
        if mal: cats.append(f"malicious:{mal}")
        if sus: cats.append(f"suspicious:{sus}")
        for cat in (attrs.get("categories") or {}).values():
            if cat and cat not in cats: cats.append(str(cat))
        j = " ".join(cats).lower()
        o.phishing = "phish" in j
        o.malware = "malware" in j or "trojan" in j
        o.botnet = "botnet" in j or "c2" in j
        o.categories = cats
        if mal or sus:
            o.status = TS2.POSITIVE
            o.confidence = min(100, 50 + mal * 5 + sus * 2)
        else:
            o.status = TS.NO_THREAT.value; o.confidence = 75.0
        return o

# ---------------- AlienVault OTX ----------------
class AlienVault(Provider):
    name = "alienvault"; env_var = "ALIENVAULT_API_KEY"; cfg_key = "alienvault"
    def __init__(s):
        super().__init__()
        s.weight = float(PI["providers"].get(s.name, {}).get("weight", 0.7))
        s.reliability = float(PI["providers"].get(s.name, {}).get("reliability", 0.70))
    def query(s, ip):
        o = Obs(provider=s.name, status=TS.NO_DATA.value, timestamp=now(),
                weight=s.weight, reliability=s.reliability)
        k = resolve_key(s.env_var, s.cfg_key)
        hdrs = {"X-OTX-API-KEY": k} if k else {}
        try:
            r = http.s.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                           headers=hdrs, timeout=http.to)
        except Exception as e:
            o.status = TS2.PROVIDER_ERROR; o.error = str(e); return o
        if r.status_code == 429: o.status = TS2.RATE_LIMITED; return o
        if r.status_code != 200: o.status = TS2.PROVIDER_ERROR; return o
        try: d = r.json() or {}
        except Exception: o.status = TS2.PROVIDER_ERROR; return o

        pl = d.get("pulse_info", {}) or {}
        pc = int(pl.get("count", 0) or 0)
        pulses = pl.get("pulses", []) or []

        # v21.5 FIX: only count RECENT pulses with THREAT tags
        THREAT_KEYWORDS = ("malware", "phish", "ransom", "botnet", "c2",
                           "apt", "trojan", "rat", "exploit", "crypto",
                           "ddos", "scanner", "backdoor", "spam")
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=180)
        recent_threats = 0
        cats = set()
        for p in pulses:
            # Age check
            age_ok = False
            for key in ("modified", "created"):
                v = p.get(key)
                if v:
                    try:
                        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
                        if dt > cutoff:
                            age_ok = True; break
                    except Exception: pass
            p_tags = [str(t).lower() for t in (p.get("tags") or [])]
            threat_tags = [t for t in p_tags
                           if any(k in t for k in THREAT_KEYWORDS)]
            if age_ok and threat_tags:
                recent_threats += 1
                cats.update(threat_tags)
                for f in (p.get("malware_families") or []):
                    if isinstance(f, dict) and f.get("display_name"):
                        cats.add(str(f["display_name"]).lower())

        o.reports = recent_threats
        o.categories = sorted(cats)[:20]
        j = " ".join(cats)
        o.phishing = "phish" in j
        o.malware = "malware" in j or "ransom" in j or "trojan" in j
        o.botnet = "botnet" in j or "c2" in j

        # No recent threat pulses → NO_THREAT (even if older pulses exist)
        if recent_threats == 0:
            o.status = TS.NO_THREAT.value
            o.confidence = 65.0 if pc > 0 else 60.0
            # Note historical mentions in categories (informational)
            if pc > 0 and not cats:
                o.categories = [f"historical_mentions:{pc}"]
            return o

        # Logarithmic scoring (avoids false 100)
        import math
        o.score = round(min(100, 30 + math.log2(recent_threats + 1) * 12), 1)
        o.status = TS2.POSITIVE
        o.confidence = min(100, 60 + recent_threats * 4)
        return o

# ---------------- URLhaus ----------------
class URLhaus(Provider):
    name = "urlhaus"; env_var = ""; cfg_key = ""
    def __init__(s):
        super().__init__()
        s.weight = float(PI["providers"].get(s.name, {}).get("weight", 0.8))
        s.reliability = float(PI["providers"].get(s.name, {}).get("reliability", 0.75))
    def query(s, ip):
        o = Obs(provider=s.name, status=TS.NO_DATA.value, timestamp=now(),
                weight=s.weight, reliability=s.reliability)
        try:
            r = http.s.post("https://urlhaus-api.abuse.ch/v1/host/",
                            data={"host": ip}, timeout=(3, 8))
        except Exception as e:
            o.status = TS2.PROVIDER_ERROR; o.error = str(e); return o
        if r.status_code == 429: o.status = TS2.RATE_LIMITED; return o
        if r.status_code != 200: o.status = TS2.PROVIDER_ERROR; return o
        try: d = r.json() or {}
        except Exception: o.status = TS2.PROVIDER_ERROR; return o
        urls = d.get("urls") or []
        if d.get("query_status") != "ok" or not urls:
            o.status = TS.NO_THREAT.value; o.confidence = 65.0; return o
        online = sum(1 for u in urls if u.get("url_status") == "online")
        tags = set()
        for u in urls:
            for t in (u.get("tags") or []): tags.add(str(t).lower())
        o.reports = len(urls)
        o.categories = sorted(tags)[:10]
        o.malware = any("malware" in t for t in tags)
        o.score = min(100, 40 + len(urls) * 3 + online * 15)
        o.status = TS2.POSITIVE
        o.confidence = min(100, 65 + len(urls) * 2)
        return o

# ---------------- ThreatFox ----------------
class ThreatFox(Provider):
    name = "threatfox"; env_var = ""; cfg_key = ""
    def __init__(s):
        super().__init__()
        s.weight = float(PI["providers"].get(s.name, {}).get("weight", 1.0))
        s.reliability = float(PI["providers"].get(s.name, {}).get("reliability", 0.85))
    def query(s, ip):
        o = Obs(provider=s.name, status=TS.NO_DATA.value, timestamp=now(),
                weight=s.weight, reliability=s.reliability)
        try:
            r = http.s.post("https://threatfox-api.abuse.ch/api/v1/",
                            json={"query": "search_ioc", "search_term": ip},
                            timeout=(3, 8))
        except Exception as e:
            o.status = TS2.PROVIDER_ERROR; o.error = str(e); return o
        if r.status_code != 200: o.status = TS2.PROVIDER_ERROR; return o
        try: d = r.json() or {}
        except Exception: o.status = TS2.PROVIDER_ERROR; return o
        data = d.get("data") or []
        if not data:
            o.status = TS.NO_THREAT.value; o.confidence = 70.0; return o
        fams = set()
        for row in data:
            if row.get("malware"): fams.add(row["malware"])
            if row.get("threat_type"): o.categories.append(row["threat_type"])
        o.reports = len(data)
        o.categories = sorted(set(o.categories))[:10]
        o.malware = bool(fams)
        o.score = min(100, 60 + len(data) * 5)
        o.status = TS2.POSITIVE
        o.confidence = min(100, 75 + len(data) * 3)
        return o

# ---------------- Feodo Tracker ----------------
class FeodoTracker(Provider):
    name = "feodo"; env_var = ""; cfg_key = ""
    _cache = {"data": None, "ts": 0.0}
    def __init__(s):
        super().__init__()
        s.weight = float(PI["providers"].get(s.name, {}).get("weight", 1.0))
        s.reliability = float(PI["providers"].get(s.name, {}).get("reliability", 0.90))
    def query(s, ip):
        o = Obs(provider=s.name, status=TS.NO_DATA.value, timestamp=now(),
                weight=s.weight, reliability=s.reliability)
        n = time.time()
        if not s._cache["data"] or (n - s._cache["ts"]) > 1800:
            try:
                r = http.s.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                               timeout=(3, 8))
                if r.status_code != 200:
                    o.status = TS2.PROVIDER_ERROR; return o
                data = r.json() or []
                s._cache["data"] = {row.get("ip_address"): row for row in data
                                     if row.get("ip_address")}
                s._cache["ts"] = n
            except Exception as e:
                o.status = TS2.PROVIDER_ERROR; o.error = str(e); return o
        match = s._cache["data"].get(ip)
        if match:
            o.status = TS2.POSITIVE
            o.score = 100.0; o.confidence = 95.0
            o.categories = ["botnet_c2", match.get("malware", "unknown")]
            o.malware = True; o.botnet = True
            o.first_seen = match.get("first_seen")
            o.last_seen = match.get("last_online")
        else:
            o.status = TS.NO_THREAT.value; o.confidence = 75.0
        return o

# ---------------- SSLBL ----------------
class SSLBL(Provider):
    name = "sslbl"; env_var = ""; cfg_key = ""
    _cache = {"data": None, "ts": 0.0}
    def __init__(s):
        super().__init__()
        s.weight = float(PI["providers"].get(s.name, {}).get("weight", 0.9))
        s.reliability = float(PI["providers"].get(s.name, {}).get("reliability", 0.80))
    def query(s, ip):
        o = Obs(provider=s.name, status=TS.NO_DATA.value, timestamp=now(),
                weight=s.weight, reliability=s.reliability)
        n = time.time()
        if not s._cache["data"] or (n - s._cache["ts"]) > 3600:
            try:
                r = http.s.get("https://sslbl.abuse.ch/blacklist/sslipblacklist.json",
                               timeout=(3, 8))
                if r.status_code != 200:
                    o.status = TS2.PROVIDER_ERROR; return o
                data = r.json() or []
                s._cache["data"] = {row.get("ip"): row for row in data if row.get("ip")}
                s._cache["ts"] = n
            except Exception as e:
                o.status = TS2.PROVIDER_ERROR; o.error = str(e); return o
        match = s._cache["data"].get(ip)
        if match:
            o.status = TS2.POSITIVE
            o.score = 100.0; o.confidence = 85.0
            o.categories = ["malicious_tls"]; o.malware = True
        else:
            o.status = TS.NO_THREAT.value; o.confidence = 65.0
        return o

# ---------------- GreyNoise Community ----------------
class GreyNoise(Provider):
    _disabled = True
    name = "greynoise"; env_var = "GREYNOISE_API_KEY"; cfg_key = "greynoise"
    def __init__(s):
        super().__init__()
        s.weight = float(PI["providers"].get(s.name, {}).get("weight", 0.8))
        s.reliability = float(PI["providers"].get(s.name, {}).get("reliability", 0.80))
    def query(s, ip):
        o = Obs(provider=s.name, status=TS.NO_DATA.value, timestamp=now(),
                weight=s.weight, reliability=s.reliability)
        k = resolve_key(s.env_var, s.cfg_key)
        hdrs = {"Accept": "application/json"}
        if k: hdrs["key"] = k
        try:
            r = http.s.get(f"https://api.greynoise.io/v3/community/{ip}",
                           headers=hdrs, timeout=(2, 4))
        except Exception as e:
            o.status = TS2.PROVIDER_ERROR; o.error = str(e); return o
        if r.status_code == 404:
            o.status = TS.NO_THREAT.value; o.confidence = 65.0; return o
        if r.status_code == 429: o.status = TS2.RATE_LIMITED; return o
        if r.status_code != 200:
            o.status = TS2.PROVIDER_ERROR; o.error = f"HTTP {r.status_code}"; return o
        try: d = r.json() or {}
        except Exception: o.status = TS2.PROVIDER_ERROR; return o
        noise = bool(d.get("noise"))
        riot = bool(d.get("riot"))
        cls = str(d.get("classification", "") or "").lower()
        name = d.get("name", "") or ""
        o.categories = [c for c in (cls, "noise" if noise else "",
                                     "riot" if riot else "") if c]
        if not noise and not riot:
            o.status = TS.NO_THREAT.value; o.confidence = 70.0; return o
        if riot:
            o.status = TS.NO_THREAT.value; o.confidence = 85.0
            o.categories.append("benign_service"); return o
        if cls == "malicious":
            o.status = TS2.POSITIVE
            o.score = 70.0; o.confidence = 80.0
            o.categories.append(name or "malicious_scanner")
        elif cls == "benign":
            o.status = TS.NO_THREAT.value; o.confidence = 65.0
        else:
            o.status = TS2.POSITIVE
            o.score = 40.0; o.confidence = 60.0
            o.categories.append("noise_scanner")
        return o

# ---------------- CINS Army ----------------
class CINS(Provider):
    name = "cins"; env_var = ""; cfg_key = ""
    _cache = {"data": None, "ts": 0.0}
    def __init__(s):
        super().__init__()
        s.weight = float(PI["providers"].get(s.name, {}).get("weight", 0.7))
        s.reliability = float(PI["providers"].get(s.name, {}).get("reliability", 0.70))
    def query(s, ip):
        o = Obs(provider=s.name, status=TS.NO_DATA.value, timestamp=now(),
                weight=s.weight, reliability=s.reliability)
        n = time.time()
        if not s._cache["data"] or (n - s._cache["ts"]) > 3600:
            try:
                r = http.s.get("http://cinsscore.com/list/ci-badguys.txt",
                               timeout=(3, 8))
                if r.status_code != 200:
                    o.status = TS2.PROVIDER_ERROR; return o
                s._cache["data"] = set(r.text.splitlines())
                s._cache["ts"] = n
            except Exception as e:
                o.status = TS2.PROVIDER_ERROR; o.error = str(e); return o
        if ip in s._cache["data"]:
            o.status = TS2.POSITIVE
            o.score = 75.0; o.confidence = 70.0
            o.categories = ["cins_listed"]
        else:
            o.status = TS.NO_THREAT.value; o.confidence = 60.0
        return o

# ---------------- Spamhaus DROP ----------------
class SpamhausDROP(Provider):
    name = "spamhaus_drop"; env_var = ""; cfg_key = ""
    _cache = {"data": None, "ts": 0.0}
    def __init__(s):
        super().__init__()
        s.weight = float(PI["providers"].get(s.name, {}).get("weight", 0.9))
        s.reliability = float(PI["providers"].get(s.name, {}).get("reliability", 0.85))
    def query(s, ip):
        o = Obs(provider=s.name, status=TS.NO_DATA.value, timestamp=now(),
                weight=s.weight, reliability=s.reliability)
        n = time.time()
        if not s._cache["data"] or (n - s._cache["ts"]) > 3600:
            try:
                r = http.s.get("https://www.spamhaus.org/drop/drop.txt",
                               timeout=(3, 8))
                if r.status_code != 200:
                    o.status = TS2.PROVIDER_ERROR; return o
                nets = []
                for ln in r.text.splitlines():
                    ln = ln.strip()
                    if not ln or ln.startswith(";"): continue
                    try:
                        nets.append(ipaddress.ip_network(ln.split(";")[0].strip(),
                                                          strict=False))
                    except Exception:
                        pass
                s._cache["data"] = nets
                s._cache["ts"] = n
            except Exception as e:
                o.status = TS2.PROVIDER_ERROR; o.error = str(e); return o
        try: ip_obj = ipaddress.ip_address(ip)
        except Exception: o.status = TS2.PROVIDER_ERROR; return o
        for net in s._cache["data"]:
            if ip_obj.version == net.version and ip_obj in net:
                o.status = TS2.POSITIVE
                o.score = 80.0; o.confidence = 85.0
                o.categories = [f"spamhaus:{net}"]
                return o
        o.status = TS.NO_THREAT.value; o.confidence = 65.0
        return o

# ---------------- Registry ----------------
PROVIDERS = [AbuseIPDB, VirusTotal, AlienVault, URLhaus, ThreatFox,
             FeodoTracker, SSLBL, GreyNoise, CINS, SpamhausDROP]

def collect_threat(ip, per_provider_timeout=8.0):
    """v21.11: hard timeout per provider via signal.alarm."""
    import signal as _sig
    heavy_names = {"feodo", "sslbl", "cins", "spamhaus_drop"}
    heavy_enabled = os.environ.get("RECONIP_BULK_FEEDS", "1") != "0"
    ps = []
    for cls in PROVIDERS:
        try:
            p = cls()
            if not p.enabled: continue
            if p.name in heavy_names and not heavy_enabled: continue
            ps.append(p)
        except Exception as e:
            log.warning(f"provider {cls.__name__}: {e}")
    if not ps: return [], MS.SKIPPED.value

    def _alarm_handler(signum, frame):
        raise TimeoutError("provider hard timeout")

    def _query_with_timeout(p, ip, timeout):
        """Run p.query(ip) with signal-based hard timeout."""
        try:
            old = _sig.signal(_sig.SIGALRM, _alarm_handler)
            _sig.alarm(int(max(1, timeout)))
        except (ValueError, OSError):
            # Not in main thread — fall back to soft timeout
            return p.query(ip)
        try:
            return p.query(ip)
        finally:
            _sig.alarm(0)
            try:
                _sig.signal(_sig.SIGALRM, old)
            except Exception:
                pass

    obs_list = []
    for p in ps:
        t0 = time.monotonic()
        try:
            o = _query_with_timeout(p, ip, per_provider_timeout)
        except TimeoutError:
            o = Obs(provider=p.name, status=TS2.PROVIDER_ERROR, timestamp=now(),
                    weight=p.weight, reliability=p.reliability,
                    error=f"hard timeout ({per_provider_timeout}s)")
            log.warning(f"[HARD-TIMEOUT] {p.name}")
        except Exception as e:
            o = Obs(provider=p.name, status=TS2.PROVIDER_ERROR, timestamp=now(),
                    weight=p.weight, reliability=p.reliability, error=str(e))
        ms = (time.monotonic() - t0) * 1000
        if o.status in (TS2.POSITIVE, TS.NO_THREAT.value):
            H(p.name).success(ms)
        elif o.status == TS2.RATE_LIMITED:
            H(p.name).failure(EC.RATE_LIMITED.value, ms)
        elif o.status == TS2.PROVIDER_ERROR:
            H(p.name).failure(EC.TRANSIENT.value, ms)
        # Stage 2: Evidence traceability for each threat provider
        try:
            ev_threat = make_evidence(
                source=p.name,
                value=getattr(o, 'score', None),
                normalized_value=getattr(o, 'score', None),
                confidence=(getattr(o, 'confidence', 50) / 100.0) if getattr(o, 'confidence', None) else 0.5,
                status="OK" if o.status in (TS2.POSITIVE, TS.NO_THREAT.value, TS.NO_DATA.value) else "FAILED",
                ttl_key="threat",
                metadata={"provider": p.name, "status": o.status, "categories": getattr(o, 'categories', []), "error": getattr(o, 'error', None), "data_type": "threat", "field": p.name, "target": ip, "raw_value": getattr(o, 'score', None)}
            )
            # Keep evidence for debugging / future report pipeline
            format_evidence(ev_threat)
        except Exception:
            pass
        obs_list.append(o)
    att = len(ps)
    resp = sum(1 for o in obs_list if o.status in
               (TS2.POSITIVE, TS.NO_THREAT.value, TS.NO_DATA.value))
    return obs_list, module_status(att, resp)


def agg_threat(obs_list):
    if not obs_list:
        return {"score": 0.0, "classification": "No provider data", "coverage": 0.0,
                "confidence": 0.0, "agreement": 0.0, "positive": 0, "negative": 0,
                "no_data": 0, "error": 0, "not_configured": 0, "rate_limited": 0,
                "providers": [], "disagreements": [],
                "explanation": "No providers.",
                "answered_weight": 0.0, "total_weight": 0.0}
    tw = sum(o.weight for o in obs_list)
    aw = pw = ws = 0.0
    pos, neg = [], []
    nd = er = nc = rl = 0
    for o in obs_list:
        s = o.status
        if s == TS.NOT_CONFIGURED.value: nc += 1
        elif s == TS2.PROVIDER_ERROR: er += 1
        elif s == TS2.RATE_LIMITED: rl += 1
        elif s == TS.NO_DATA.value: nd += 1
        elif s == TS.NO_THREAT.value:
            neg.append(o); aw += o.weight
        elif s == TS2.POSITIVE:
            pos.append(o); aw += o.weight; pw += o.weight
            ws += (o.score or 0) * o.weight
    cov = round(aw / tw * 100, 1) if tw else 0.0
    sc = round(ws / pw, 1) if pw else 0.0
    if pos:
        if sc >= 80: cls = "Critical Threat Evidence"
        elif sc >= 60: cls = "High Threat Evidence"
        elif sc >= 40: cls = "Moderate Threat Evidence"
        elif sc >= 20: cls = "Low Threat Evidence"
        else: cls = "Informational Threat Evidence"
    elif neg:
        gaps = nd + er + nc + rl
        cls = ("No threat evidence (provider gaps exist)"
               if gaps >= len(obs_list) else "No threat evidence detected")
    elif nd > 0: cls = "No data for this IP"
    elif nc == len(obs_list): cls = "No threat providers configured"
    else: cls = "Threat data unavailable"
    pc = (sum(o.confidence * o.weight for o in pos) / pw) if pw else 0.0
    dis = []
    if pos and neg:
        dis.append({"type": "positive_vs_negative",
                    "positive_providers": [o.provider for o in pos],
                    "negative_providers": [o.provider for o in neg],
                    "explanation": "Some providers report positive while others report none."})
    if len(pos) >= 2:
        ss = [o.score or 0 for o in pos]
        sp = max(ss) - min(ss)
        if sp >= 40:
            dis.append({"type": "score_spread", "spread": round(sp, 1),
                        "explanation": f"Positive providers disagree (spread {round(sp,1)})."})
    dc = PI["disagreement"]
    pen = min(dc["max_penalty"], dc["confidence_penalty_per_conflict"] * len(dis))
    cp = (100 - cov) * 0.3 if cov < 100 else 0
    conf = round(max(0, min(100, pc - pen - cp)), 1)
    pw2 = sum(o.weight for o in pos); nw = sum(o.weight for o in neg)
    agr = round(100 - min(pw2, nw) / (pw2 + nw) * 100, 1) if (pw2 + nw) > 0 else 100.0
    parts = []
    if pos: parts.append(f"{len(pos)} positive")
    if neg: parts.append(f"{len(neg)} negative")
    if nd: parts.append(f"{nd} no data")
    if er: parts.append(f"{er} errored")
    if rl: parts.append(f"{rl} rate-limited")
    if nc: parts.append(f"{nc} not configured")
    expl = "; ".join(parts) + "." if parts else "No info."
    if dis: expl += " Providers disagree."
    return {"score": sc, "classification": cls, "coverage": cov, "confidence": conf,
            "agreement": agr, "positive": len(pos), "negative": len(neg),
            "no_data": nd, "error": er, "not_configured": nc, "rate_limited": rl,
            "providers": [o.to_dict() for o in obs_list],
            "disagreements": dis, "explanation": expl,
            "answered_weight": round(aw, 3), "total_weight": round(tw, 3)}

def threat_evs(ip, obs_list):
    evs = []
    for o in obs_list:
        if o.status != TS2.POSITIVE: continue
        evs.append(mk_ev(ip, "threat", "provider_score", o.provider, o.score, o.to_dict()))
        evs.append(mk_ev(ip, "threat", "provider_reports", o.provider, o.reports, o.to_dict()))
        for c in o.categories:
            evs.append(mk_ev(ip, "threat", "provider_category", o.provider, c, o.to_dict()))
        if o.malware:
            evs.append(mk_ev(ip, "threat", "malware_association", o.provider, True, o.to_dict()))
        if o.phishing:
            evs.append(mk_ev(ip, "threat", "phishing", o.provider, True, o.to_dict()))
        if o.botnet:
            evs.append(mk_ev(ip, "threat", "botnet", o.provider, True, o.to_dict()))
    return evs

# ============================================================
#  PHASE 2 — SUBDOMAIN ENUM + TYPOSQUATTING + CT DEEP + WHOIS
# ============================================================

def levenshtein(a, b, max_dist=5):
    if abs(len(a) - len(b)) > max_dist: return max_dist + 1
    if a == b: return 0
    if not a: return len(b)
    if not b: return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j-1] + cost))
        prev = cur
    return prev[-1]

def is_likely_typosquat(candidate, target, max_dist=2):
    if not candidate or not target: return False
    a = candidate.lower().strip(".")
    b = target.lower().strip(".")
    if a == b: return False
    if a.endswith("." + b): return False
    a_parts = a.split("."); b_parts = b.split(".")
    if len(a_parts) < 2 or len(b_parts) < 2: return False
    a_reg = ".".join(a_parts[-2:])
    b_reg = ".".join(b_parts[-2:])
    if a_reg == b_reg: return False
    d_reg = levenshtein(a_reg, b_reg, max_dist)
    if 0 < d_reg <= max_dist: return True
    homoglyph_pairs = [("0","o"), ("1","l"), ("1","i"),
                       ("rn","m"), ("vv","w"), ("5","s"), ("3","e")]
    a_h = a_reg; b_h = b_reg
    for x, y in homoglyph_pairs:
        a_h = a_h.replace(x, y)
    if a_h == b_h and a_reg != b_reg: return True
    return False

class SubdomainEnum:
    @staticmethod
    def from_crtsh(domain, max_n=200):
        if not domain: return []
        try:
            r = http.s.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                           timeout=(5, 15))
            if r.status_code != 200: return []
            data = r.json() or []
        except Exception as e:
            log.debug(f"crtsh subdomains: {e}"); return []
        subs = set()
        for entry in data[:500]:
            name_value = (entry.get("name_value") or "")
            for name in name_value.split("\n"):
                n = name.strip().lower().rstrip(".")
                if not n: continue
                if n.startswith("*."): n = n[2:]
                if n.endswith(domain) and len(n) < 253:
                    subs.add(n)
                    if len(subs) >= max_n: break
            if len(subs) >= max_n: break
        return sorted(subs)

    @staticmethod
    def from_hackertarget(domain, max_n=200):
        if not domain: return []
        try:
            r = http.s.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                           timeout=(5, 15))
            if r.status_code != 200: return []
            t = r.text.strip()
            if "error" in t.lower() or "exceeded" in t.lower() or not t: return []
            out = set()
            for ln in t.splitlines():
                if "," in ln:
                    h = ln.split(",", 1)[0].strip().lower()
                    if h and h.endswith(domain):
                        out.add(h)
                        if len(out) >= max_n: break
            return sorted(out)
        except Exception as e:
            log.debug(f"hackertarget subs: {e}"); return []

    @staticmethod
    def from_otx(domain, max_n=200):
        if not domain: return []
        try:
            r = http.s.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                           timeout=(5, 15))
            if r.status_code != 200: return []
            data = r.json() or {}
            subs = set()
            for row in (data.get("passive_dns") or []):
                h = (row.get("hostname") or "").strip().lower().rstrip(".")
                if h and h.endswith(domain):
                    subs.add(h)
                    if len(subs) >= max_n: break
            return sorted(subs)
        except Exception as e:
            log.debug(f"otx subs: {e}"); return []

def enumerate_subdomains(domain, target_ip=None):
    if not domain: return {"subdomains": [], "sources": {}, "total": 0}
    cfg = CFG.get("phase_p2", {}).get("subdomain_enum", {})
    if not cfg.get("enabled", True): return {"subdomains": [], "sources": {}, "total": 0}
    sources = cfg.get("sources", ["crtsh", "hackertarget", "otx"])
    max_n = int(cfg.get("max_results", 200))
    results = {}
    if "crtsh" in sources:
        results["crtsh"] = SubdomainEnum.from_crtsh(domain, max_n)
    if "hackertarget" in sources:
        results["hackertarget"] = SubdomainEnum.from_hackertarget(domain, max_n)
    if "otx" in sources:
        results["otx"] = SubdomainEnum.from_otx(domain, max_n)
    all_subs = set()
    for arr in results.values():
        all_subs.update(arr)
    # v21.6: filter numeric-only subdomains (1.google.com, 216-239-33-25.google.com)
    filtered = set()
    for s in all_subs:
        first = s.split(".")[0]
        if re.match(r'^\d+$', first): continue          # "1", "216"
        if re.match(r'^\d+\-\d+.*$', first): continue   # "216-239-33-25"
        if re.match(r'^[a-f0-9]{16,}$', first): continue # hex garbage
        filtered.add(s)
    return {"subdomains": sorted(filtered)[:max_n],
            "sources": {k: len(v) for k, v in results.items()},
            "total": len(filtered), "target_ip": target_ip}

def detect_typosquatting(domain, candidate_domains):
    if not domain: return []
    cfg = CFG.get("phase_p2", {}).get("typosquatting", {})
    if not cfg.get("enabled", True): return []
    max_d = int(cfg.get("max_distance", 2))
    out = []
    for c in candidate_domains:
        if not c: continue
        c_clean = c.lower().strip().rstrip(".")
        if c_clean == domain.lower(): continue
        first_label = c_clean.split(".")[0]
        if re.match(r'^[\d\-\.]+$', first_label): continue
        if is_likely_typosquat(c_clean, domain, max_d):
            d = levenshtein(c_clean, domain, max_d)
            out.append({"domain": c_clean, "distance": d,
                        "reason": "levenshtein" if d > 0 else "homoglyph"})
    return sorted(out, key=lambda x: x["distance"])[:20]

def analyze_ct_subdomains(cert_records):
    if not cert_records:
        return {"all_subdomains": [], "ca_distribution": {},
                "suspicious_sans": [], "total_certs": 0}
    subs = set(); ca_dist = defaultdict(int); suspicious = []
    for rec in cert_records.values():
        for san in rec.sans:
            s = san.lower().strip().rstrip(".")
            if s.startswith("*."): s = s[2:]
            if s: subs.add(s)
        issuer = rec.issuer or ""
        m = re.search(r"CN=([^,]+)", issuer)
        if m: ca_dist[m.group(1).strip()] += 1
        elif issuer: ca_dist[issuer[:40]] += 1
        for san in rec.sans:
            s = san.lower()
            if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s):
                suspicious.append({"san": san, "reason": "IP in SAN",
                                    "cert": rec.id[:24]})
            if any(s.endswith(tld) for tld in
                   (".biz", ".xyz", ".top", ".tk", ".ml", ".ga", ".cf")):
                suspicious.append({"san": san, "reason": "suspicious TLD",
                                    "cert": rec.id[:24]})
    return {"all_subdomains": sorted(subs)[:500],
            "ca_distribution": dict(ca_dist),
            "suspicious_sans": suspicious[:20],
            "total_certs": len(cert_records)}

def whois_enhanced(target):
    try:
        t0 = time.monotonic()
        out, _ = safe_subprocess("whois", [target], timeout=PN["subprocess_timeout"])
        ms = (time.monotonic() - t0) * 1000
        if not out:
            H("whois_enhanced").failure(EC.PERMANENT.value, ms); return None
        H("whois_enhanced").success(ms)
        text = out
        def grab(*patterns):
            for pat in patterns:
                r = re.search(pat, text, re.I)
                if r:
                    for g in (2, 1):
                        try:
                            v = r.group(g).strip()
                            if v: return v
                        except Exception: continue
            return ""
        result = {
            "handle": grab(r"(handle|nic-hdl):\s*([^\n]+)"),
            "name": grab(r"(netname|name):\s*([^\n]+)"),
            "organization": grab(r"(OrgName|org-name|organisation|owner):\s*([^\n]+)"),
            "country": grab(r"(Country|country):\s*([^\n]+)"),
            "netrange": grab(r"(NetRange):\s*([^\n]+)"),
            "cidr": grab(r"(CIDR):\s*([^\n]+)"),
            "created": grab(r"(Created|RegDate|created|Registration Date):\s*([^\n]+)"),
            "updated": grab(r"(Updated|Updated Date|last-modified|Last Modified):\s*([^\n]+)"),
            "abuse_email": grab(r"(abuse-mailbox|OrgAbuseEmail):\s*([^\n]+)"),
            "abuse_phone": grab(r"(OrgAbusePhone|abuse-phone):\s*([^\n]+)"),
            "tech_email": grab(r"(TechEmail|tech-c|Tech Email):\s*([^\n]+)"),
            "admin_email": grab(r"(AdminEmail|admin-c|Admin Email):\s*([^\n]+)"),
            "status": grab(r"(Status|status):\s*([^\n]+)"),
            "dnssec": grab(r"(DNSSEC):\s*([^\n]+)"),
        }
        return {k: v for k, v in result.items() if v}
    except Exception as e:
        H("whois_enhanced").failure(exc_class(e), 0); return None

def whois_parse(whois_data):
    """
    Parse WHOIS data and clearly separate registration date from update date (B3 fix).
    Return dict with keys: 'reg_date', 'updated_date', 'org', 'netrange', 'cidr', etc.
    """
    if not isinstance(whois_data, dict):
        return {}
    parsed = {}
    # Support multiple key variants
    parsed['reg_date'] = whois_data.get('created') or whois_data.get('creation_date') or whois_data.get('RegDate') or ""
    parsed['updated_date'] = whois_data.get('updated') or whois_data.get('updated_date') or whois_data.get('Updated') or ""
    parsed['org'] = whois_data.get('organization', '') or whois_data.get('org', '')
    parsed['netrange'] = whois_data.get('netrange', '')
    parsed['cidr'] = whois_data.get('cidr', '')
    parsed['handle'] = whois_data.get('handle', '')
    parsed['country'] = whois_data.get('country', '')
    if not parsed['reg_date']:
        parsed['reg_date_note'] = 'Original registration date not provided by WHOIS server.'
    return parsed

class PassiveOSINTv2:
    @staticmethod
    def virustotal_passive_dns(ip):
        key = resolve_key("VIRUSTOTAL_API_KEY", "virustotal")
        if not key: return []
        try:
            r = http.s.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions",
                           headers={"x-apikey": key}, timeout=(3, 8))
            if r.status_code != 200: return []
            d = r.json() or {}
            out = []
            for row in (d.get("data") or [])[:50]:
                attrs = row.get("attributes") or {}
                out.append({"hostname": attrs.get("host_name"),
                            "date": attrs.get("date"),
                            "resolved_ip": ip})
            return out
        except Exception as e:
            log.debug(f"vt passive dns: {e}"); return []

def normalize_passive_dns(raw_records):
    """
    Normalize passive DNS records into a consistent structure (B2 fix).
    Each record should have: domain/hostname, first_seen, last_seen, source.
    Preserves provider dates instead of overwriting with current date.
    """
    normalized = []
    for rec in raw_records or []:
        # Handle multiple provider formats
        domain = rec.get("hostname") or rec.get("domain") or ""
        # OTX provides first/last, VT provides single date
        first = rec.get("first") or rec.get("first_seen") or rec.get("firstSeen")
        last = rec.get("last") or rec.get("last_seen") or rec.get("lastSeen")
        # VT single date fallback
        vt_date = rec.get("date")
        if vt_date and not first and not last:
            # Single date provider: treat as last_seen, leave first_seen None to avoid false identical
            last = vt_date
            first = None
        # If provider only gives a single date field as both, keep it but don't fabricate current date
        normalized.append({
            'hostname': domain,
            'domain': domain,
            'first': first,
            'last': last,
            'first_seen': first,
            'last_seen': last,
            'source': rec.get("source", "unknown"),
            'record_type': rec.get("record_type", "")
        })
    # Sort by last_seen descending
    normalized.sort(key=lambda x: (x['last_seen'] or ''), reverse=True)
    return normalized

def merge_passive_dns(ip, existing_otx):
    cfg = CFG.get("phase_p2", {}).get("passive_dns", {})
    if not cfg.get("enabled", True): return normalize_passive_dns(existing_otx or [])
    sources = cfg.get("sources", ["otx", "virustotal"])
    merged = list(existing_otx or [])
    if "virustotal" in sources:
        vt = PassiveOSINTv2.virustotal_passive_dns(ip)
        merged.extend(vt)
    seen = set(); out = []
    for row in merged:
        h = row.get("hostname") or row.get("domain")
        if not h or h in seen: continue
        seen.add(h); out.append(row)
    # Normalize to ensure first_seen/last_seen are preserved correctly (B2)
    return normalize_passive_dns(out[:100])

def enrich_suspicious_ips(rev_ip_list):
    if not rev_ip_list: return []
    rev_ip_list = _filter_reverse_ip(rev_ip_list)
    if not rev_ip_list: return []
    suspicious = []
    for dom in rev_ip_list:
        d = str(dom).lower()
        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", d):
            suspicious.append({"domain": dom, "reason": "IP-in-domain"})
        elif any(d.endswith(tld) for tld in
                 (".biz", ".xyz", ".top", ".tk", ".ml", ".ga", ".cf",
                  ".work", ".click", ".download")):
            suspicious.append({"domain": dom, "reason": "suspicious-tld"})
        elif re.match(r"^[a-z0-9]{20,}\.", d):
            suspicious.append({"domain": dom, "reason": "random-looking"})
    return suspicious[:20]

# ============================================================
#  PASSIVE OSINT (base)
# ============================================================
def _filter_reverse_ip(domains):
    """v21.6: aggressive filter. Removes spam/arpa/numeric/hex patterns."""
    # Common spam TLDs / known parking/abuse domains
    SPAM_SUFFIXES = (
        ".vip", ".top", ".xyz", ".tk", ".ml", ".ga", ".cf",
        ".cn.trustexporter.com", ".trustexporter.com",
        ".freeddns.org", ".dpdns.org", ".magas.services",
        ".639296.vip", ".321654987.ir", ".pp.ua",
        ".shop", ".work", ".click", ".download", ".loan",
        ".bid", ".win", ".racing", ".party", ".review",
    )
    out = []
    for d in domains:
        if not isinstance(d, str): continue
        dl = d.lower().strip()
        if not dl: continue
        # arpa
        if dl.endswith('.ip6.arpa'): continue
        if dl.endswith('.in-addr.arpa'): continue
        if dl.endswith('.arpa'): continue
        # pure numeric/dots
        if re.match(r'^[\d\.\-]+$', dl): continue
        # error strings
        if 'no dns' in dl or 'not found' in dl or 'error' in dl: continue
        # length
        if len(dl) < 4 or len(dl) > 80: continue
        first = dl.split('.')[0]
        # hex garbage (random subdomain)
        if re.match(r'^[a-f0-9]{16,}$', first): continue
        # pure numeric first label
        if re.match(r'^\d+$', first): continue
        # numeric with dashes (000-000-000 pattern)
        if re.match(r'^\d[\d\-]+\d$', first): continue
        # v21.6: skip known spam suffixes
        if any(dl.endswith(sfx) for sfx in SPAM_SUFFIXES):
            continue
        # v21.6: skip domains with IP-like first label (e.g. 216-239-33-25)
        if re.match(r'^\d{1,3}\-\d{1,3}\-\d{1,3}\-\d{1,3}$', first):
            continue
        out.append(dl)
    return out

def ports_parse(open_ports):
    """
    Enrich port list with protocol, service, and version if available (B5 fix).
    Input: list of port numbers or raw scan results.
    Output: list of dicts {'port': int, 'protocol': 'tcp/udp', 'service': str, 'version': str}
    """
    enriched = []
    service_map = {
        53: ('dns', 'tcp/udp'),
        443: ('https', 'tcp'),
        80: ('http', 'tcp'),
        22: ('ssh', 'tcp'),
        25: ('smtp', 'tcp'),
        110: ('pop3', 'tcp'),
        143: ('imap', 'tcp'),
        3306: ('mysql', 'tcp'),
        5432: ('postgresql', 'tcp'),
        6379: ('redis', 'tcp'),
        8080: ('http-proxy', 'tcp'),
        8443: ('https-alt', 'tcp'),
    }
    for port in open_ports or []:
        try:
            p = int(port)
        except Exception:
            continue
        service, proto = service_map.get(p, ('unknown', 'tcp'))
        enriched.append({'port': p, 'protocol': proto, 'service': service, 'version': ''})
    return enriched

def filter_reverse_ip(domains, target_ip, public_resolvers=None, anycast_asns=None, asn=None):
    """
    Filter out domains that are not true reverse IP records (B4 fix).
    - Remove public resolvers (if target_ip is a resolver, skip reverse IP entirely).
    - Remove anycast ASNs (reverse IP is meaningless for anycast).
    - Otherwise apply aggressive domain filtering.
    Returns (filtered_list, note)
    """
    if public_resolvers is None:
        public_resolvers = CFG.get("public_resolvers") or CFG.get("geo_validation", {}).get("anycast_ips", []) or []
    if anycast_asns is None:
        anycast_asns = CFG.get("anycast_asns", []) or []
    # If target IP is a known public resolver, return empty with note
    if target_ip and str(target_ip) in [str(x) for x in public_resolvers]:
        return [], "Target is a public DNS resolver. Reverse IP is not applicable."
    # If ASN is anycast, reverse IP is unreliable
    if asn:
        try:
            asn_num = int(str(asn).replace("AS", "").replace("as", "").strip())
            if asn_num in [int(x) for x in anycast_asns]:
                return [], "Target is in an anycast ASN. Reverse IP is not meaningful."
        except Exception:
            pass
        # Also check string form
        if str(asn) in [str(x) for x in anycast_asns] or f"AS{asn}" in [str(x) for x in anycast_asns]:
            return [], "Target is in an anycast ASN. Reverse IP is not meaningful."
    # Otherwise apply base filter but add warning
    filtered = _filter_reverse_ip(domains or [])
    if not filtered:
        return [], "No valid reverse IP domains after filtering."
    return filtered, "Reverse IP list may include passive DNS artifacts."


# ============================================================
#  PHASE 3 — MITRE ATT&CK + THREAT ATTRIBUTION
# ============================================================

ATTACK_TECHNIQUES = {
    "T1071":     ("Application Layer Protocol", "Command and Control"),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
    "T1090":     ("Proxy", "Command and Control"),
    "T1090.003": ("Proxy: Multi-hop Proxy", "Command and Control"),
    "T1102":     ("Web Service", "Command and Control"),
    "T1566":     ("Phishing", "Initial Access"),
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access"),
    "T1566.002": ("Phishing: Spearphishing Link", "Initial Access"),
    "T1595":     ("Active Scanning", "Reconnaissance"),
    "T1595.001": ("Active Scanning: Scanning IP Blocks", "Reconnaissance"),
    "T1592":     ("Gather Victim Host Information", "Reconnaissance"),
    "T1583":     ("Acquire Infrastructure", "Resource Development"),
    "T1583.001": ("Acquire Infrastructure: Domains", "Resource Development"),
    "T1583.003": ("Acquire Infrastructure: Virtual Private Server", "Resource Development"),
    "T1584":     ("Compromise Infrastructure", "Resource Development"),
    "T1584.005": ("Compromise Infrastructure: Botnet", "Resource Development"),
    "T1587":     ("Develop Capabilities", "Resource Development"),
    "T1587.001": ("Develop Capabilities: Malware", "Resource Development"),
    "T1588":     ("Obtain Capabilities", "Resource Development"),
    "T1496":     ("Resource Hijacking", "Impact"),
    "T1498":     ("Network Denial of Service", "Impact"),
    "T1505":     ("Server Software Component", "Persistence"),
    "T1190":     ("Exploit Public-Facing Application", "Initial Access"),
    "T1133":     ("External Remote Services", "Persistence"),
}

APT_KEYWORDS = {
    "apt28": "APT28 (Fancy Bear)", "apt29": "APT29 (Cozy Bear)",
    "apt32": "APT32 (OceanLotus)", "apt34": "APT34 (OilRig)",
    "apt41": "APT41 (Winnti)", "lazarus": "Lazarus Group",
    "sandworm": "Sandworm Team", "turla": "Turla",
    "kimsuky": "Kimsuky", "darkside": "DarkSide",
    "revil": "REvil", "conti": "Conti", "lockbit": "LockBit",
    "blackcat": "BlackCat/ALPHV", "hive": "Hive",
    "emotet": "Emotet", "trickbot": "TrickBot", "qakbot": "QakBot",
    "cobalt": "Cobalt Strike", "metasploit": "Metasploit",
    "mirai": "Mirai", "wizard": "Wizard Spider",
    "fin7": "FIN7", "carbanak": "Carbanak",
}


def map_to_attack(observations, provider_results, anomalies):
    techniques = {}
    def _add(tid, conf, reason):
        if tid not in ATTACK_TECHNIQUES: return
        name, tactic = ATTACK_TECHNIQUES[tid]
        if tid not in techniques:
            techniques[tid] = {"id": tid, "name": name, "tactic": tactic,
                                "confidence": 0.0, "reasons": []}
        if conf > techniques[tid]["confidence"]:
            techniques[tid]["confidence"] = conf
        techniques[tid]["reasons"].append(reason)

    for p in (provider_results or []):
        if p.get("status") != "POSITIVE_EVIDENCE": continue
        cats = " ".join(p.get("categories") or []).lower()
        prov = p.get("provider", "?")
        if p.get("botnet") or "botnet" in cats or "c2" in cats:
            _add("T1071", 75, f"{prov}: botnet C2")
            _add("T1584.005", 60, f"{prov}: botnet infrastructure")
        if p.get("malware") or "malware" in cats:
            _add("T1587.001", 65, f"{prov}: malware association")
            _add("T1071", 60, f"{prov}: malware C2 potential")
        if p.get("phishing") or "phish" in cats:
            _add("T1566", 80, f"{prov}: phishing")
            _add("T1566.002", 70, f"{prov}: phishing link")
        if "abuse_high" in cats or "abuse_reports" in cats:
            _add("T1595.001", 55, f"{prov}: abuse reports")
        if "cins_listed" in cats:
            _add("T1595", 45, f"{prov}: CINS-listed")
        if "spamhaus" in cats:
            _add("T1583.003", 55, f"{prov}: Spamhaus DROP")

    for a in (anomalies or []):
        t = a.get("type", "")
        if "multiple_ptrs" in t: _add("T1583.001", 40, f"anomaly: {t}")
        if "asn_inconsistency" in t: _add("T1583.003", 35, f"anomaly: {t}")
        if "certificate_weak" in t: _add("T1587", 30, f"anomaly: {t}")

    for o in (provider_results or []):
        if o.get("status") == "POSITIVE_EVIDENCE":
            if "tor" in str(o.get("categories", [])).lower():
                _add("T1090.003", 70, "Tor exit node")

    kc_map = {
        "Reconnaissance": ["T1595", "T1595.001", "T1592"],
        "Resource Development": ["T1583", "T1583.001", "T1583.003",
                                  "T1584", "T1584.005", "T1587",
                                  "T1587.001", "T1588"],
        "Initial Access": ["T1566", "T1566.001", "T1566.002", "T1190", "T1133"],
        "Command and Control": ["T1071", "T1071.004", "T1090", "T1090.003", "T1102"],
        "Impact": ["T1496", "T1498"],
        "Persistence": ["T1505", "T1133"],
    }
    kill_chain = []
    for tactic, tids in kc_map.items():
        active_tids = [t for t in tids if t in techniques]
        kill_chain.append({"tactic": tactic, "active": bool(active_tids),
                            "techniques": active_tids})

    tactics_present = sorted({info["tactic"] for info in techniques.values()})
    return {"techniques": sorted(techniques.values(), key=lambda x: -x["confidence"]),
            "tactics": tactics_present, "kill_chain": kill_chain,
            "total_techniques": len(techniques)}


def attribute_threat_actors(provider_results, pulse_count=0):
    actor_hits = {}
    for p in (provider_results or []):
        if p.get("status") != "POSITIVE_EVIDENCE": continue
        cats = [str(c).lower() for c in (p.get("categories") or [])]
        for cat in cats:
            for kw, actor in APT_KEYWORDS.items():
                if kw in cat:
                    actor_hits.setdefault(actor, []).append(
                        {"provider": p.get("provider", "?"), "tag": cat})
    out = []
    for actor, hits in actor_hits.items():
        conf = min(95, 30 + 20 * len(hits))
        out.append({"actor": actor, "confidence": conf,
                    "evidence_count": len(hits),
                    "sources": list({h["provider"] for h in hits}),
                    "tags": list({h["tag"] for h in hits})})
    return sorted(out, key=lambda x: -x["confidence"])


def discover_related_infra(asn_numbers):
    if not asn_numbers: return []
    out = []
    for asn in asn_numbers[:2]:
        num = asn.replace("AS", "").strip()
        if not num.isdigit(): continue
        try:
            r = http.s.post("https://threatfox-api.abuse.ch/api/v1/",
                            json={"query": "search_ioc",
                                  "search_term": f"asn:{num}"},
                            timeout=(3, 8))
            if r.status_code != 200: continue
            d = r.json() or {}
            for row in (d.get("data") or [])[:10]:
                ioc = row.get("ioc", "")
                if ioc and not ioc.startswith("http"):
                    out.append({"ip": ioc,
                                "malware": row.get("malware", "unknown"),
                                "threat_type": row.get("threat_type", ""),
                                "confidence": int(row.get("confidence_level", 50)),
                                "source": "threatfox"})
        except Exception as e:
            log.debug(f"related infra {asn}: {e}")
    return out[:20]


def build_phase3(provider_results, anomalies, asn_numbers):
    cfg = CFG.get("phase_p3", {})
    if not cfg.get("enabled", True): return {"enabled": False}
    r = {"enabled": True}
    if cfg.get("mitre_mapping", True):
        r["mitre"] = map_to_attack(None, provider_results, anomalies)
    if cfg.get("actor_attribution", True):
        r["actors"] = attribute_threat_actors(provider_results)
    if cfg.get("related_infra", True):
        r["related_infra"] = discover_related_infra(asn_numbers)
    return r


class PassiveOSINT:
    @staticmethod
    def hackertarget_reverse_ip(ip):
        try:
            r = http.s.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                           timeout=(3, 8))
            if r.status_code != 200: return []
            t = r.text.strip()
            if "error" in t.lower() or "exceeded" in t.lower() or not t:
                return []
            return [ln.strip() for ln in t.splitlines() if ln.strip()][:50]
        except Exception:
            return []

    @staticmethod
    def otx_passive_dns(ip):
        try:
            r = http.s.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns",
                timeout=(3, 8))
            if r.status_code != 200: return []
            d = r.json() or {}
            return [{"hostname": row.get("hostname"),
                     "first": row.get("first"),
                     "last": row.get("last"),
                     "record_type": row.get("record_type")}
                    for row in (d.get("passive_dns") or [])[:50]]
        except Exception:
            return []

    @staticmethod
    def internetdb(ip):
        try:
            r = http.s.get(f"https://internetdb.shodan.io/{ip}", timeout=(3, 6))
            if r.status_code != 200: return {}
            return r.json() or {}
        except Exception:
            return {}

    @staticmethod
    def host_search(domain):
        try:
            r = http.s.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                           timeout=(3, 8))
            if r.status_code != 200: return []
            t = r.text.strip()
            if "error" in t.lower() or "exceeded" in t.lower() or not t:
                return []
            out = []
            for ln in t.splitlines():
                if "," in ln:
                    h, ip = ln.split(",", 1)
                    out.append({"host": h.strip(), "ip": ip.strip()})
            return out[:100]
        except Exception:
            return []

# ============================================================
#  PARALLEL COLLECTION
# ============================================================
async def _thread(fn, *args):
    return await asyncio.get_event_loop().run_in_executor(None, fn, *args)

def collect_parallel(ip, domain=None):
    async def _run():
        tasks = {
            "geo": _thread(collect_geo, ip),
            "asn": _thread(collect_asn, ip),
            "rdap": _thread(collect_rdap, ip),
            "dns": _thread(collect_dns, ip, domain),
            "cert": _thread(collect_certs, domain or ip),
            "threat": _thread(collect_threat, ip),
        }
        res = await asyncio.gather(*tasks.values(), return_exceptions=True)
        return dict(zip(tasks.keys(), res))
    try: return asyncio.run(_run())
    except Exception as e:
        log.error(f"parallel: {e}"); return {}

# ============================================================
#  HELPERS
# ============================================================
def module_status(att, resp):
    if att == 0: return MS.SKIPPED.value
    if resp == 0: return MS.FAILED.value
    if resp < att: return MS.PARTIAL.value
    return MS.SUCCESS.value

def agg_scan_status(ms):
    vals = [v for v in ms.values() if v != MS.SKIPPED.value]
    if not vals: return MS.SKIPPED.value
    s = sum(1 for v in vals if v == MS.SUCCESS.value)
    f = sum(1 for v in vals if v == MS.FAILED.value)
    if s == len(vals): return MS.SUCCESS.value
    if f == len(vals): return MS.FAILED.value
    return MS.PARTIAL.value

def weighted_agreement(vals):
    b = {}; tot = 0.0
    for v, w in vals:
        b[v] = b.get(v, 0) + w; tot += w
    if not b: return None, 0.0
    best = max(b, key=b.get)
    return best, round(b[best] / tot * 100, 1)

def validate_field(field, evs):
    if not evs:
        return TF(field=field, value=None, confidence=0.0, evidence_ids=[],
                  providers=[], reason="No evidence", status="INSUFFICIENT")
    if field == "country":
        vals = [(_normalize_country(e.value), e.weight) for e in evs]
    elif field == "country_code":
        vals = [(str(e.value).strip().upper(), e.weight) for e in evs]
    elif field == "organization":
        # v21.14: clean org names before agreement check
        vals = [(_clean_org(e.value), e.weight) for e in evs]
    else:
        vals = [(e.value, e.weight) for e in evs]
    provs = sorted({e.provider for e in evs})
    eids = [e.id for e in evs]
    best, agr = weighted_agreement(vals)
    min_src = CFG["validation"]["min_sources_for_trusted"]
    min_agr = CFG["validation"]["min_agreement_for_trusted"]
    if field in ("asn", "prefix", "rir"): min_src = 1
    if field in ("country_code", "timezone", "region", "city"): min_src = 1
    if field == "organization" and any(p in provs for p in
                                        ("ripe", "rdap", "maxmind_local",
                                         "bgpview", "whois")):
        min_src = 1
    if len(provs) < min_src:
        return TF(field=field, value=best, confidence=round(agr, 1),
                  evidence_ids=eids, providers=provs,
                  reason=f"{len(provs)} provider(s)", status="INSUFFICIENT")
    SOFT = {"timezone", "organization", "isp", "city", "region"}
    if field in SOFT and agr < min_agr:
        reduced = round(agr * 0.75, 1)
        return TF(field=field, value=best, confidence=reduced,
                  evidence_ids=eids, providers=provs,
                  reason=f"soft: {agr}% agreement, best-value chosen",
                  status="APPROXIMATE")
    if agr < min_agr:
        return TF(field=field, value=None, confidence=round(agr, 1),
                  evidence_ids=eids, providers=provs,
                  reason=f"agreement {agr}%", status="UNRELIABLE")
    return TF(field=field, value=best, confidence=round(agr, 1),
              evidence_ids=eids, providers=provs,
              reason=f"{len(provs)} providers, {agr}%", status="TRUSTED")


def coord_conflict(ge):
    lat = [(e.value, e.provider, e.id) for e in ge
           if e.field == "latitude" and e.value is not None]
    lon = [(e.value, e.provider, e.id) for e in ge
           if e.field == "longitude" and e.value is not None]
    by = {}
    for v, p, eid in lat: by.setdefault(p, {})["lat"] = (v, eid)
    for v, p, eid in lon: by.setdefault(p, {})["lon"] = (v, eid)
    pairs = [(p, d["lat"][0], d["lon"][0], d["lat"][1], d["lon"][1])
             for p, d in by.items() if "lat" in d and "lon" in d]
    if len(pairs) < 2: return None
    mx, wr = 0.0, None
    for i in range(len(pairs)):
        for j in range(i+1, len(pairs)):
            dd = hav(pairs[i][1], pairs[i][2], pairs[j][1], pairs[j][2])
            if dd > mx: mx, wr = dd, (pairs[i], pairs[j])
    if not wr: return None
    km = CFG["validation"]["geo_conflict_km"]
    if mx < km["low"]: return None
    if mx >= km["high"]: sev, imp = SEV.HIGH.value, 1.0
    elif mx >= km["moderate"]: sev, imp = SEV.MODERATE.value, 0.6
    else: sev, imp = SEV.LOW.value, 0.25
    a, b = wr
    return CFL(field="coordinates", severity=sev,
               description=f"Max distance {round(mx,1)} km",
               sources=[a[0], b[0]],
               observations=[{"provider": a[0], "lat": a[1], "lon": a[2],
                              "evidence_id": a[3]},
                             {"provider": b[0], "lat": b[1], "lon": b[2],
                              "evidence_id": b[3]}],
               resolution="weighted-median" if sev == SEV.HIGH.value else "unreliable",
               confidence_impact=imp, distance_km=round(mx, 1))

def field_conflict(field, evs):
    provs = {e.provider for e in evs}
    if field == "country":
        canon = {_normalize_country(e.value) for e in evs}
    elif field == "country_code":
        canon = {str(e.value).strip().upper() for e in evs}
    elif field == "organization":
        # v21.10: broader canon — first 6 alnum chars as identity
        def _o(x):
            s2 = re.sub(r"^AS\d+\s+", "", str(x))
            s2 = re.sub(r"[^a-z0-9]+", "", s2.lower())
            return s2[:6] if s2 else ""
        canon = {_o(e.value) for e in evs if e.value}
        # If all canon values share a common prefix -> not a real conflict
        if len(canon) > 1:
            prefix = canon.pop() if canon else ""
            while prefix and not all(c.startswith(prefix) for c in canon):
                prefix = prefix[:-1]
            if prefix and len(prefix) >= 3:
                return None  # Same org, just naming variation
            canon.add(prefix)
    else:
        canon = {str(e.value).strip() for e in evs}
    canon.discard("")
    if len(provs) < 2 or len(canon) < 2: return None
    sev = SEV.MODERATE.value if len(canon) > 2 else SEV.LOW.value
    imp = 0.5 if sev == SEV.MODERATE.value else 0.2
    return CFL(field=field, severity=sev,
               description=f"Providers disagree: {sorted(canon)}",
               sources=sorted(provs),
               observations=[{"provider": e.provider, "value": e.value,
                              "evidence_id": e.id} for e in evs],
               resolution="unreliable", confidence_impact=imp)


def detect_conflicts(data):
    """
    Detect conflicts between data sources (B7 fix).
    Currently: Anycast vs Geolocation.
    """
    conflicts = []
    if data.get('anycast') is True:
        geo = data.get('geolocation', {}) or data.get('geo', {})
        # Also handle flat geo fields
        if not geo:
            # Try to build geo from trusted or ev values
            geo = {}
            for k in ("country", "city", "country_code"):
                if data.get(k):
                    geo[k] = data.get(k)
        if geo.get('country') or geo.get('city') or geo.get('country_code'):
            conflicts.append(CFL(
                field="anycast_geo",
                severity="INFORMATIONAL",
                description="Anycast IP: geolocation is approximate and may not reflect actual server location.",
                sources=["anycast", "geo"],
                observations=[{"type": "anycast_geo", "geo": geo}],
                resolution="informational",
                confidence_impact=0.0
            ))
    return conflicts

def conflict_report(evs, anycast=False):
    cs = []
    ge = [e for e in evs if e.data_type == "geo"]
    # v21.7: anycast IPs inherently have multi-city geo → skip city/coord conflicts (but add informational conflict via detect_conflicts)
    if not anycast:
        c = coord_conflict(ge)
        if c: cs.append(c)
    for f in ("country", "country_code", "organization", "isp"):
        c = field_conflict(f, [e for e in ge if e.field == f])
        if c: cs.append(c)
    if not anycast:
        c = field_conflict("city", [e for e in ge if e.field == "city"])
        if c: cs.append(c)
    c = field_conflict("asn", [e for e in ge if e.field == "asn"])
    if c: cs.append(c)
    for f in ("asn", "organization", "prefix", "rir"):
        c = field_conflict(f, [e for e in evs if e.data_type == "asn" and e.field == f])
        if c: cs.append(c)
    # B7 fix: Detect Anycast vs Geolocation conflict
    if anycast:
        ge_fields = {e.field: e.value for e in ge if e.value}
        if ge_fields.get("country") or ge_fields.get("city") or ge_fields.get("country_code"):
            cs.append(CFL(
                field="anycast_geo",
                severity="INFORMATIONAL",
                description="Anycast IP: geolocation is approximate and may not reflect actual server location.",
                sources=["anycast", "geo"],
                observations=[{"geo": ge_fields, "anycast": True}],
                resolution="informational",
                confidence_impact=0.0
            ))
    return cs

def field_conf(tf, cs, anycast, is_coord=False):
    if tf.status not in ("TRUSTED", "APPROXIMATE"):
        return 0.0
    base = tf.confidence
    if tf.status == "APPROXIMATE" and base < 20.0:
        base = 20.0
    imp = 0.0
    for c in cs:
        if c.field == tf.field or (is_coord and c.field == "coordinates"):
            imp = max(imp, c.confidence_impact)
    base *= max(0.0, 1.0 - imp)
    if anycast and tf.field in ("country", "country_code", "city",
                                 "latitude", "longitude"):
        base *= 0.75
    if tf.status == "APPROXIMATE":
        base = max(20.0, base)
    return round(min(100, base), 1)


def _weighted_median(values_with_weights):
    if not values_with_weights: return None
    vals = sorted(values_with_weights, key=lambda x: x[0])
    total = sum(w for _, w in vals)
    if total <= 0: return None
    half = total / 2.0
    cum = 0.0
    for v, w in vals:
        cum += w
        if cum >= half: return v
    return vals[-1][0]

def _coord_precision_km(values):
    if len(values) < 2: return None
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    std = var ** 0.5
    return round(std * 111.0, 1)

def resolve_coordinate(evs, field, anycast):
    cands = [e for e in evs if e.data_type == "geo" and e.field == field
             and e.value is not None]
    if not cands: return None, None, []
    by_prov = {}
    for e in evs:
        if e.data_type != "geo": continue
        if e.field not in ("latitude", "longitude"): continue
        if e.value is None: continue
        by_prov.setdefault(e.provider, {})[e.field] = float(e.value)
    provs = [(p, d["latitude"], d["longitude"],
              next(e.reliability * e.weight for e in cands
                   if e.provider == p and e.field == field))
             for p, d in by_prov.items()
             if "latitude" in d and "longitude" in d]
    if len(provs) >= 2:
        clusters = []
        for p, la, lo, w in provs:
            placed = False
            for cl in clusters:
                cx, cy = cl["centroid"]
                if hav(la, lo, cx, cy) < 500:
                    cl["points"].append((la, lo, w, p))
                    n = len(cl["points"])
                    cl["centroid"] = (sum(x[0] for x in cl["points"])/n,
                                      sum(x[1] for x in cl["points"])/n)
                    placed = True
                    break
            if not placed:
                clusters.append({"centroid": (la, lo),
                                 "points": [(la, lo, w, p)]})
        best = max(clusters, key=lambda c: sum(x[2] for x in c["points"]))
        vw = [(pt[0] if field == "latitude" else pt[1], pt[2])
              for pt in best["points"]]
        eids = [e.id for e in cands
                if e.provider in {pt[3] for pt in best["points"]}]
    else:
        vw = [(float(e.value), e.reliability * e.weight) for e in cands]
        eids = [e.id for e in cands]
    median = _weighted_median(vw)
    if median is None: return None, None, []
    precision = _coord_precision_km([v for v, _ in vw])
    if anycast and precision is not None:
        precision = max(precision, 250.0)
    return round(median, 6), precision, eids

def build_trusted(evs, cs, anycast):
    fields = [("country", "geo"), ("country_code", "geo"), ("region", "geo"),
              ("city", "geo"), ("latitude", "geo"), ("longitude", "geo"),
              ("timezone", "geo"), ("isp", "geo"), ("organization", "geo"),
              ("asn", "geo"), ("PTR", "dns"), ("abuse_email", "rdap"),
              ("country_rdap", "rdap"), ("abuse_score", "threat"),
              ("current_fingerprint", "cert"), ("current_status", "cert")]
    out = {}
    for f, dt in fields:
        cands = [e for e in evs if e.data_type == dt and e.field == f]
        tf = validate_field(f, cands)
        is_coord = f in ("latitude", "longitude")
        tf.confidence = field_conf(tf, cs, anycast, is_coord)
        if is_coord:
            median, precision, eids = resolve_coordinate(evs, f, anycast)
            if median is not None:
                tf.value = median
                base_conf = tf.confidence if tf.confidence > 0 else 20.0
                if precision is not None and precision > 50:
                    tf.reason = f"weighted-median +/-{precision:.0f}km | " + tf.reason
                    base_conf = max(20.0, base_conf * 0.85)
                if anycast:
                    tf.reason = "anycast:geo approx | " + tf.reason
                    base_conf = min(base_conf, 45.0)
                tf.confidence = round(base_conf, 1)
                tf.status = "TRUSTED" if tf.confidence >= 40 else "APPROXIMATE"
                if eids: tf.evidence_ids = eids
        if anycast and f == "city" and tf.status == "TRUSTED" and tf.value:
            tf.status = "APPROXIMATE"
            tf.confidence = min(tf.confidence, 25.0)
            tf.reason = "anycast:city may vary | " + tf.reason
        out[f] = tf
    return out


# ============================================================
#  PHASE B — SCORING
# ============================================================
@dataclass
class SF:
    name: str
    contribution: float
    detail: str = ""

@dataclass
class SD:
    score: float
    classification: str
    factors: List[SF]
    raw: Dict = field(default_factory=dict)

def threat_score(evs, phase_i=None):
    if phase_i and phase_i.get("positive", 0) > 0:
        f = [SF("phase_i_aggregate", phase_i["score"], phase_i["explanation"])]
        for p in phase_i.get("providers", []):
            if p.get("status") == TS2.POSITIVE:
                f.append(SF(f"provider:{p['provider']}",
                            float(p.get("score") or 0) * float(p.get("weight", 1)),
                            f"reports={p.get('reports',0)} conf={p.get('confidence',0)}"))
        return SD(phase_i["score"], phase_i["classification"], f, {"phase_i": phase_i})
    w = PB["threat_score"]["weights"]; th = PB["threat_score"]["thresholds"]
    f = []; pt = {}
    for e in evs:
        if e.field == "provider_score":
            pt.setdefault("malicious_reputation", []).append(float(e.value or 0))
        elif e.field in ("malware_association", "phishing", "botnet") and \
                (e.value is True or e.value == "True"):
            pt.setdefault(e.field, []).append(100.0)
        elif e.field == "abuse_score":
            pt.setdefault("abuse_report", []).append(float(e.value or 0))
    tot = 0.0
    for it, sevs in pt.items():
        ww = w.get(it, 5); s = max(sevs); c = ww * (s / 100); tot += c
        f.append(SF(it, round(c, 1), f"max {round(s,1)} x {ww}"))
    sc = round(min(100, tot), 1)
    if sc < th["no_evidence"]: cls = "No Significant Threat Evidence"
    elif sc < th["low"]: cls = "Low Threat Evidence"
    elif sc < th["moderate"]: cls = "Moderate Threat Evidence"
    elif sc < th["high"]: cls = "High Threat Evidence"
    else: cls = "Critical Threat Evidence"
    if not f: f.append(SF("no_threat_signals", 0.0, "no indicators"))
    return SD(sc, cls, f, {"per_type": pt})

def infra_risk(ip, trusted, evs):
    chars = []; w = PB["infrastructure_risk"]["weights"]
    if ip in CFG["geo_validation"]["anycast_ips"]:
        chars.append(("anycast", "known anycast IP"))
    org = str((trusted.get("organization") or TF("", None, 0, [], [], "")).value or "").lower()
    isp = str((trusted.get("isp") or TF("", None, 0, [], [], "")).value or "").lower()
    hay = f"{org} {isp}"
    kws = {"tor_exit": ["tor"], "vpn": ["vpn"], "proxy": ["proxy"],
           "cloud": ["cloud", "aws", "amazon", "azure", "gcp",
                     "digitalocean", "linode", "vultr", "oracle"],
           "hosting": ["hosting"], "datacenter": ["datacenter", "colo"],
           "shared_hosting": ["shared hosting"],
           "cdn": ["cdn", "cloudflare", "akamai", "fastly"],
           "residential": ["residential", "dsl", "cable", "fiber", "broadband"],
           "carrier_nat": ["carrier", "carrier-grade"]}
    for c, ks in kws.items():
        for k in ks:
            if k in hay: chars.append((c, f"'{k}' in org/ISP")); break
    if ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"):
        chars.append(("public_dns", f"{ip} is a public DNS resolver"))
    f = []; tot = 0.0; seen = set()
    for c, n in chars:
        if c in seen: continue
        seen.add(c); ww = w.get(c, 0); tot += ww
        f.append(SF(c, ww, n))
    sc = round(min(100, tot), 1)
    if not f: f.append(SF("no_infra_indicators", 0.0, ""))
    return SD(sc, f"{sc}/100 infrastructure risk", f, {})

def data_confidence(evs, trusted, cs, _ps):
    w = PB["data_confidence"]["weights"]; pen = PB["data_confidence"]["conflict_penalty"]
    f = []
    avg_rel = sum(e.reliability for e in evs) / len(evs) if evs else 0
    rc = avg_rel * 100 * w["reliability"]
    tf = [t for t in trusted.values() if t.status == "TRUSTED"]
    agr = (sum(t.confidence for t in tf) / len(tf)) if tf else 0
    ac = agr * w["agreement"]
    tot_f = len(trusted)
    we = sum(1 for t in trusted.values() if t.status != "INSUFFICIENT")
    comp = (we / tot_f * 100) if tot_f else 0
    cc = comp * w["completeness"]
    if evs:
        fw = {FR.FRESH.value: 1.0, FR.RECENT.value: 0.9, FR.AGING.value: 0.7,
              FR.STALE.value: 0.4, FR.UNKNOWN.value: 0.5}
        avg_f = sum(fw.get(e.freshness, 0.5) for e in evs) / len(evs)
    else: avg_f = 0
    fc = avg_f * 100 * w["freshness"]
    val = (len(tf) / tot_f * 100) if tot_f else 0
    vc = val * w["validation"]
    base = rc + ac + cc + fc + vc
    cp = 0.0
    for c in cs:
        p = pen.get(c.severity.lower(), 0); cp += p
        f.append(SF(f"conflict_{c.field}", -p, f"{c.severity} conflict"))
    sc = round(max(0, min(100, base - cp)), 1)
    return SD(sc, f"{sc}% data confidence", f, {"conflict_penalty": cp})

def coverage(ps, phase_i=None):
    if phase_i is not None:
        cov = float(phase_i.get("coverage", 0))
        if cov >= 90: cls = "Excellent Coverage"
        elif cov >= 70: cls = "Good Coverage"
        elif cov >= 40: cls = "Partial Coverage"
        elif cov >= 20: cls = "Limited Coverage"
        else: cls = "Insufficient Coverage"
        provs = phase_i.get("providers", [])
        return {"coverage": cov, "classification": cls, "intended": len(provs),
                "configured": sum(1 for p in provs
                                   if p["status"] != TS.NOT_CONFIGURED.value),
                "available": phase_i.get("positive", 0) + phase_i.get("negative", 0),
                "successful": phase_i.get("positive", 0) + phase_i.get("negative", 0),
                "failed": phase_i.get("error", 0),
                "not_configured": phase_i.get("not_configured", 0),
                "rate_limited": phase_i.get("rate_limited", 0),
                "no_data": phase_i.get("no_data", 0)}
    return {"coverage": 0, "classification": "Insufficient Coverage", "intended": 0,
            "configured": 0, "available": 0, "successful": 0, "failed": 0,
            "not_configured": 0, "rate_limited": 0, "no_data": 0}

def evidence_quality(evs, cs):
    w = PB["evidence_quality"]["weights"]
    if not evs: return SD(0, "No evidence", [SF("no_evidence", 0)])
    ar = sum(e.reliability for e in evs) / len(evs)
    provs = {e.provider for e in evs}; ind = min(1, len(provs) / 5)
    fw = {FR.FRESH.value: 1, FR.RECENT.value: 0.9, FR.AGING.value: 0.7,
          FR.STALE.value: 0.4, FR.UNKNOWN.value: 0.5}
    af = sum(fw.get(e.freshness, 0.5) for e in evs) / len(evs)
    cf = {c.field for c in cs}; af2 = {e.field for e in evs}
    cons = 1 - (len(cf & af2) / max(1, len(af2)))
    spec = sum(1 for e in evs if e.value not in (None, "", [], {})) / len(evs)
    rc = ar * 100 * w["reliability"]; ic = ind * 100 * w["independence"]
    fc = af * 100 * w["freshness"]; cc = cons * 100 * w["consistency"]
    sc = spec * 100 * w["specificity"]
    total = round(min(100, rc + ic + fc + cc + sc), 1)
    return SD(total, f"{total}% evidence quality", [], {})

def assess_confidence(threat, infra, dc, cov, eq, cs):
    g = PB["assessment_confidence"]["guardrails"]; r = []; h = True
    if cov["coverage"] < g["min_coverage_for_high"]:
        h = False; r.append(f"coverage {cov['coverage']}%")
    if dc.score < g["min_data_confidence_for_high"]:
        h = False; r.append(f"data_conf {dc.score}%")
    if sum(1 for c in cs if c.severity == SEV.HIGH.value) > g["max_high_conflicts"]:
        h = False; r.append("HIGH conflicts")
    if sum(1 for c in cs if c.severity == SEV.MODERATE.value) > g["max_moderate_conflicts"]:
        h = False; r.append("MOD conflicts")
    if cov["intended"] > 0 and cov["successful"] < g["min_successful_providers"]:
        h = False; r.append("few providers")
    if eq.score < g["min_evidence_quality_for_high"]:
        h = False; r.append("low evidence quality")
    if h: lbl = "High"
    elif cov["coverage"] >= g["min_coverage_for_moderate"] and dc.score >= 40:
        lbl = "Moderate"
    else: lbl = "Low"
    if not r: r.append("All guardrails satisfied")
    return {"label": lbl, "reasons": r}

def final_assess(threat, infra, dc, cov, ac, cs, anycast):
    lv = PB["classification"]["concern_levels"]
    ts = threat.score; cov_pct = cov["coverage"]
    dcs = dc.score; cl = ac["label"]
    reasons = []; limits = []
    if ts >= lv["critical"]: base = "Critical concern"
    elif ts >= lv["high"]: base = "High concern"
    elif ts >= lv["moderate"]: base = "Moderate concern"
    elif ts >= lv["low"]: base = "Low concern"
    else: base = "No significant threat evidence detected"
    if cov_pct < 40 and cl == "High":
        cl = "Moderate"; reasons.append("downgraded: coverage < 40%")
    if cov_pct < 40 and base == "No significant threat evidence detected":
        base = "Insufficient evidence"; reasons.append("Insufficient evidence")
    if any(c.field == "coordinates" and c.severity == SEV.HIGH.value for c in cs):
        limits.append("Geographic coordinates approximate (weighted median)")
    if anycast: limits.append("Anycast - geolocation approximate")
    if cov.get("not_configured", 0) > 0:
        limits.append(f"{cov['not_configured']} providers not configured")
    if cov.get("failed", 0) > 0:
        limits.append(f"{cov['failed']} providers failed")
    reasons += [f"threat={ts}", f"coverage={cov_pct}%",
                f"data_conf={dcs}%", f"assessment_conf={cl}"]
    if base == "Critical concern":
        rec = "Immediate investigation and block pending verification"
    elif base == "High concern":
        rec = "Investigate and correlate with internal telemetry"
    elif base == "Moderate concern":
        rec = "Review logs and corroborate"
    elif base == "Low concern":
        rec = "Monitor"
    elif base == "No significant threat evidence detected":
        rec = "Continue routine monitoring; not a formal 'safe' verdict"
    else:
        rec = "Collect additional intelligence"
    return {"assessment": base, "confidence": cl, "reasons": reasons,
            "limitations": limits, "recommendation": rec}

# ============================================================
#  PHASE G — NETWORK INTELLIGENCE
# ============================================================
def dns_evs(evs, field=None, direction=None, name=None):
    out = []
    for e in evs:
        if e.data_type != "dns": continue
        if field is not None and e.field != field: continue
        rv = e.raw_value or {}
        if direction is not None and rv.get("direction") != direction: continue
        if name is not None and rv.get("name") != name: continue
        out.append(e)
    return out

def anomaly_conf(ids):
    if not ids: return 0.0
    return round(min(95, 60 + 10 * (len(ids) - 1)), 1)

def detect_anomalies(ip, domain, evs):
    a = []; sm = PG["anomaly_severity"]
    ptrs = dns_evs(evs, field="PTR", direction="reverse")
    hosts = sorted({e.value for e in ptrs})
    peids = defaultdict(list)
    for e in ptrs: peids[e.value].append(e.id)
    fwd = [e for e in evs if e.data_type == "dns" and e.field in ("A", "AAAA")
           and (e.raw_value or {}).get("direction") == "forward_from_ptr"]
    fbyhost = defaultdict(list)
    for e in fwd:
        h = (e.raw_value or {}).get("name")
        if h: fbyhost[h].append((e.value, e.id))
    for h in hosts:
        fw = fbyhost.get(h, []); fips = sorted({v for v, _ in fw})
        if fips and ip not in fips:
            ids = [eid_ for _, eid_ in fw] + peids[h]
            a.append({"type": "forward_reverse_mismatch",
                      "severity": sm.get("forward_reverse_mismatch", "moderate"),
                      "description": f"PTR {h} doesn't forward to {ip}",
                      "confidence": anomaly_conf(ids),
                      "evidence_ids": ids, "sources": ["dns"]})
        elif not fips:
            ids = peids[h]
            a.append({"type": "ptr_without_forward",
                      "severity": sm.get("ptr_without_forward", "low"),
                      "description": f"PTR {h} has no forward",
                      "confidence": anomaly_conf(ids),
                      "evidence_ids": ids, "sources": ["dns"]})
    if len(hosts) > 1:
        ids = [eid_ for h in hosts for eid_ in peids[h]]
        a.append({"type": "multiple_ptrs",
                  "severity": sm.get("multiple_ptrs", "low"),
                  "description": f"{len(hosts)} hostnames",
                  "confidence": anomaly_conf(ids),
                  "evidence_ids": ids, "sources": ["dns"]})
    asn_v = defaultdict(list)
    for e in evs:
        if e.data_type == "asn" and e.field == "asn": asn_v[e.value].append(e.id)
    if len(asn_v) > 1:
        ids = [eid_ for v in asn_v.values() for eid_ in v]
        a.append({"type": "asn_inconsistency",
                  "severity": sm.get("asn_inconsistency", "moderate"),
                  "description": f"ASNs: {sorted(asn_v.keys())}",
                  "confidence": anomaly_conf(ids),
                  "evidence_ids": ids, "sources": ["asn"]})
    # v21.14: org comparison uses cleaned + first-word-of-core identity
    org_v = defaultdict(list)
    for e in evs:
        if e.field == "organization" and e.data_type in ("asn", "geo"):
            cleaned = _clean_org(e.value)
            # v21.15: use FIRST WORD only — robust to "Google LLC" vs "Google Public DNS"
            core = re.split(r"[\s,\-]+", cleaned.strip())[0].lower()
            core = re.sub(r"[^a-z0-9]+", "", core)
            if core and len(core) >= 3:
                org_v[core].append(e.id)
    if len(org_v) > 1:
        ids = [eid_ for v in org_v.values() for eid_ in v]
        a.append({"type": "organization_inconsistency",
                  "severity": sm.get("organization_inconsistency", "low"),
                  "description": f"Orgs: {sorted(org_v.keys())}",
                  "confidence": anomaly_conf(ids),
                  "evidence_ids": ids, "sources": ["asn", "geo"]})
    return a


def sev_summary(a):
    out = {"informational": 0, "low": 0, "moderate": 0, "high": 0}
    for x in a:
        s = x.get("severity", "informational")
        out[s] = out.get(s, 0) + 1
    return out

def network_intel(ip, domain, evs, trusted, cert_ci=None):
    # v21.10: robust RIR derivation (RDAP + WHOIS + geo country_code)
    rirs = sorted({e.value for e in evs
                   if e.data_type == "asn" and e.field == "rir" and e.value})
    if not rirs:
        countries = set()
        for e in evs:
            if e.value and isinstance(e.value, str):
                if e.data_type == "rdap" and e.field == "country_rdap":
                    countries.add(e.value.upper()[:2])
                elif e.data_type == "asn" and e.field == "country":
                    countries.add(e.value.upper()[:2])
                elif e.data_type == "geo" and e.field == "country_code":
                    countries.add(e.value.upper()[:2])
        rir_map = {"US": "ARIN", "CA": "ARIN",
                   "GB": "RIPE NCC", "DE": "RIPE NCC", "FR": "RIPE NCC",
                   "NL": "RIPE NCC", "IT": "RIPE NCC", "ES": "RIPE NCC",
                   "RU": "RIPE NCC", "PL": "RIPE NCC", "SE": "RIPE NCC",
                   "JP": "APNIC", "CN": "APNIC", "AU": "APNIC",
                   "IN": "APNIC", "KR": "APNIC", "SG": "APNIC",
                   "BR": "LACNIC", "AR": "LACNIC", "MX": "LACNIC"}
        for c in countries:
            rir = rir_map.get(c)
            if rir: rirs.append(rir)
        rirs = sorted(set(rirs))
    asn_data = {
        "numbers": sorted({e.value for e in evs
                            if e.data_type == "asn" and e.field == "asn"}),
        "prefixes": sorted({e.value for e in evs
                             if e.data_type == "asn" and e.field == "prefix"}),
        "rirs": rirs,
        "orgs": sorted({e.value for e in evs
                         if e.data_type == "asn" and e.field == "organization"}),
    }
    dns_recs = {}
    for rt in PG["dns"]["record_types"]:
        dns_recs[rt] = sorted({e.value for e in evs
                                if e.data_type == "dns" and e.field == rt})
    ptrs = [e for e in evs if e.data_type == "dns" and e.field == "PTR"
            and (e.raw_value or {}).get("direction") == "reverse"]
    hosts = sorted({e.value for e in ptrs})
    cons = []
    for h in hosts:
        fwd = [e.value for e in evs if e.data_type == "dns"
               and e.field in ("A", "AAAA")
               and (e.raw_value or {}).get("name") == h
               and (e.raw_value or {}).get("direction") == "forward_from_ptr"]
        if fwd:
            cons.append({"ptr": h, "forward_ips": sorted(set(fwd)),
                         "forward_includes_target": ip in fwd,
                         "status": "consistent" if ip in fwd else "mismatch"})
    anomalies = detect_anomalies(ip, domain, evs)
    if cert_ci:
        for r in cert_ci["records"].values():
            if r.status == "CURRENT":
                if r.is_expired:
                    anomalies.append({"type": "certificate_expired",
                                      "severity": "moderate",
                                      "description": f"Expired cert ({r.valid_to})",
                                      "confidence": 95.0,
                                      "evidence_ids": r.ev_ids,
                                      "sources": r.sources})
                if r.is_near:
                    anomalies.append({"type": "certificate_near_expiry",
                                      "severity": "low",
                                      "description": f"Cert expires in {r.days_left}d",
                                      "confidence": 90.0,
                                      "evidence_ids": r.ev_ids,
                                      "sources": r.sources})
                if r.weak:
                    anomalies.append({"type": "certificate_weak_algorithms",
                                      "severity": "moderate",
                                      "description": f"Weak crypto: {', '.join(r.weak)}",
                                      "confidence": 90.0,
                                      "evidence_ids": r.ev_ids,
                                      "sources": r.sources})
    return {"asn": asn_data, "dns_records": dns_recs, "dns_consistency": cons,
            "anomalies": anomalies, "anomaly_count": len(anomalies),
            "severity_summary": sev_summary(anomalies),
            "note": "Anomalies reflect observations, not threats."}


# ============================================================
#  PHASE C — ENTITIES + RELATIONSHIPS
# ============================================================
@dataclass
class Ent:
    id: str
    type: str
    value: str
    sources: List[str] = field(default_factory=list)

@dataclass
class Rel:
    from_e: str
    to_e: str
    rel: str
    sources: List[str] = field(default_factory=list)
    confidence: float = 0.0
    reason: str = ""

def norm_val(etype, v):
    if v is None: return None
    s = str(v).strip()
    if not s: return None
    if etype == ET.IP.value:
        try: return str(ipaddress.ip_address(s))
        except: return None
    if etype == ET.CIDR.value:
        try: return str(ipaddress.ip_network(s, strict=False))
        except: return None
    if etype == ET.ASN.value:
        m = re.search(r"AS?\s*(\d+)", s.upper())
        return f"AS{m.group(1)}" if m else None
    if etype in (ET.ORG.value, ET.ISP.value):
        return re.sub(r"\s+", " ", s)
    return s

def build_entities(evs, target):
    ents = {}
    def ensure(t, v, prov="", eid_=""):
        c = norm_val(t, v)
        if not c: return None
        k = f"{t}:{c}"
        if k not in ents: ents[k] = Ent(id=k, type=t, value=c)
        if prov and prov not in ents[k].sources: ents[k].sources.append(prov)
        return k
    ensure(ET.IP.value, target, "target")
    for e in evs:
        if e.data_type == "asn":
            if e.field == "asn": ensure(ET.ASN.value, e.value, e.provider, e.id)
            elif e.field == "organization": ensure(ET.ORG.value, e.value, e.provider, e.id)
            elif e.field == "prefix": ensure(ET.CIDR.value, e.value, e.provider, e.id)
        elif e.data_type == "geo":
            if e.field == "asn": ensure(ET.ASN.value, e.value, e.provider, e.id)
            elif e.field == "organization": ensure(ET.ORG.value, e.value, e.provider, e.id)
            elif e.field == "isp": ensure(ET.ISP.value, e.value, e.provider, e.id)
        elif e.data_type == "dns":
            if e.field == "PTR": ensure("Hostname", e.value, e.provider, e.id)
            elif e.field == "NS": ensure("Nameserver", e.value, e.provider, e.id)
            elif e.field == "MX": ensure("MX", e.value, e.provider, e.id)
    return ents

def build_rels(ents, evs, target):
    rels = []
    def add(f, t, r, prov, reason):
        if not f or not t or f == t: return
        for x in rels:
            if x.from_e == f and x.to_e == t and x.rel == r:
                if prov and prov not in x.sources: x.sources.append(prov)
                x.confidence = min(100, 40 + len(x.sources) * 20)
                return
        rels.append(Rel(f, t, r, [prov] if prov else [], 40 + 20 if prov else 40, reason))
    ip_id = f"{ET.IP.value}:{target}"
    for e in evs:
        if e.field == "asn":
            k = norm_val(ET.ASN.value, e.value)
            if k: add(ip_id, f"{ET.ASN.value}:{k}", "BELONGS_TO", e.provider, "ASN")
        elif e.field == "organization":
            k = norm_val(ET.ORG.value, e.value)
            if k: add(ip_id, f"{ET.ORG.value}:{k}", "OPERATED_BY", e.provider, "Org")
        elif e.field == "isp":
            k = norm_val(ET.ISP.value, e.value)
            if k: add(ip_id, f"{ET.ISP.value}:{k}", "PROVIDED_BY", e.provider, "ISP")
        elif e.data_type == "dns" and e.field == "PTR":
            k = norm_val("Hostname", e.value)
            if k: add(ip_id, f"Hostname:{k}", "RESOLVES_TO", e.provider, "PTR")
    return rels

# ============================================================
#  PHASE J — TIMELINE
# ============================================================
def extract_state(result):
    st = {}
    for e in result.get("evidence", []):
        v = e.get("value")
        if v in (None, "", [], {}): continue
        dt, f = e.get("data_type"), e.get("field")
        if dt == "dns": st[("dns", f)] = v
        elif dt == "asn" and f in ("asn", "organization", "prefix", "rir"):
            st[("asn", f)] = v
        elif dt == "geo" and f in ("country", "country_code", "city"):
            st[("geo", f)] = v
        elif dt == "cert" and f == "current_fingerprint":
            st[("cert", f)] = v
    pi = result.get("phase_i", {}) or {}
    for p in pi.get("providers", []):
        st[("threat", p.get("provider", "unknown"))] = p.get("status", "NO_DATA")
    pb = result.get("phase_b", {}) or {}
    th = pb.get("threat", {}) or {}
    if "score" in th:
        st[("risk", "threat_score")] = str(th.get("score", 0))
    return st

def classify_change(field, subfield, old_v, new_v, _prev, cur):
    if field == "cert" and subfield == "current_fingerprint":
        po = _prev.get(("cert", "issuer"))
        co = cur.get(("cert", "issuer"))
        if isinstance(po, dict): po = po.get("value")
        if isinstance(co, dict): co = co.get("value")
        if po and co and po != co:
            return ("SIGNIFICANT", "high", "Cert issuer changed")
        return ("NORMAL_ROTATION", "low", "Cert rotated")
    if field == "asn" and subfield == "asn":
        return ("SIGNIFICANT", "moderate", f"ASN {old_v} -> {new_v}")
    if field == "asn" and subfield == "organization":
        return ("SIGNIFICANT", "high", f"Org {old_v} -> {new_v}")
    if field == "threat":
        if new_v == "POSITIVE_EVIDENCE" and old_v != "POSITIVE_EVIDENCE":
            return ("POTENTIALLY_SUSPICIOUS", "high", f"{subfield} now positive")
        return ("NORMAL_ROTATION", "informational", "threat status change")
    if field == "risk" and subfield == "threat_score":
        try:
            d = float(new_v) - float(old_v)
            if d >= 40: return ("POTENTIALLY_SUSPICIOUS", "high", f"+{d:.1f}")
            if d >= 20: return ("SIGNIFICANT", "moderate", f"+{d:.1f}")
            if d <= -20: return ("SIGNIFICANT", "low", f"{d:.1f}")
            return ("NORMAL_ROTATION", "informational", f"{d:.1f}")
        except: pass
    return ("NORMAL_ROTATION", "informational", f"{field}.{subfield}")

# ============================================================
#  PHASE K — GRAPH
# ============================================================
@dataclass
class GN:
    key: str
    etype: str
    value: str

@dataclass
class GE:
    src: str
    tgt: str
    rel: str
    confidence: float = 0.0
    sources: List[str] = field(default_factory=list)

def build_graph(result):
    nodes = {}; edges = {}
    def an(etype, value, prov=""):
        if value is None: return None
        v = str(value).strip()
        if not v: return None
        k = f"{etype}:{v}"
        if k not in nodes: nodes[k] = GN(k, etype, v)
        return k
    def ae(s, t, r, prov="", eid_=""):
        if not s or not t or s == t: return
        key = (s, t, r)
        if key not in edges: edges[key] = GE(s, t, r, 0, [])
        if prov and prov not in edges[key].sources: edges[key].sources.append(prov)
    ip = result.get("ip")
    if not ip: return [], []
    ipk = an("IP", ip, "target")
    for e in result.get("evidence", []):
        dt, f, v = e.get("data_type"), e.get("field"), e.get("value")
        prov = e.get("provider", "")
        if v in (None, "", [], {}): continue
        if dt == "asn":
            if f == "asn":
                k = an("ASN", v, prov); ae(ipk, k, "BELONGS_TO", prov)
            elif f == "organization":
                k = an("Organization", v, prov); ae(ipk, k, "OWNED_BY", prov)
            elif f == "prefix":
                k = an("CIDR", v, prov); ae(ipk, k, "BELONGS_TO", prov)
        elif dt == "geo":
            if f == "asn":
                k = an("ASN", v, prov); ae(ipk, k, "BELONGS_TO", prov)
            elif f == "organization":
                k = an("Organization", v, prov); ae(ipk, k, "OWNED_BY", prov)
            elif f == "isp":
                k = an("ISP", v, prov); ae(ipk, k, "HOSTED_BY", prov)
        elif dt == "dns":
            if f == "PTR":
                k = an("Hostname", v, prov)
                ae(ipk, k, "HAS_PTR", prov); ae(k, ipk, "RESOLVES_TO", prov)
        elif dt == "cert":
            if f == "current_fingerprint":
                k = an("Certificate", v, prov); ae(ipk, k, "HAS_CERTIFICATE", prov)
            elif f == "san":
                k = an("Domain", v, prov); ae(ipk, k, "ASSOCIATED_WITH", prov)
    for e in edges.values():
        e.confidence = min(95, 40 + (len(e.sources) - 1) * 20)
    return list(nodes.values()), list(edges.values())

# ============================================================
#  DATABASE
# ============================================================
class DB:
    def __init__(s, path):
        s.p = path; s._l = threading.RLock()
        with s._l:
            c = s._c()
            try:
                c.executescript("""
                CREATE TABLE IF NOT EXISTS targets(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT UNIQUE NOT NULL, target_type TEXT,
                    first_seen TEXT, last_seen TEXT, scan_count INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS scan_runs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER, started_at TEXT, finished_at TEXT,
                    status TEXT, error TEXT);
                CREATE TABLE IF NOT EXISTS observations(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER, scan_id INTEGER,
                    data_type TEXT, field TEXT, value TEXT, provider TEXT,
                    reliability REAL, first_seen TEXT, last_seen TEXT,
                    UNIQUE(target_id, data_type, field, provider));
                CREATE TABLE IF NOT EXISTS assessments(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER, scan_id INTEGER, created_at TEXT,
                    threat_score REAL, threat_classification TEXT,
                    data_confidence REAL, threat_coverage REAL,
                    final_assessment TEXT, final_confidence TEXT,
                    recommendation TEXT, payload TEXT);
                CREATE TABLE IF NOT EXISTS timeline_events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER, scan_id INTEGER,
                    field TEXT, subfield TEXT, old_value TEXT, new_value TEXT,
                    change_time TEXT, category TEXT, severity TEXT, reason TEXT);
                CREATE TABLE IF NOT EXISTS graph_entities(
                    key TEXT PRIMARY KEY, etype TEXT, value TEXT,
                    sources_json TEXT, first_seen TEXT, last_seen TEXT);
                CREATE TABLE IF NOT EXISTS graph_relationships(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src TEXT, tgt TEXT, rel TEXT, confidence REAL,
                    sources_json TEXT,
                    UNIQUE(src, tgt, rel));
                CREATE TABLE IF NOT EXISTS subdomains(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER, domain TEXT, source TEXT,
                    first_seen TEXT, last_seen TEXT,
                    UNIQUE(target_id, domain, source));
                CREATE TABLE IF NOT EXISTS passive_dns(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER, ip TEXT, hostname TEXT,
                    first_seen TEXT, last_seen TEXT,
                    UNIQUE(target_id, ip, hostname));
                """)
            finally: c.close()
    def _c(s):
        c = sqlite3.connect(s.p, timeout=30, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c
    def start_scan(s, target, ttype):
        with s._l:
            c = s._c()
            try:
                r = c.execute("SELECT id FROM targets WHERE target=?", (target,)).fetchone()
                if r:
                    c.execute("UPDATE targets SET last_seen=?, scan_count=scan_count+1 WHERE id=?",
                              (now(), r["id"])); tid = r["id"]
                else:
                    cur = c.execute(
                        "INSERT INTO targets(target,target_type,first_seen,last_seen,scan_count) VALUES(?,?,?,?,1)",
                        (target, ttype, now(), now()))
                    tid = cur.lastrowid
                cur = c.execute(
                    "INSERT INTO scan_runs(target_id,started_at,status) VALUES(?,?,?)",
                    (tid, now(), "RUNNING"))
                return tid, cur.lastrowid
            finally: c.close()
    def complete_scan(s, sid, status, err=None):
        with s._l:
            c = s._c()
            try:
                c.execute("UPDATE scan_runs SET finished_at=?, status=?, error=? WHERE id=?",
                          (now(), status, err, sid))
            finally: c.close()
    def persist(s, tid, sid, result):
        with s._l:
            c = s._c()
            try:
                for e in result.get("evidence", []):
                    v = json.dumps(e["value"]) if isinstance(e["value"], (dict, list)) \
                        else str(e["value"] or "")
                    ex = c.execute(
                        "SELECT id FROM observations WHERE target_id=? AND data_type=? AND field=? AND provider=?",
                        (tid, e["data_type"], e["field"], e["provider"])).fetchone()
                    if ex:
                        c.execute("UPDATE observations SET value=?, last_seen=? WHERE id=?",
                                  (v, now(), ex["id"]))
                    else:
                        c.execute(
                            "INSERT INTO observations(target_id,scan_id,data_type,field,value,provider,reliability,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
                            (tid, sid, e["data_type"], e["field"], v, e["provider"],
                             e.get("reliability", 0.5), now(), now()))
                pb = result.get("phase_b", {}) or {}
                th = pb.get("threat", {}) or {}
                fa = pb.get("final_assessment", {}) or {}
                c.execute("""INSERT INTO assessments(target_id,scan_id,created_at,threat_score,
                    threat_classification,data_confidence,threat_coverage,final_assessment,
                    final_confidence,recommendation,payload)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (tid, sid, now(), th.get("score", 0),
                     th.get("classification", ""),
                     pb.get("data_confidence", {}).get("score", 0),
                     pb.get("coverage", {}).get("coverage", 0),
                     fa.get("assessment", ""), fa.get("confidence", ""),
                     fa.get("recommendation", ""),
                     json.dumps(pb, default=str)))
                # Phase 2: persist subdomains + passive DNS
                ni = result.get("network_intelligence", {}) or {}
                for sd in (ni.get("subdomains") or {}).get("subdomains", []):
                    try:
                        c.execute("INSERT OR IGNORE INTO subdomains(target_id,domain,source,first_seen,last_seen) VALUES(?,?,?,?,?)",
                                  (tid, sd, "enum", now(), now()))
                    except Exception: pass
                for row in (ni.get("passive_dns_merged") or []):
                    try:
                        h = row.get("hostname")
                        if h:
                            c.execute("INSERT OR IGNORE INTO passive_dns(target_id,ip,hostname,first_seen,last_seen) VALUES(?,?,?,?,?)",
                                      (tid, result.get("ip"), h, now(), now()))
                    except Exception: pass
            finally: c.close()
    def timeline_append(s, tid, sid, events):
        with s._l:
            c = s._c()
            try:
                for e in events:
                    c.execute("""INSERT INTO timeline_events(target_id,scan_id,field,subfield,
                        old_value,new_value,change_time,category,severity,reason)
                        VALUES(?,?,?,?,?,?,?,?,?,?)""",
                        (tid, sid, e["field"], e["subfield"],
                         str(e.get("old_value", "")), str(e.get("new_value", "")),
                         now(), e["category"], e["severity"], e["reason"]))
            finally: c.close()
    def prev_state(s, tid, before_sid):
        with s._l:
            c = s._c()
            try:
                r = c.execute(
                    "SELECT MAX(id) AS sid FROM scan_runs WHERE target_id=? AND id<? AND status='COMPLETED'",
                    (tid, before_sid)).fetchone()
                if not r or not r["sid"]: return {}
                rows = c.execute(
                    "SELECT data_type, field, value FROM observations WHERE target_id=?",
                    (tid,)).fetchall()
                return {(x["data_type"], x["field"]): x["value"] for x in rows}
            finally: c.close()
    def history(s, tid):
        with s._l:
            c = s._c()
            try:
                t = c.execute("SELECT * FROM targets WHERE id=?", (tid,)).fetchone()
                return dict(t) if t else None
            finally: c.close()
    def graph_persist(s, nodes, edges):
        with s._l:
            c = s._c()
            try:
                for n in nodes:
                    c.execute("""INSERT INTO graph_entities(key,etype,value,sources_json,first_seen,last_seen)
                        VALUES(?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET last_seen=excluded.last_seen""",
                        (n.key, n.etype, n.value, json.dumps([]), now(), now()))
                for e in edges:
                    c.execute("""INSERT INTO graph_relationships(src,tgt,rel,confidence,sources_json)
                        VALUES(?,?,?,?,?) ON CONFLICT(src,tgt,rel) DO UPDATE SET confidence=excluded.confidence""",
                        (e.src, e.tgt, e.rel, e.confidence, json.dumps(e.sources)))
            finally: c.close()
    def graph_summary(s):
        with s._l:
            c = s._c()
            try:
                n = c.execute("SELECT COUNT(*) AS c FROM graph_entities").fetchone()["c"]
                e = c.execute("SELECT COUNT(*) AS c FROM graph_relationships").fetchone()["c"]
                return {"nodes": n, "edges": e}
            finally: c.close()

INTEL_DB: Optional[DB] = None

# ============================================================
#  STIX / MISP EXPORT
# ============================================================
def export_stix(result):
    ip = result.get("ip")
    pi = result.get("phase_i", {}) or {}
    out = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": []}
    if ip:
        out["objects"].append({"type": "ipv4-addr", "spec_version": "2.1",
                                "id": f"ipv4-addr--{uuid.uuid4()}", "value": ip})
    if pi.get("positive", 0) > 0:
        out["objects"].append({
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now(), "modified": now(),
            "name": f"Suspicious IP: {ip}",
            "pattern": f"[ipv4-addr:value = '{ip}']", "pattern_type": "stix",
            "valid_from": now(), "labels": ["malicious-activity"],
            "confidence": int(pi.get("confidence", 0)),
            "description": pi.get("explanation", ""),
        })
    # Add subdomains as domain SCOs
    ni = result.get("network_intelligence", {}) or {}
    for sd in (ni.get("subdomains") or {}).get("subdomains", [])[:50]:
        out["objects"].append({"type": "domain-name", "spec_version": "2.1",
                                "id": f"domain-name--{uuid.uuid4()}", "value": sd})
    return out

def export_misp(result):
    ip = result.get("ip")
    pi = result.get("phase_i", {}) or {}
    pb = result.get("phase_b", {}) or {}
    fa = pb.get("final_assessment", {}) or {}
    attrs = [{"type": "ip-dst", "category": "Network activity", "value": ip,
              "to_ids": pi.get("positive", 0) > 0,
              "comment": f"Threat score {(pb.get('threat') or {}).get('score',0)}"}]
    for e in result.get("evidence", []):
        if e.get("data_type") == "cert" and e.get("field") == "san":
            attrs.append({"type": "domain", "category": "Network activity",
                          "value": e["value"], "to_ids": False})
        elif e.get("data_type") == "dns" and e.get("field") == "PTR":
            attrs.append({"type": "hostname", "category": "Network activity",
                          "value": e["value"], "to_ids": False})
    ni = result.get("network_intelligence", {}) or {}
    for sd in (ni.get("subdomains") or {}).get("subdomains", [])[:50]:
        attrs.append({"type": "domain", "category": "Network activity",
                      "value": sd, "to_ids": False, "comment": "subdomain"})
    for typo in (ni.get("typosquatting") or [])[:20]:
        attrs.append({"type": "domain", "category": "Network activity",
                      "value": typo.get("domain"), "to_ids": True,
                      "comment": f"typosquat d={typo.get('distance')}"})
    return {"Event": {"info": f"ReconIP: {ip} ({fa.get('assessment','Unknown')})",
                       "distribution": "0", "threat_level_id": "2", "analysis": "2",
                       "Attribute": attrs}}

# ============================================================
#  RECON (MAIN FLOW) — v21.3 with Phase 2
# ============================================================
def recon(target, enable_db=True, parallel=None):
    try:
        normalized, _k = validate_target(target, allow_private=PN["allow_private_targets"])
    except SecurityError as e:
        return {"input": target, "error": f"SECURITY: {e}",
                "scan_status": MS.FAILED.value, "module_statuses": {}}
    target = normalized
    if parallel is None:
        parallel = "--parallel" in sys.argv
    t0 = time.time()
    out = {"input": target, "timestamp": now(), "type": "ip", "module_statuses": {}}
    try:
        ipaddress.ip_address(target)
        ip, domain = target, None
    except ValueError:
        try:
            ans = dns.resolver.resolve(target, "A")
            ip, domain = str(ans[0]), target
            out["type"] = "domain"
            out["resolved_ip"] = ip
        except Exception as e:
            out["error"] = f"Cannot resolve: {e}"
            out["scan_status"] = MS.FAILED.value
            return out
    out["ip"] = ip
    evs = []; cert_ci = None; threat_obs = []

    if parallel:
        res = collect_parallel(ip, domain)
        geo_evs, geo_st = res.get("geo", ([], MS.SKIPPED.value))
        asn_evs, asn_st = res.get("asn", ([], MS.SKIPPED.value))
        rdap_evs, rdap_st = res.get("rdap", ([], MS.SKIPPED.value))
        dns_evs, dns_st = res.get("dns", ([], MS.SKIPPED.value))
        cert_res = res.get("cert", ([], MS.SKIPPED.value, {"records": {}}))
        threat_res = res.get("threat", ([], MS.SKIPPED.value))
    else:
        geo_evs, geo_st = collect_geo(ip)
        asn_evs, asn_st = collect_asn(ip)
        rdap_evs, rdap_st = collect_rdap(ip)
        dns_evs, dns_st = collect_dns(ip, domain=domain)
        cert_res = collect_certs(domain or ip)
        threat_res = collect_threat(ip)

    # v21.6 FIX: ASN dedup by source PRIORITY (not weight)
    # Priority: RIPE(100) > BGPView(90) > WHOIS(85) > bgp.he.net(50)
    if asn_evs:
        ASN_PRIO = {"ripe": 100, "bgpview": 90, "whois": 85, "bgp_he": 50}
        STRICT_FIELDS = ("asn", "prefix", "rir", "organization")
        def _src_prio(e):
            s = e.provider.split(":")[0] if ":" in e.provider else e.provider
            return ASN_PRIO.get(s, 60)
        kept = []
        # For strict fields: keep ONLY the value from the highest-priority source
        for fld in STRICT_FIELDS:
            cands = [e for e in asn_evs if e.field == fld]
            if not cands: continue
            best = max(cands, key=_src_prio)
            kept.append(best)
        # For informational fields: keep all (country, abuse_contact, created, updated)
        for e in asn_evs:
            if e.field not in STRICT_FIELDS:
                kept.append(e)
        asn_evs = kept

    evs += geo_evs + asn_evs + rdap_evs + dns_evs
    out["module_statuses"]["geo"] = geo_st
    out["module_statuses"]["asn"] = asn_st
    out["module_statuses"]["rdap"] = rdap_st
    out["module_statuses"]["dns"] = dns_st

    cert_evs, cert_st, cert_ci = cert_res if len(cert_res) == 3 \
        else ([], MS.SKIPPED.value, {"records": {}})
    evs += cert_evs
    out["module_statuses"]["cert"] = cert_st

    threat_obs, threat_st = threat_res if len(threat_res) == 2 \
        else ([], MS.SKIPPED.value)
    threat_agg = agg_threat(threat_obs)
    evs += threat_evs(ip, threat_obs)
    out["module_statuses"]["threat"] = threat_st
    out["phase_i"] = threat_agg

    # Stage 3: Source Reliability Engine — run new providers (v32) with reliability/weight
    stage3_threat_evs: List[Evidence] = []
    try:
        cfg_providers = load_providers(CFG)
        load_api_keys(cfg_providers)
        stage3_threat_evs = run_providers(ip, cfg_providers)
        # Keep for evidence_engine; also optionally extend evs for legacy scoring (as Ev)
        # Convert to Ev for downstream if needed, but keep separate to avoid double count
        out["stage3_threat_evidences"] = [e.to_dict() for e in stage3_threat_evs]
    except Exception as e:
        log.debug(f"stage3 providers: {e}")
        stage3_threat_evs = []
        out["stage3_threat_evidences"] = []

    out["scan_status"] = agg_scan_status(out["module_statuses"])
    anycast = ip in CFG["geo_validation"]["anycast_ips"]
    cs = conflict_report(evs, anycast=anycast)
    trusted = build_trusted(evs, cs, anycast)

    threat_dim = threat_score([e for e in evs if e.data_type == "threat"],
                              phase_i=threat_agg)
    infra_dim = infra_risk(ip, trusted, evs)
    dc = data_confidence(evs, trusted, cs, None)
    cov = coverage({}, phase_i=threat_agg)
    eq = evidence_quality(evs, cs)
    ac = assess_confidence(threat_dim, infra_dim, dc, cov, eq, cs)
    fa = final_assess(threat_dim, infra_dim, dc, cov, ac, cs, anycast)

    ents = build_entities(evs, ip)
    rels = build_rels(ents, evs, ip)
    ni = network_intel(ip, domain, evs, trusted, cert_ci)

    # Passive OSINT enrichment (v21.2) — B4 fix with public resolver / anycast check
    try:
        rev_raw = PassiveOSINT.hackertarget_reverse_ip(ip)
        # Determine ASN for anycast check
        asn_val = ""
        try:
            asn_cands = [e.value for e in evs if e.data_type == "asn" and e.field == "asn"]
            if trusted.get("asn") and trusted["asn"].value:
                asn_val = str(trusted["asn"].value)
            elif asn_cands:
                asn_val = str(asn_cands[0])
        except Exception:
            asn_val = ""
        rev_filtered, rev_note = filter_reverse_ip(rev_raw or [], ip, CFG.get("public_resolvers"), CFG.get("anycast_asns"), asn_val)
        rev = rev_filtered
        ni["reverse_ip_note"] = rev_note
        otx_pd_raw = PassiveOSINT.otx_passive_dns(ip)
        # B2: normalize OTX results immediately to avoid identical date bug
        otx_pd = normalize_passive_dns(otx_pd_raw) if otx_pd_raw else []
        idb = PassiveOSINT.internetdb(ip)
        ni["reverse_ip"] = rev
        ni["passive_dns_otx"] = otx_pd
        ni["internetdb"] = idb
    except Exception as e:
        log.debug(f"passive osint: {e}")
        ni["reverse_ip"] = []
        ni["passive_dns_otx"] = []
        ni["internetdb"] = {}

    # PHASE 2 — Deep OSINT (v21.3)
    try:
        # 1. Subdomain enumeration (only if domain)
        if domain:
            sub_enum = enumerate_subdomains(domain, ip)
            ni["subdomains"] = sub_enum
            typos = detect_typosquatting(domain, sub_enum.get("subdomains", []))
            ni["typosquatting"] = typos
        else:
            ni["subdomains"] = {"subdomains": [], "sources": {}, "total": 0}
            ni["typosquatting"] = []

        # 2. CT deep analysis
        ct_deep = analyze_ct_subdomains(cert_ci.get("records", {}) if cert_ci else {})
        ni["ct_deep"] = ct_deep

        # 3. Merge passive DNS (OTX + VT)
        ni["passive_dns_merged"] = merge_passive_dns(ip, otx_pd)

        # 4. Reverse IP suspicious analysis
        ni["reverse_ip_suspicious"] = enrich_suspicious_ips(rev if rev else [])

        # 5. Enhanced WHOIS
        whois_target = domain or ip
        whois_full = whois_enhanced(whois_target)
        ni["whois_enhanced"] = whois_full or {}

    except Exception as e:
        log.debug(f"phase2: {e}")
        ni.setdefault("subdomains", {"subdomains": [], "sources": {}, "total": 0})
        ni.setdefault("typosquatting", [])
        ni.setdefault("ct_deep", {})
        ni.setdefault("passive_dns_merged", [])
        ni.setdefault("reverse_ip_suspicious", [])
        ni.setdefault("whois_enhanced", {})

    # PHASE 3 — MITRE + Attribution + Related Infra
    try:
        asn_nums = sorted({e.value for e in evs
                            if e.data_type == "asn" and e.field == "asn"})
        out["phase3"] = build_phase3(
            threat_agg.get("providers", []),
            ni.get("anomalies", []),
            asn_nums)
    except Exception as e:
        log.debug(f"phase3: {e}")
        out["phase3"] = {"enabled": False, "error": str(e)}

    # Stage 2: Evidence Engine — build traceable evidence store (v31)
    # Every data point wrapped via Evidence; ensure freshness, confidence, status
    evidence_store = {}
    evidence_flat = []
    for e in evs:
        try:
            if isinstance(e, Evidence):
                ev_obj = e
            elif isinstance(e, Ev):
                ev_obj = ev_to_evidence(e)
            elif isinstance(e, Obs):
                # Convert Obs (threat) to Evidence
                ev_obj = make_evidence(
                    source=getattr(e, 'provider', 'threat'),
                    value=getattr(e, 'score', None),
                    normalized_value=getattr(e, 'score', None),
                    confidence=(getattr(e, 'confidence', 50) / 100.0) if getattr(e, 'confidence', None) else 0.5,
                    status="OK" if getattr(e, 'status', '') in (TS2.POSITIVE, TS.NO_THREAT.value, TS.NO_DATA.value) else "FAILED",
                    ttl_key="threat",
                    metadata={"status": getattr(e, 'status', ''), "categories": getattr(e, 'categories', []), "error": getattr(e, 'error', None), "provider": getattr(e, 'provider', '')}
                )
            else:
                continue
            evidence_flat.append(ev_obj.to_dict())
            # Group by source for report structure
            key = ev_obj.source
            evidence_store.setdefault(key, []).append(ev_obj.to_dict())
        except Exception:
            continue
    # Also merge in dedicated Evidence collectors for completeness (DNS, WHOIS, cert, passive) if not already covered
    try:
        # WHOIS via collect_whois
        for ev in collect_whois(ip):
            evidence_flat.append(ev.to_dict())
            evidence_store.setdefault(ev.source, []).append(ev.to_dict())
    except Exception:
        pass
    try:
        # Passive DNS via collect_passive_dns
        for ev in collect_passive_dns(ip):
            evidence_flat.append(ev.to_dict())
            evidence_store.setdefault("passive_dns", []).append(ev.to_dict())
    except Exception:
        pass
    # Stage 2: Add threat Obs as Evidence (including FAILED for traceability)
    try:
        for o in threat_obs:
            ev = make_evidence(
                source=getattr(o, 'provider', 'threat'),
                value=getattr(o, 'score', None),
                normalized_value=getattr(o, 'score', None),
                confidence=(getattr(o, 'confidence', 50) / 100.0) if getattr(o, 'confidence', None) else 0.5,
                status="OK" if getattr(o, 'status', '') in (TS2.POSITIVE, TS.NO_THREAT.value, TS.NO_DATA.value) else "FAILED",
                ttl_key="threat",
                metadata={"status": getattr(o, 'status', ''), "categories": getattr(o, 'categories', []), "error": getattr(o, 'error', None), "data_type": "threat", "field": getattr(o, 'provider', 'unknown'), "target": ip, "raw_value": getattr(o, 'score', None)}
            )
            # Avoid duplicates
            if not any(e.get("source") == ev.source and str(e.get("value")) == str(ev.value) for e in evidence_flat):
                evidence_flat.append(ev.to_dict())
                evidence_store.setdefault(ev.source, []).append(ev.to_dict())
    except Exception as e:
        log.debug(f"threat evidence: {e}")
        pass
    # Stage 3: merge new provider evidences (v32) — reliability, error_rate, confidence
    try:
        for ev in stage3_threat_evs:
            # Avoid duplicates already added via threat_obs
            if not any(e.get("source") == ev.source for e in evidence_flat):
                evidence_flat.append(ev.to_dict())
                evidence_store.setdefault(ev.source, []).append(ev.to_dict())
    except Exception as e:
        log.debug(f"stage3 merge: {e}")
        pass
    # Stage 2: ensure every field traceable — add evidence_engine and keep legacy evidence for compat
    out.update({
        "anycast": anycast,
        "evidence": evidence_flat,  # v31 Evidence objects (source, timestamp, value, normalized_value, confidence, freshness, status, metadata)
        "evidence_legacy": [e.to_dict() if hasattr(e, 'to_dict') else str(e) for e in evs],
        "evidence_engine": evidence_store,
        "conflicts": [asdict(c) for c in cs],
        "trusted": {k: asdict(v) for k, v in trusted.items()},
        "entities": [asdict(e) for e in ents.values()],
        "relationships": [asdict(r) for r in rels],
        "network_intelligence": ni,
        "certificate_intelligence": cert_summary(cert_ci),
        "phase_b": {
            "threat": {"score": threat_dim.score,
                       "classification": threat_dim.classification,
                       "factors": [asdict(f) for f in threat_dim.factors]},
            "infrastructure": {"score": infra_dim.score,
                                "classification": infra_dim.classification,
                                "factors": [asdict(f) for f in infra_dim.factors]},
            "data_confidence": {"score": dc.score,
                                 "classification": dc.classification,
                                 "factors": [asdict(f) for f in dc.factors]},
            "coverage": cov,
            "evidence_quality": {"score": eq.score,
                                  "classification": eq.classification},
            "assessment_confidence": ac,
            "final_assessment": fa,
        },
        "execution_time": round(time.time() - t0, 2),
    })

    if enable_db and INTEL_DB is not None:
        try:
            tid, sid = INTEL_DB.start_scan(ip, "ip")
            try:
                INTEL_DB.persist(tid, sid, out)
                prev = INTEL_DB.prev_state(tid, sid)
                cur_state = extract_state(out)
                events = []
                for key, new_v in cur_state.items():
                    old_v = prev.get(key)
                    if old_v == new_v or old_v is None: continue
                    cat, sev, reason = classify_change(key[0], key[1], old_v,
                                                        new_v, prev, cur_state)
                    events.append({"field": key[0], "subfield": key[1],
                                   "old_value": old_v, "new_value": new_v,
                                   "category": cat, "severity": sev,
                                   "reason": reason})
                if events: INTEL_DB.timeline_append(tid, sid, events)
                out["phase_j"] = {"events": events, "event_count": len(events)}
                nodes, edges = build_graph(out)
                INTEL_DB.graph_persist(nodes, edges)
                out["phase_k"] = {"nodes": len(nodes), "edges": len(edges),
                                   "summary": INTEL_DB.graph_summary()}
                out["history"] = INTEL_DB.history(tid)
                INTEL_DB.complete_scan(sid, out["scan_status"])
            except Exception as e:
                INTEL_DB.complete_scan(sid, "FAILED", str(e))
                log.error(f"persist: {e}")
        except Exception as e:
            log.error(f"db outer: {e}")
    return out

# ============================================================
#  REST API
# ============================================================
class APIError(Exception):
    def __init__(s, status, code, msg):
        s.status = status; s.code = code; s.msg = msg

class TokenBucket:
    def __init__(s, rpm):
        s.rpm = max(1, rpm); s.hits = defaultdict(list); s._l = threading.Lock()
    def allow(s, k):
        t = time.monotonic()
        with s._l:
            b = s.hits[k]; cut = t - 60
            while b and b[0] < cut: b.pop(0)
            if len(b) >= s.rpm: return False
            b.append(t); return True

def _resolve_tokens():
    env_var = PM.get("token_env_var", "RECONIP_API_TOKEN")
    env_val = os.environ.get(env_var, "")
    raw = ([t.strip() for t in env_val.split(",") if t.strip()]
           if env_val.strip()
           else [t for t in (PM.get("tokens") or [])
                 if isinstance(t, str) and t.strip()])
    return [hashlib.sha256(t.encode()).hexdigest() for t in raw]

API_TOKENS = _resolve_tokens()
RATE = TokenBucket(PM.get("rate_limit_per_min", 60))
JOBS = {}; JOBS_LOCK = threading.Lock()

def spawn_job(target):
    jid = str(uuid.uuid4())
    with JOBS_LOCK:
        JOBS[jid] = {"id": jid, "target": target, "state": "QUEUED",
                     "created_at": now(), "started_at": None,
                     "finished_at": None, "error": None, "result": None}
    def run():
        with JOBS_LOCK:
            JOBS[jid]["state"] = "RUNNING"
            JOBS[jid]["started_at"] = now()
        try:
            r = recon(target)
            with JOBS_LOCK:
                JOBS[jid]["state"] = "COMPLETED"
                JOBS[jid]["result"] = r
                JOBS[jid]["finished_at"] = now()
        except Exception as e:
            with JOBS_LOCK:
                JOBS[jid]["state"] = "FAILED"
                JOBS[jid]["error"] = str(e)
                JOBS[jid]["finished_at"] = now()
    threading.Thread(target=run, daemon=True).start()
    return jid

class APIHandler(BaseHTTPRequestHandler):
    server_version = "ReconIP-API/21.3"
    def log_message(s, *a): pass
    def _send(s, code, payload):
        body = json.dumps(redact(payload), ensure_ascii=False, default=str).encode()
        s.send_response(code)
        s.send_header("Content-Type", "application/json")
        s.send_header("Content-Length", str(len(body)))
        s.send_header("X-Content-Type-Options", "nosniff")
        if PM.get("cors_origin"):
            s.send_header("Access-Control-Allow-Origin", PM["cors_origin"])
        s.end_headers(); s.wfile.write(body)
    def _auth(s):
        if not PM.get("require_auth", True): return "anon"
        h = s.headers.get("Authorization", "")
        if not h.lower().startswith("bearer "):
            raise APIError(401, "unauthorized", "Missing token")
        tok = hashlib.sha256(h[7:].strip().encode()).hexdigest()
        if not any(hmac.compare_digest(stored, tok) for stored in API_TOKENS):
            raise APIError(401, "unauthorized", "Invalid token")
        return tok[:16]
    def _route(s, method):
        try:
            key = s._auth()
        except APIError as e:
            s._send(e.status, {"error": {"code": e.code, "message": e.msg}}); return
        if not RATE.allow(key):
            s._send(429, {"error": {"code": "rate_limited"}}); return
        p = urlparse(s.path); path = p.path.rstrip("/") or "/"
        try:
            if method == "GET" and path == "/health":
                s._send(200, {"status": "READY",
                              "uptime": round(time.time() - _START_T, 1),
                              "providers": {n: h.to_dict()
                                             for n, h in _health.items()}})
                return
            if method == "GET" and path == "/metrics":
                s._send(200, {"jobs": len(JOBS),
                              "cache": CACHE.stats() if CACHE else {},
                              "providers": len(_health)})
                return
            if method == "GET" and path == "/providers":
                provs = []
                for cls in PROVIDERS:
                    try:
                        x = cls()
                        provs.append({"name": x.name, "enabled": x.enabled,
                                      "configured": x.configured(),
                                      "env_var": x.env_var})
                    except: pass
                s._send(200, {"providers": provs}); return
            if method == "POST" and path == "/scan":
                length = int(s.headers.get("Content-Length", 0) or 0)
                if length > PN["max_body_bytes"]:
                    s._send(413, {"error": {"code": "too_large"}}); return
                body = json.loads(s.rfile.read(length).decode() or "{}")
                if "target" in body:
                    t, _ = validate_target(body["target"],
                                            allow_private=PN["allow_private_targets"])
                    jid = spawn_job(t)
                    s._send(202, {"job_id": jid}); return
                if "targets" in body:
                    if len(body["targets"]) > PN["max_batch"]:
                        s._send(400, {"error": {"code": "batch_too_large"}}); return
                    ids = [spawn_job(validate_target(
                        t, allow_private=PN["allow_private_targets"])[0])
                        for t in body["targets"]]
                    s._send(202, {"job_ids": ids, "count": len(ids)}); return
                s._send(400, {"error": {"code": "invalid_request"}}); return
            if method == "GET" and path.startswith("/scan/"):
                jid = path.split("/")[-1]
                with JOBS_LOCK:
                    j = JOBS.get(jid)
                    if not j:
                        s._send(404, {"error": {"code": "not_found"}}); return
                    resp = {k: v for k, v in j.items() if k != "result"}
                    if j.get("state") == "COMPLETED":
                        resp["result"] = j["result"]
                s._send(200, resp); return
            s._send(404, {"error": {"code": "not_found", "path": path}})
        except APIError as e:
            s._send(e.status, {"error": {"code": e.code, "message": e.msg}})
        except Exception as e:
            log.exception("api")
            s._send(500, {"error": {"code": "internal",
                                     "type": type(e).__name__}})
    def do_GET(s): s._route("GET")
    def do_POST(s): s._route("POST")

_START_T = time.time()

def start_api(host=None, port=None):
    h = host or PM.get("host", "127.0.0.1")
    p = int(port or PM.get("port", 8787))
    httpd = ThreadingHTTPServer((h, p), APIHandler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    log.info(f"API on http://{h}:{p}")
    return httpd

# ============================================================
#  PROFESSIONAL TEXT RENDERER (v21.3 — with Phase 2 sections)
# ============================================================
def render_text(d):
    """Hacker-style colored terminal output."""
    if "error" in d and "module_statuses" not in d:
        return f"{C.FAIL}✗ ERROR:{C.RST} {d['error']}"

    out = [_banner(), ""]
    ip = d.get("ip") or d.get("input", "?")
    status = d.get("scan_status", "?")
    anycast = d.get("anycast", False)
    exec_t = d.get("execution_time", 0)
    ts = (d.get("timestamp") or "")[:19].replace("T", " ")
    status_style = {"SUCCESS": C.OK, "PARTIAL": C.WARN, "FAILED": C.FAIL}.get(status, C.GRY)

    out.append(_kv("TARGET", ip, 12, C.BLD + C.WHT))
    out.append(_kv("STATUS", _c(f"● {status}", status_style), 12))
    out.append(_kv("SCAN TIME", f"{exec_t}s", 12))
    out.append(_kv("TIMESTAMP", ts, 12, C.GRY))
    if d.get("type") == "domain":
        out.append(_kv("DOMAIN", f"{d.get('input')} → {ip}", 12, C.CYN))
    out.append(_kv("ANYCAST", _c("● YES" if anycast else "○ NO",
                                  C.WARN if anycast else C.OK), 12))

    # [00] MODULE STATUS
    out.append(_section_header("00", "Module Status"))
    mods = d.get("module_statuses") or {}
    items = list(mods.items())
    for i in range(0, len(items), 3):
        row = "   "
        for name, st in items[i:i+3]:
            cell = f"{_c(name.upper().ljust(8), C.BLD, C.WHT)} {_status_dot(st)}"
            row += _vpad(cell, 32)
        out.append(row.rstrip())
    out.append(_section_footer())

    # [01] THREAT ASSESSMENT
    out.append(_section_header("01", "Threat Assessment"))
    pb = d.get("phase_b") or {}
    th = pb.get("threat") or {}
    tscore = float(th.get("score", 0))
    bar_color = C.OK if tscore < 20 else C.WARN if tscore < 60 else C.FAIL
    out.append(f"   {_c('SCORE', C.KEY).ljust(28)} {_bar(tscore, 40, color=bar_color)} "
               f"{_c(f'{tscore:>5.1f}/100', C.BLD, bar_color)}")
    out.append(f"   {_c('CLASSIFICATION', C.KEY).ljust(28)} "
               f"{_c(th.get('classification', '-'), C.BLD, C.WHT)}")
    ac = pb.get("assessment_confidence") or {}
    lbl = ac.get("label", "?")
    lbl_color = {"High": C.OK, "Moderate": C.WARN, "Low": C.FAIL}.get(lbl, C.GRY)
    out.append(f"   {_c('CONFIDENCE', C.KEY).ljust(28)} "
               f"{_c('● ' + lbl.upper(), C.BLD, lbl_color)}")
    infra = pb.get("infrastructure") or {}
    iscore = float(infra.get("score", 0))
    out.append(f"   {_c('INFRA RISK', C.KEY).ljust(28)} "
               f"{_bar(iscore, 40, color=C.ORG)} "
               f"{_c(f'{iscore:>5.1f}/100', C.BLD, C.ORG)}")

    # FINAL VERDICT BOX
    fa = pb.get("final_assessment") or {}
    assess = fa.get("assessment", "Unknown")
    a_color = C.OK if "No significant" in assess else \
              C.WARN if "Insufficient" in assess or "Moderate" in assess else \
              C.FAIL if "High" in assess or "Critical" in assess else C.WHT
    out.append("")
    w = min(_w(), 100)
    out.append(f"   {C.DRED}┌─{C.RST} {_c('FINAL VERDICT', C.BLD, C.WHT)} "
               f"{C.DRED}{'─' * (w - 22)}┐{C.RST}")
    out.append(f"   {C.DRED}│{C.RST}  {_c('▸', C.GRN)} "
               f"{_c(assess.upper(), C.BLD, a_color)}")
    for r in (fa.get("reasons") or [])[:4]:
        out.append(f"   {C.DRED}│{C.RST}    {_c('·', C.GRY)} {r}")
    for lm in (fa.get("limitations") or [])[:4]:
        out.append(f"   {C.DRED}│{C.RST}    {_c('!', C.WARN)} {_c(lm, C.WARN)}")
    rec = fa.get("recommendation", "")
    if rec:
        out.append(f"   {C.DRED}│{C.RST}  {_c('➤', C.CYN)} {_c(rec, C.ITL, C.CYN)}")
    out.append(f"   {C.DRED}└{'─' * (w - 5)}┘{C.RST}")
    out.append(_section_footer())

    # [02] TRUSTED INTEL
    out.append(_section_header("02", "Trusted Intelligence"))
    trusted = d.get("trusted") or {}
    for f, t in trusted.items():
        if t.get("status") == "INSUFFICIENT": continue
        status = t.get("status", "?")
        conf = float(t.get("confidence", 0))
        val = t.get("value")
        val_s = "(unavailable)" if val is None else str(val)[:44]
        badge = _badge(status,
                       "ok" if status == "TRUSTED" else
                       "warn" if status in ("UNRELIABLE", "APPROXIMATE") else "dim")
        conf_color = C.OK if conf >= 70 else C.WARN if conf >= 40 else C.FAIL
        out.append(f"   {_c(f.ljust(18), C.KEY)} "
                   f"{_c(val_s.ljust(46), C.VAL)} "
                   f"{_c(f'{conf:>5.1f}%', C.BLD, conf_color)} {badge}")
    out.append(_section_footer())

    # [03] THREAT INTEL
    pi = d.get("phase_i") or {}
    if pi:
        out.append(_section_header("03", "Threat Intelligence"))
        pcov = float(pi.get("coverage", 0))
        pscore = float(pi.get("score", 0))
        pconf = float(pi.get("confidence", 0))
        out.append(f"   {_c('AGGREGATE', C.KEY).ljust(28)} "
                   f"{_bar(pscore, 40, color=C.FAIL if pscore > 50 else C.OK)} "
                   f"{_c(f'{pscore:>5.1f}/100', C.BLD)}")
        out.append(f"   {_c('COVERAGE', C.KEY).ljust(28)} "
                   f"{_bar(pcov, 40, color=C.GRN if pcov > 70 else C.YEL if pcov > 40 else C.RED)} "
                   f"{_c(f'{pcov:>5.1f}%', C.BLD)}")
        out.append(f"   {_c('CONFIDENCE', C.KEY).ljust(28)} "
                   f"{_bar(pconf, 40, color=C.GRN if pconf > 70 else C.YEL)} "
                   f"{_c(f'{pconf:>5.1f}%', C.BLD)}")
        out.append("")
        out.append(f"   {C.GRY}┌─── Provider Results "
                   + "─" * (w - 25) + f"┐{C.RST}")
        for p in pi.get("providers", []):
            name = p.get("provider", "?")
            ps = p.get("status", "?")
            score = p.get("score")
            reps = p.get("reports", 0)
            conf = p.get("confidence", 0)
            pcolor = {"POSITIVE_EVIDENCE": C.FAIL, "NO_THREAT_FOUND": C.OK,
                      "NOT_CONFIGURED": C.GRY, "PROVIDER_ERROR": C.WARN,
                      "RATE_LIMITED": C.YEL, "NO_DATA": C.DIM}.get(ps, C.WHT)
            symbol = {"POSITIVE_EVIDENCE": "✗", "NO_THREAT_FOUND": "✓",
                      "NOT_CONFIGURED": "○", "PROVIDER_ERROR": "!",
                      "RATE_LIMITED": "⏱", "NO_DATA": "·"}.get(ps, "?")
            score_s = f"{score:>5.1f}" if score is not None else "  -  "
            out.append(f"   {C.GRY}│{C.RST} "
                       f"{_c(symbol, C.BLD, pcolor)} "
                       f"{_c(name.ljust(14), C.BLD, C.WHT)} "
                       f"{_c(ps.ljust(18), pcolor)} "
                       f"{_c('score=' + score_s, C.DIM)} "
                       f"{_c('rep=' + str(reps).ljust(4), C.DIM)} "
                       f"{_c('conf=' + f'{conf:.0f}', C.DIM)}")
        out.append(f"   {C.GRY}└{'─' * (w - 5)}┘{C.RST}")
        if pi.get("disagreements"):
            for dis in pi["disagreements"][:3]:
                out.append(f"   {_c('⚠', C.WARN)} "
                           f"{_c(dis.get('explanation', ''), C.WARN)}")
        out.append(_section_footer())

    # [04] CONFLICTS
    cs = d.get("conflicts") or []
    out.append(_section_header("04", f"Data Conflicts ({len(cs)})"))
    if not cs:
        out.append(f"   {_c('✓ No conflicts detected', C.OK)}")
    else:
        for c in cs:
            sev = c.get("severity", "LOW")
            sc = _severity_color(sev)
            out.append(f"   {_c('[' + sev.ljust(8) + ']', C.BLD, sc)} "
                       f"{_c(c.get('field', '?').ljust(14), C.KEY)} "
                       f"{c.get('description', '')}")
    out.append(_section_footer())

    # [05] NETWORK INTELLIGENCE
    ni = d.get("network_intelligence") or {}
    if ni:
        out.append(_section_header("05", "Network Intelligence"))
        asn = ni.get("asn") or {}
        out.append(f"   {_c('ASN', C.KEY).ljust(14)} "
                   f"{_c(', '.join(asn.get('numbers', [])) or 'n/a', C.VAL)}")
        out.append(f"   {_c('PREFIXES', C.KEY).ljust(14)} "
                   f"{_c(', '.join(asn.get('prefixes', [])) or 'n/a', C.VAL)}")
        out.append(f"   {_c('RIR', C.KEY).ljust(14)} "
                   f"{_c(', '.join(asn.get('rirs', [])) or 'n/a', C.VAL)}")
        out.append(f"   {_c('ORG', C.KEY).ljust(14)} "
                   f"{_c(', '.join(asn.get('orgs', [])) or 'n/a', C.VAL)}")
        dns_recs = ni.get("dns_records") or {}
        out.append("")
        for rt, vals in dns_recs.items():
            if not vals: continue
            v = ", ".join(vals[:5])
            if len(vals) > 5: v += f" {C.GRY}(+{len(vals)-5} more){C.RST}"
            out.append(f"   {_c(rt.ljust(6), C.KEY)} → {_c(v, C.VAL)}")
        anom = ni.get("anomalies") or []
        out.append("")
        out.append(f"   {_c('ANOMALIES', C.KEY).ljust(14)} "
                   f"{_c(str(len(anom)), C.BLD, C.WARN if anom else C.OK)} "
                   f"{_c(str(ni.get('severity_summary', {})), C.GRY)}")
        for a in anom[:5]:
            sev = a.get("severity", "info")
            sc = _severity_color(sev)
            conf_pct = a.get("confidence", 0)
            out.append(f"     {_c('[' + sev.ljust(13) + ']', sc)} "
                       f"{_c(a.get('type', '?').ljust(28), C.KEY)} "
                       f"{_c('conf=' + f'{conf_pct:.0f}' + '%', C.GRY)}")
            out.append(f"        {a.get('description', '')}")
        out.append(_section_footer())

    # [05b] PASSIVE OSINT — B2, B4, B5 fixes integrated
    rev_ip = ni.get("reverse_ip") or []
    rev_note = ni.get("reverse_ip_note") or ""
    otx_pd = ni.get("passive_dns_otx") or []
    # Prefer merged normalized if available
    pd_merged = ni.get("passive_dns_merged") or []
    idb = ni.get("internetdb") or {}
    if rev_ip or otx_pd or pd_merged or idb or rev_note:
        out.append(_section_header("5b", "Passive OSINT"))
        # Reverse IP — B4: show note when filtered for resolver/anycast
        if rev_note and not rev_ip:
            out.append(f"   {_c('REVERSE IP', C.KEY).ljust(14)} {_c(rev_note, C.GRY)}")
        elif rev_ip:
            out.append(f"   {_c('REVERSE IP', C.KEY).ljust(14)} "
                       f"{_c(str(len(rev_ip)) + ' domains share this IP', C.VAL)}")
            for dom in rev_ip[:8]:
                out.append(f"     {_c('·', C.GRY)} {_c(dom, C.VAL)}")
            if rev_note:
                out.append(f"     {_c(rev_note, C.DIM)}")
        # Passive DNS — B2: use normalized first_seen/last_seen, avoid identical date overwrite
        pd_display = pd_merged if pd_merged else otx_pd
        if pd_display:
            out.append(f"   {_c('PASSIVE DNS', C.KEY).ljust(14)} "
                       f"{_c(str(len(pd_display)) + ' historical records', C.VAL)}")
            for row in pd_display[:5]:
                h = row.get("hostname") or row.get("domain") or "?"
                # Support both old (first/last) and new (first_seen/last_seen)
                f_raw = row.get("first") or row.get("first_seen") or ""
                l_raw = row.get("last") or row.get("last_seen") or row.get("date") or ""
                f_ = str(f_raw)[:10] if f_raw else ""
                l_ = str(l_raw)[:10] if l_raw else ""
                # B2: distinguish missing first_seen
                if f_ and l_ and f_ == l_:
                    date_str = f_  # truly same date
                elif not f_ and l_:
                    date_str = f"N/A → {l_}"
                elif f_ and not l_:
                    date_str = f"{f_} → N/A"
                else:
                    date_str = f"{f_ or 'N/A'} → {l_ or 'N/A'}"
                out.append(f"     {_c('·', C.GRY)} {_c(h.ljust(40), C.VAL)} "
                           f"{_c(date_str, C.GRY)}")
        if idb:
            ports = idb.get("ports") or []
            # B5 fix: enrich ports with protocol/service via ports_parse
            enriched_ports = ports_parse(ports)
            hostnames = idb.get("hostnames") or []
            vulns = idb.get("vulns") or []
            if ports:
                display_ports = ', '.join(f"{e['port']}/{e['protocol']} {e['service']}" for e in enriched_ports[:15])
                out.append(f"   {_c('OPEN PORTS', C.KEY).ljust(14)} "
                           f"{_c(display_ports, C.WARN)}")
            if hostnames:
                out.append(f"   {_c('HOSTNAMES', C.KEY).ljust(14)} "
                           f"{_c(', '.join(hostnames[:5]), C.VAL)}")
            if vulns:
                out.append(f"   {_c('KNOWN VULNS', C.KEY).ljust(14)} "
                           f"{_c(', '.join(vulns[:5]), C.FAIL)}")
        out.append(_section_footer())

    # [05c] SUBDOMAINS (Phase 2)
    sub_enum = ni.get("subdomains") or {}
    subs = sub_enum.get("subdomains") or []
    if subs:
        out.append(_section_header("5c", f"Subdomain Enumeration ({len(subs)})"))
        srcs = sub_enum.get("sources", {})
        if srcs:
            out.append(f"   {_c('SOURCES', C.KEY).ljust(14)} "
                       f"{_c('  '.join(f'{k}={v}' for k, v in srcs.items()), C.GRY)}")
        for s in subs[:15]:
            out.append(f"     {_c('·', C.GRN)} {_c(s, C.VAL)}")
        if len(subs) > 15:
            out.append(f"     {_c(f'... and {len(subs)-15} more', C.GRY)}")
        out.append(_section_footer())

    # [05d] TYPOSQUATTING (Phase 2)
    typos = ni.get("typosquatting") or []
    if typos:
        out.append(_section_header("5d", f"Typosquatting Detection ({len(typos)})"))
        for t in typos[:10]:
            d_ = t.get("domain", "?")
            dist = t.get("distance", "?")
            reason = t.get("reason", "?")
            out.append(f"   {_c('⚠', C.WARN)} {_c(d_.ljust(40), C.FAIL)} "
                       f"{_c(f'd={dist} ({reason})', C.GRY)}")
        out.append(_section_footer())

    # [05e] CT DEEP ANALYSIS (Phase 2) — B6 fix
    ct_deep = ni.get("ct_deep") or {}
    ca_dist = ct_deep.get("ca_distribution") or {}
    suspicious_sans = ct_deep.get("suspicious_sans") or []
    cert_info = d.get("certificate_intelligence") or {}
    timeline = cert_info.get("timeline") or []
    # Also parse via ct_parse for enriched view
    parsed_certs = ct_parse([r for r in (cert_info.get("timeline") or [])]) if timeline else []
    if ca_dist or suspicious_sans or timeline or parsed_certs:
        out.append(_section_header("5e", "CT Deep Analysis"))
        if ca_dist:
            out.append(f"   {_c('CA DISTRIBUTION', C.KEY).ljust(20)}")
            for ca, n in sorted(ca_dist.items(), key=lambda x: -x[1])[:6]:
                out.append(f"     {_c('·', C.GRY)} {_c(ca.ljust(40), C.VAL)} "
                           f"{_c(f'{n} certs', C.GRY)}")
        if suspicious_sans:
            out.append(f"   {_c('SUSPICIOUS SANs', C.FAIL).ljust(20)} "
                       f"{_c(str(len(suspicious_sans)), C.BLD, C.WARN)}")
            for s in suspicious_sans[:5]:
                out.append(f"     {_c('⚠', C.WARN)} "
                           f"{_c(str(s.get('san','?')).ljust(50), C.FAIL)} "
                           f"{_c(s.get('reason',''), C.GRY)}")
        # B6: Show SAN, Issuer, Validity, Fingerprint per cert
        if timeline:
            out.append(f"   {_c('CERTIFICATES', C.KEY).ljust(20)} {_c(str(len(timeline)) + ' certs', C.VAL)}")
            for rec in timeline[:4]:
                san_list = rec.get("sans") or rec.get("san") or []
                if isinstance(san_list, str):
                    san_list = [san_list]
                sans_str = ", ".join(san_list[:3]) + (f" +{len(san_list)-3} more" if len(san_list) > 3 else "") if san_list else "no SAN"
                issuer = str(rec.get("issuer", "unknown"))[:50]
                vf = str(rec.get("valid_from", ""))[:10]
                vt = str(rec.get("valid_to", ""))[:10]
                fp = str(rec.get("fingerprint") or rec.get("fingerprint_sha256", ""))[:16]
                wild = " wildcard" if rec.get("wildcards") else ""
                out.append(f"     {_c('·', C.GRY)} {_c(sans_str[:60].ljust(60), C.VAL)}{_c(wild, C.YEL)}")
                out.append(f"       {_c('Issuer:', C.DIM)} {_c(issuer[:45], C.CYN)}")
                out.append(f"       {_c('Validity:', C.DIM)} {_c(f'{vf} → {vt}', C.GRY)}  {_c('FP:', C.DIM)} {_c(fp, C.DIM)}")
        elif parsed_certs:
            out.append(f"   {_c('CERTIFICATES', C.KEY).ljust(20)} {_c(str(len(parsed_certs)) + ' certs', C.VAL)}")
            for rec in parsed_certs[:4]:
                sans = rec.get("san", [])
                sans_str = ", ".join(sans[:3]) if sans else "no SAN"
                out.append(f"     {_c('·', C.GRY)} {_c(sans_str[:60], C.VAL)}")
                out.append(f"       {_c('Issuer:', C.DIM)} {_c(str(rec.get('issuer',''))[:45], C.CYN)}  {_c(str(rec.get('validity', {})), C.GRY)}")
        out.append(_section_footer())

    # [05f] WHOIS ENHANCED (Phase 2) — B3 fix
    whois_full = ni.get("whois_enhanced") or {}
    if whois_full:
        out.append(_section_header("5f", "WHOIS Enhanced"))
        # B3: clearly separate registration date vs update date
        parsed = whois_parse(whois_full) if whois_full else {}
        # Show structured fields
        for k in ("organization", "name", "handle", "country",
                  "netrange", "cidr", "abuse_email", "abuse_phone", "status"):
            v = whois_full.get(k)
            if not v: continue
            kcolor = C.KEY
            vcolor = C.CYN if k in ("abuse_email", "abuse_phone") else C.VAL
            out.append(f"   {_c(k.ljust(16), kcolor)} {_c(str(v)[:60], vcolor)}")
        # Registration vs Updated with distinct labels
        if parsed.get("reg_date") or whois_full.get("created"):
            rv = parsed.get("reg_date") or whois_full.get("created")
            out.append(f"   {_c('reg_date'.ljust(16), C.KEY)} {_c(str(rv)[:60], C.GRY)} {_c('(Registration)', C.DIM)}")
        if parsed.get("updated_date") or whois_full.get("updated"):
            uv = parsed.get("updated_date") or whois_full.get("updated")
            out.append(f"   {_c('updated_date'.ljust(16), C.KEY)} {_c(str(uv)[:60], C.GRY)} {_c('(Last Updated)', C.DIM)}")
        if parsed.get("reg_date_note"):
            out.append(f"   {_c('note', C.DIM)} {_c(parsed.get('reg_date_note'), C.GRY)}")
        # Fallback show raw created/updated if not yet covered
        if not parsed.get("reg_date") and whois_full.get("created"):
            out.append(f"   {_c('created'.ljust(16), C.KEY)} {_c(str(whois_full.get('created'))[:60], C.GRY)}")
        if not parsed.get("updated_date") and whois_full.get("updated"):
            out.append(f"   {_c('updated'.ljust(16), C.KEY)} {_c(str(whois_full.get('updated'))[:60], C.GRY)}")
        out.append(_section_footer())

    # [05g] REVERSE IP (Enhanced)
    rev_susp = ni.get("reverse_ip_suspicious") or []
    if rev_susp:
        out.append(_section_header("5g", f"Suspicious Co-Hosted ({len(rev_susp)})"))
        for s in rev_susp[:10]:
            out.append(f"   {_c('⚠', C.WARN)} "
                       f"{_c(str(s.get('domain','?')).ljust(50), C.FAIL)} "
                       f"{_c(s.get('reason',''), C.GRY)}")
        out.append(_section_footer())

    # [07] MITRE ATT&CK + ATTRIBUTION (Phase 3)
    p3 = d.get("phase3") or {}
    if p3.get("enabled"):
        mitre = p3.get("mitre") or {}
        actors = p3.get("actors") or []
        rel = p3.get("related_infra") or []
        out.append(_section_header("08", "Threat Attribution (MITRE ATT&CK)"))
        kc = mitre.get("kill_chain") or []
        if kc:
            out.append(f"   {_c('KILL CHAIN', C.KEY).ljust(20)}")
            for phase in kc:
                active = phase.get("active", False)
                tids = phase.get("techniques", [])
                if active:
                    out.append(f"     {_c('x', C.FAIL, C.BLD)} "
                               f"{_c(phase['tactic'].ljust(24), C.FAIL, C.BLD)} "
                               f"{_c(', '.join(tids) if tids else 'observed', C.GRY)}")
                else:
                    out.append(f"     {_c('.', C.GRY)} "
                               f"{_c(phase['tactic'].ljust(24), C.GRY)}")
        techs = mitre.get("techniques") or []
        if techs:
            out.append("")
            out.append(f"   {_c('TECHNIQUES', C.KEY).ljust(20)} "
                       f"({len(techs)} matched)")
            for t in techs[:10]:
                conf = t.get("confidence", 0)
                cc = C.FAIL if conf >= 70 else C.WARN if conf >= 40 else C.GRY
                out.append(f"     {_c(t['id'].ljust(11), C.BLD, C.WARN)} "
                           f"{_c(t['name'][:38].ljust(40), C.WHT)} "
                           f"{_c(str(int(conf)).rjust(3) + '%', C.BLD, cc)} "
                           f"{_c('[' + t['tactic'][:18] + ']', C.GRY)}")
                for r_ in (t.get("reasons") or [])[:2]:
                    out.append(f"                    {_c('.', C.GRY)} {r_}")
        if actors:
            out.append("")
            out.append(f"   {_c('ACTOR ATTRIBUTION', C.KEY).ljust(20)} "
                       f"({len(actors)} matched)")
            for a in actors[:5]:
                conf = a.get("confidence", 0)
                cc = C.FAIL if conf >= 70 else C.WARN
                out.append(f"     {_c('!', C.FAIL)} "
                           f"{_c(a['actor'].ljust(35), C.FAIL, C.BLD)} "
                           f"{_c(str(int(conf)).rjust(3) + '%', cc)} "
                           f"{_c('evidence=' + str(a['evidence_count']), C.GRY)}")
        if rel:
            out.append("")
            out.append(f"   {_c('RELATED INFRA', C.KEY).ljust(20)} "
                       f"({len(rel)} IPs in same ASN)")
            for ri in rel[:8]:
                out.append(f"     {_c('*', C.WARN)} "
                           f"{_c(str(ri.get('ip','?')).ljust(18), C.FAIL)} "
                           f"{_c(str(ri.get('malware','')).ljust(15), C.WARN)} "
                           f"{_c(str(ri.get('threat_type','')), C.GRY)}")
        if not (kc and any(p.get("active") for p in kc)) and not techs and not actors and not rel:
            out.append(f"   {_c('No threat attribution evidence', C.OK)}")
        out.append(_section_footer())

    # [06] CERTIFICATES
    ci = d.get("certificate_intelligence") or {}
    if ci.get("total"):
        out.append(_section_header("06", "Certificate Intelligence"))
        out.append(f"   {_c('TOTAL', C.KEY).ljust(14)} "
                   f"{_c(ci.get('total', 0), C.BLD, C.VAL)}")
        bs = ci.get("by_status", {})
        cur_n = bs.get("CURRENT", 0)
        hist_n = bs.get("HISTORICAL", 0)
        unreach_n = bs.get("UNREACHABLE", 0)
        status_str = f"CURRENT={cur_n}  HISTORICAL={hist_n}  UNREACHABLE={unreach_n}"
        out.append(f"   {_c('STATUS', C.KEY).ljust(14)} "
                   f"{_c(status_str, C.VAL)}")
        exp = ci.get("expired", 0)
        near = ci.get("near_expiry", 0)
        weak = ci.get("weak", 0)
        exp_c = C.FAIL if exp else C.OK
        near_c = C.WARN if near else C.OK
        weak_c = C.FAIL if weak else C.OK
        out.append(f"   {_c('EXPIRED', C.KEY).ljust(14)} "
                   f"{_c(str(exp), C.BLD, exp_c)}    "
                   f"{_c('NEAR-EXPIRY', C.KEY).ljust(14)} "
                   f"{_c(str(near), C.BLD, near_c)}    "
                   f"{_c('WEAK ALGO', C.KEY).ljust(14)} "
                   f"{_c(str(weak), C.BLD, weak_c)}")
        wc = ci.get("wildcards") or []
        if wc:
            out.append(f"   {_c('WILDCARDS', C.KEY).ljust(14)} "
                       f"{_c(', '.join(wc[:5]), C.MAG)}")
        out.append(_section_footer())

    # [09] EVIDENCE ENGINE (Stage 2) — traceable source, freshness, status
    ev_list = d.get("evidence") or []
    if ev_list:
        out.append(_section_header("09", f"Evidence Engine ({len(ev_list)})"))
        for ev in ev_list[:8]:
            try:
                src = str(ev.get("source", "?"))
                val = str(ev.get("value", ""))[:45]
                conf = float(ev.get("confidence", 0))
                fresh = str(ev.get("freshness", "?"))
                status = str(ev.get("status", "?"))
                sc = C.OK if status == "OK" else C.WARN if status == "FAILED" else C.GRY
                fc = C.OK if fresh == "FRESH" else C.WARN if fresh == "STALE" else C.GRY
                out.append(f"   {_c(f'[{src}]', C.KEY)} {_c(val.ljust(45), C.VAL)} {_c(f'conf={conf:.2f}', C.GRY)} {_c(fresh, fc)} {_c(status, sc)}")
                # Show normalized and metadata hint
                meta = ev.get("metadata", {}) or {}
                if meta.get("field"):
                    out.append(f"     {_c('field='+str(meta.get('field')), C.DIM)} {_c('norm='+str(ev.get('normalized_value',''))[:30], C.DIM)} {_c('target='+str(meta.get('target','')), C.DIM)}")
            except Exception:
                continue
        if len(ev_list) > 8:
            out.append(f"   {_c(f'... and {len(ev_list)-8} more evidences', C.GRY)}")
        out.append(_section_footer())

    # FOOTER
    out.append("")
    out.append(f"{C.DRED}  ● {C.GRN}ReconIP v30.1{C.RST}  {C.DRED}●{C.RST}  "
               f"{C.GRY}Connectivity ≠ Maliciousness. Secrets are redacted.{C.RST}  "
               f"{C.DRED}●{C.RST}")
    out.append(_c("═" * min(_w(), 100), C.DRED))
    return "\n".join(out)

# ============================================================
#  REPORT BUILDERS
# ============================================================
def build_report(result):
    pb = result.get("phase_b", {}) or {}
    fa = pb.get("final_assessment", {}) or {}
    th = pb.get("threat", {}) or {}
    pi = result.get("phase_i", {}) or {}
    ni = result.get("network_intelligence", {}) or {}
    ci = result.get("certificate_intelligence", {}) or {}
    sections = []
    def add(sid, title, items, narrative=""):
        sections.append({"id": sid, "title": title,
                          "narrative": narrative, "items": items})
    add(1, "Executive Summary", [
        {"field": "target", "value": result.get("ip"), "class": "Observed"},
        {"field": "scan_status", "value": result.get("scan_status"), "class": "Derived"},
        {"field": "threat_score", "value": th.get("score", 0), "class": "Derived"},
        {"field": "final_assessment", "value": fa.get("assessment"), "class": "Derived"},
        {"field": "confidence", "value": fa.get("confidence"), "class": "Derived"},
    ], f"Target {result.get('ip')} - {fa.get('assessment','Unknown')}")
    t = result.get("trusted", {}) or {}
    add(3, "Infrastructure", [
        {"field": "asn", "value": (t.get("asn") or {}).get("value"), "class": "Validated"},
        {"field": "organization", "value": (t.get("organization") or {}).get("value"),
         "class": "Validated"},
        {"field": "isp", "value": (t.get("isp") or {}).get("value"), "class": "Validated"},
    ])
    add(4, "Geolocation", [
        {"field": "country", "value": (t.get("country") or {}).get("value"),
         "class": "Validated"},
        {"field": "city", "value": (t.get("city") or {}).get("value"),
         "class": "Validated"},
        {"field": "latitude", "value": (t.get("latitude") or {}).get("value"),
         "class": "Validated"},
        {"field": "longitude", "value": (t.get("longitude") or {}).get("value"),
         "class": "Validated"},
    ])
    dns = ni.get("dns_records", {})
    add(5, "DNS", [{"field": k, "value": ", ".join(v[:3]), "class": "Observed"}
                    for k, v in dns.items() if v])
    add(6, "ASN/Network", [
        {"field": "asn_numbers",
         "value": ", ".join(ni.get("asn", {}).get("numbers", [])),
         "class": "Observed"},
        {"field": "prefixes",
         "value": ", ".join(ni.get("asn", {}).get("prefixes", [])),
         "class": "Observed"},
    ])
    sub_enum = ni.get("subdomains") or {}
    if sub_enum.get("subdomains"):
        add(7, "Subdomains", [
            {"field": sd, "value": "discovered", "class": "Observed"}
            for sd in sub_enum["subdomains"][:50]
        ], f"Total: {sub_enum.get('total', 0)}")
    typos = ni.get("typosquatting") or []
    if typos:
        add(8, "Typosquatting", [
            {"field": t_.get("domain"), "value": f"d={t_.get('distance')} ({t_.get('reason')})",
             "class": "Derived"} for t_ in typos
        ])
    whois_full = ni.get("whois_enhanced") or {}
    if whois_full:
        add(9, "WHOIS", [{"field": k, "value": v, "class": "Observed"}
                          for k, v in whois_full.items()])
    add(10, "Threat Intelligence", [
        {"field": "score", "value": pi.get("score", 0), "class": "Derived"},
        {"field": "coverage", "value": pi.get("coverage", 0), "class": "Derived"},
        {"field": "confidence", "value": pi.get("confidence", 0), "class": "Derived"},
    ] + [{"field": f"provider:{p.get('provider')}", "value": p.get("status"),
          "class": "Observed"} for p in pi.get("providers", [])])
    cs = result.get("conflicts", []) or []
    add(11, "Conflicts", [{"field": c.get("field"), "value": c.get("description"),
                            "class": "Derived"} for c in cs])
    add(18, "Final Assessment", [
        {"field": "assessment", "value": fa.get("assessment"), "class": "Derived"},
        {"field": "confidence", "value": fa.get("confidence"), "class": "Derived"},
        {"field": "recommendation", "value": fa.get("recommendation"),
         "class": "Derived"},
    ])
    return {"generated_at": now(), "target": result.get("ip", ""),
            "sections": sections}

def render_report(rep, fmt):
    fmt = (fmt or "txt").lower()
    if fmt == "json":
        return json.dumps(redact(rep), indent=2, ensure_ascii=False, default=str)
    if fmt == "html":
        parts = ["<!DOCTYPE html><html><head><meta charset='utf-8'>",
                 f"<title>ReconIP — {_html.escape(rep['target'])}</title>",
                 "<style>body{font-family:sans-serif;margin:24px;background:#f6f8fa}",
                 "section{background:#fff;border:1px solid #d0d7de;border-radius:6px;padding:16px;margin:12px 0}",
                 "h2{font-size:16px;margin:0 0 10px}table{width:100%;border-collapse:collapse;font-size:13px}",
                 "td,th{padding:6px;border-bottom:1px solid #eaeef2;text-align:left}",
                 "</style></head><body>",
                 f"<h1>ReconIP Report — {_html.escape(rep['target'])}</h1>"]
        for s in rep["sections"]:
            parts.append(f"<section><h2>[{s['id']}] {_html.escape(s['title'])}</h2>")
            if s.get("narrative"):
                parts.append(f"<p><i>{_html.escape(s['narrative'])}</i></p>")
            if s.get("items"):
                parts.append("<table><thead><tr><th>Class</th><th>Field</th>"
                             "<th>Value</th></tr></thead><tbody>")
                for it in s["items"]:
                    c = it.get("class", "Unknown")
                    v = it.get("value") if it.get("value") is not None else "(not available)"
                    parts.append(f"<tr><td>{_html.escape(c)}</td>"
                                 f"<td>{_html.escape(str(it.get('field','')))}</td>"
                                 f"<td>{_html.escape(str(v))}</td></tr>")
                parts.append("</tbody></table>")
            parts.append("</section>")
        parts.append("</body></html>")
        return "".join(parts)
    L = ["=" * 100, f"  RECONIP ANALYST REPORT — {rep['target']}", "=" * 100]
    for s in rep["sections"]:
        L.append(f"\n[{s['id']}] {s['title']}")
        if s.get("narrative"): L.append(f"  {s['narrative']}")
        for it in s.get("items", []):
            v = it.get("value") if it.get("value") is not None else "(not available)"
            L.append(f"  [{it.get('class','?')[:10]:<10}] "
                     f"{it.get('field',''):<30} = {v}")
    return "\n".join(L)

# ============================================================
#  CLI
# ============================================================
def run_single(target, output, report_fmt=None, report_file=None):
    try:
        validate_target(target, allow_private=PN["allow_private_targets"])
    except SecurityError as e:
        print(f"{C.FAIL}SECURITY:{C.RST} {e}"); return
    data = recon(target)
    if report_fmt:
        rep = build_report(data)
        content = render_report(rep, report_fmt)
        if report_file:
            open(report_file, "w", encoding="utf-8").write(content)
            print(f"Written: {report_file}")
        else:
            print(content)
        return
    if output == "json":
        print(json.dumps(redact(data), indent=2, ensure_ascii=False, default=str))
    else:
        print(render_text(data))

def main():
    global INTEL_DB
    p = argparse.ArgumentParser(
        description="ReconIP v21.3 — OSINT/CTI Platform")
    p.add_argument("targets", nargs="*")
    p.add_argument("-o", "--output", choices=["text", "json"], default="text")
    p.add_argument("--parallel", action="store_true",
                   help="Parallel collection (faster)")
    p.add_argument("--report", choices=["txt", "json", "html"], default=None)
    p.add_argument("--report-file", metavar="PATH")
    p.add_argument("--export", choices=["stix", "misp"], default=None)
    p.add_argument("--api", action="store_true")
    p.add_argument("--api-host", default=None)
    p.add_argument("--api-port", type=int, default=None)
    p.add_argument("--metrics", action="store_true")
    p.add_argument("--health", action="store_true")
    p.add_argument("--allow-private", action="store_true")
    p.add_argument("--no-db", action="store_true")
    p.add_argument("--timeout", type=int, default=None)
    args = p.parse_args()

    if args.allow_private: PN["allow_private_targets"] = True
    if args.timeout: http.to = (2, args.timeout)

    if not args.no_db and PE.get("enabled", True):
        try:
            INTEL_DB = DB(PE["db_path"])
            with INTEL_DB._l:
                c = INTEL_DB._c()
                try:
                    c.execute("UPDATE scan_runs SET status='FAILED', finished_at=? "
                              "WHERE status='RUNNING'", (now(),))
                finally:
                    c.close()
        except Exception as e:
            log.error(f"db init: {e}")
            INTEL_DB = None

    if args.health:
        print(json.dumps({"providers": {n: h.to_dict() for n, h in _health.items()},
                          "uptime": round(time.time() - _START_T, 1)},
                         indent=2, default=str))
        return
    if args.metrics:
        print(json.dumps({"jobs": len(JOBS),
                          "cache": CACHE.stats() if CACHE else {},
                          "providers_health": len(_health)}, indent=2))
        return
    if args.api:
        httpd = start_api(args.api_host, args.api_port)
        print(f"{C.OK}API running on "
              f"http://{httpd.server_address[0]}:{httpd.server_address[1]}{C.RST}")
        print("Ctrl+C to stop.")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            httpd.shutdown()
        return

    if not args.targets:
        print(render_text({"input": "?", "ip": "?", "scan_status": "IDLE",
                            "module_statuses": {}, "phase_b": {}, "phase_i": {},
                            "trusted": {}, "network_intelligence": {},
                            "certificate_intelligence": {}, "conflicts": []}))
        print(f"\n{C.INFO}Interactive mode (type 'quit' to exit){C.RST}")
        while True:
            try:
                t = input(f"{C.KEY}IP/domain:{C.RST} ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if t.lower() in ("quit", "exit", ""): break
            run_single(t, args.output, args.report, args.report_file)
        return

    for t in args.targets:
        run_single(t, args.output, args.report, args.report_file)
        if args.export:
            data = recon(t)
            if args.export == "stix":
                print(json.dumps(export_stix(data), indent=2, default=str))
            elif args.export == "misp":
                print(json.dumps(export_misp(data), indent=2, default=str))

if __name__ == "__main__":
    main()
