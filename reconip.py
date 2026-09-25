#!/usr/bin/env python3
"""ReconIP v21.2 — OSINT/CTI Platform"""
import argparse, sys, os, re, json, time, logging, socket, ssl
import base64
import csv, io
import ipaddress, subprocess, hashlib, math, asyncio, sqlite3
import threading, uuid, random, shutil, signal, pathlib
import hmac, urllib.request, urllib.error, urllib.parse
import html as _html
import concurrent.futures
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from urllib.parse import urlparse
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict, OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from abc import ABC, abstractmethod
import contextvars

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.layout import Layout
    from rich.columns import Columns
    from rich.tree import Tree
    from rich.rule import Rule
    from rich.align import Align
    from rich.box import (
        ROUNDED, HEAVY, DOUBLE, SIMPLE, MINIMAL,
        SQUARE, ASCII, ASCII2, ASCII_DOUBLE_HEAD,
    )
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn,
        TimeElapsedColumn, TimeRemainingColumn, MofNCompleteColumn,
    )
    _RICH_AVAILABLE = True
    _RICH_PROGRESS_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False
    _RICH_PROGRESS_AVAILABLE = False


# RichHandler is a separate import path. It may be missing even when
# the base rich package is present (unlikely, but possible).
try:
    from rich.logging import RichHandler
    _RICH_LOG_AVAILABLE = True
except ImportError:
    _RICH_LOG_AVAILABLE = False

# ---- Identity constants (Stage B2, config-overridable) ----

DEFAULT_TOOL_NAME = "RECONIP"

DEFAULT_TAGLINE = "EVIDENCE-DRIVEN OSINT PLATFORM"

# ASCII art for the tool name (block letters for the default name).
# ─────────────────────────────────────────────────────────────
# Banner arts — one per width tier (Stage C3.2).
#
# Widths are chosen so that:
#   WIDE    fits in terminals >= 62 columns
#   MEDIUM  fits in terminals >= 50 columns
#   COMPACT fits in terminals >= 32 columns
#
# The selector picks the largest art that fits, or returns None
# if the terminal is too narrow even for the compact art.
# ─────────────────────────────────────────────────────────────

# WIDE — ANSI Shadow style (largest)
BANNER_WIDE = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║██████╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║██╔═══╝
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝
""".strip("\n")

# MEDIUM — compressed ANSI Shadow style
BANNER_MEDIUM = r"""
████╗ ██████╗ ██████╗ ██████╗ ███╗ ██╗██╗██████╗
██╔═██╗██╔═══╝██╔═══╝██╔══██╗████╗██║██║██╔══██╗
█████╔╝█████╗ ██║    ██║  ██║██╔███║██║██████╔╝
██╔═██╗██╔══╝ ██║    ██║  ██║██║╚██║██║██╔═══╝
██║ ██║██████╗╚█████╗╚█████╔╝██║ ╚█║██║██║
╚═╝ ╚═╝╚═════╝ ╚════╝ ╚════╝ ╚═╝  ╚╝╚═╝╚═╝
""".strip("\n")

# COMPACT — small block font
BANNER_COMPACT = r"""
█▀█ █▀▀ █▀▀ █▀█ █▄░█ █ █▀█
█▀▄ ██▄ █▄▄ █▄█ █░▀█ █ █▀▀
""".strip("\n")

# Back-compat alias (Stage B2 name). Prefer the tiered arts above.
DEFAULT_BANNER_ART = BANNER_WIDE


def _banner_art_width(art: str) -> int:
    """Return the width of the widest line in the art (Stage C3.2)."""
    try:
        return max(len(line) for line in str(art).split("\n"))
    except Exception:
        return 0


def _select_banner_art(term_width: int) -> Optional[str]:
    """
    Return the widest art that fits the terminal (Stage C3.2).

    Fitting rule: art_width + PADDING + BORDER <= term_width,
    where PADDING = 2 (1 char each side) and BORDER = 2.

    Returns None when no art fits.
    """
    try:
        width = int(term_width)
    except Exception:
        return None
    PADDING_AND_BORDER = 4
    for art in (BANNER_WIDE, BANNER_MEDIUM, BANNER_COMPACT):
        try:
            if _banner_art_width(art) + PADDING_AND_BORDER <= width:
                return art
        except Exception:
            continue
    return None

import yaml, requests, dns.resolver, dns.reversename, dns.exception, dns.rdatatype
try: import geoip2.database; GEOIP2 = True
except ImportError: geoip2 = None; GEOIP2 = False
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as _ch
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, ec as _ec, dsa as _dsa, ed25519 as _ed, ed448 as _ed4
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    from cryptography.x509.oid import NameOID
    CRYPTO = True
except ImportError:
    CRYPTO = False
    try:
        from cryptography.x509.oid import NameOID  # type: ignore
    except Exception:
        NameOID = None  # type: ignore
    try:
        from cryptography.hazmat.primitives import serialization  # type: ignore
    except Exception:
        serialization = None  # type: ignore

# ============================================================
#  AUTH PROVIDER REGISTRY — Stage A2
#  Context-local reference to the active providers dict so
#  _lookup_env_for() can resolve env var names without changing
#  _log_auth_summary() signatures. Safe across threads.
# ============================================================
_PROVIDERS_REGISTRY: "contextvars.ContextVar[Optional[Dict[str, Any]]]" = \
    contextvars.ContextVar("_PROVIDERS_REGISTRY", default=None)


def _set_providers_registry(providers: Optional[Dict[str, Any]]) -> None:
    """Publish the active providers dict for auth diagnostics (Stage A2)."""
    try:
        _PROVIDERS_REGISTRY.set(providers)
    except Exception:
        pass


def _lookup_env_for(provider_name: str) -> Optional[str]:
    """
    Look up the env var name declared for a provider (Stage A2).

    Returns None when the registry is unavailable, in which case
    callers fall back to logging only the provider name.
    """
    try:
        providers = _PROVIDERS_REGISTRY.get()
    except Exception:
        return None
    if not isinstance(providers, dict):
        return None
    try:
        p = providers.get(provider_name)
    except Exception:
        return None
    try:
        return getattr(p, "auth_env", None) or None
    except Exception:
        return None

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
    sig = "X7  •  X7Λ†ΞX"
    pad = (w - 4 - len(sig)) // 2
    lines.append(C.DRED + "║ " + C.RST + C.GRY + " " * pad + sig +
                 " " * (w - 4 - len(sig) - pad) + C.RST + C.DRED + " ║" + C.RST)
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
                 "confidence_defaults": {"dns": 0.95, "whois": 0.85, "ct": 0.9, "threat": 0.5, "passive_dns": 0.6}},
    "threat_intelligence": {"min_coverage": 0.5, "max_stale_seconds": 86400, "agreement_bonus": 0.1,
                            "disagreement_penalty": 0.2, "score_range": [0, 100],
                            "provider_weights": {"abuseipdb": 1.0, "virustotal": 1.0, "alienvault": 0.8, "greynoise": 0.7, "spamhaus_drop": 0.9, "threatfox": 0.9, "urlhaus": 0.8, "feodo": 0.7, "sslbl": 0.7, "cins": 0.6}},
    "dns": {"records": ["A", "AAAA", "PTR", "NS", "MX", "TXT", "CAA", "SOA", "CNAME"], "ttl_analysis": True, "mail_analysis": True, "consistency_checks": True, "security_checks": True, "cname_chain_max_hops": 5, "low_ttl_threshold": 60, "high_ttl_threshold": 86400,
           "known_mail_providers": {"google": ["google.com", "googlemail.com", "gmail.com"], "microsoft": ["outlook.com", "office365.com", "protection.outlook.com"], "cloudflare": ["cloudflare.net", "cloudflare.com"], "amazon": ["amazonaws.com", "ses.amazonaws.com"], "proofpoint": ["pphosted.com", "proofpoint.com"], "mimecast": ["mimecast.com"], "zoho": ["zoho.com"], "yandex": ["yandex.net", "yandex.ru"]}},
    "infrastructure": {"include_peering": True, "include_history": True, "rdap_endpoint": "https://rdap.arin.net/registry/ip/{ip}", "asn_lookup_source": "team-cymru", "classify_asn": True, "related_infrastructure": True, "max_sibling_prefixes": 5, "asn_type_patterns": {"hosting": ["google", "amazon", "microsoft", "cloudflare", "akamai", "fastly", "hosting", "datacenter", "vps", "cloud"], "education": ["university", "college", "edu"], "government": ["government", "gov", "ministry"], "isp": ["telecom", "mobile", "broadband", "isp"]}},
    "certificate": {"include_expired": True, "include_san": True, "include_fingerprint": True, "live_handshake": True, "ct_source": "crt.sh", "ct_timeout": 15, "near_expiry_days": 30, "weak_algorithms": ["sha1", "md5"], "min_rsa_key_size": 2048, "max_wildcards_before_warning": 5, "max_shared_san_before_warning": 3, "ignore_private_certs": False},
    "passive_dns": {"timeline": True, "churn_threshold": 5, "active_window_days": 30, "short_lived_days": 7, "max_related_domains": 50, "max_churn_domains": 20, "sources": []},
    "history": {"enabled": True, "db_path": "reconip.db", "compare_fields": ["dns", "asn", "prefix", "certificate", "whois", "threat", "domains"], "severity_map": {"certificate.fingerprint_sha256": "critical", "certificate.issuer_cn": "high", "asn.asn": "critical", "asn.asn_name": "moderate", "prefix.cidr": "high", "prefix.rir": "moderate", "dns.NS": "high", "dns.MX": "moderate", "dns.A": "moderate", "dns.AAAA": "moderate", "dns.TXT": "low", "dns.CAA": "low", "whois.abuse_email": "critical", "whois.org": "moderate", "whois.country": "moderate", "threat.observed_threat_score": "high", "threat.threat_confidence": "high", "domains": "low"}, "max_changes_in_report": 100},
    "anomaly": {"enabled": True, "checks": ["dns", "cert", "asn", "history", "infra", "provider", "stale"], "max_stale_seconds": 86400, "max_anomalies_in_report": 200, "severity_buckets": {"informational": 0, "low": 1, "moderate": 2, "high": 3}},
    "correlation": {"enabled": True, "min_shared": 1, "include_nodes": True, "include_edges": True, "max_shared_in_report": 100, "max_related_targets": 50, "node_types": ["ip", "asn", "prefix", "organization", "domain", "nameserver", "mailserver", "certificate", "san", "passive_dns_domain", "history", "threat_intel"], "edge_types": ["belongs_to_asn", "in_prefix", "announces", "owned_by", "resolves_to", "has_ptr", "has_nameserver", "has_mailserver", "has_cname", "uses_certificate", "certificate_covers", "appears_in_passive_dns", "has_history", "has_threat_intel"], "notes": ["A shared relationship indicates shared infrastructure, not shared intent.", "Shared ASN, prefix, or nameserver may be normal for CDNs, hosting providers, or cloud platforms.", "Shared certificate is a stronger signal of shared ownership, but can also be a shared CDN certificate.", "Correlation is evidence, not a verdict. Always validate before drawing conclusions."]},
    "vulnerability": {"enabled": True, "require_validation": True, "use_nvd_api": False, "nvd_api_key_env": "NVD_API_KEY", "min_technology_confidence": 0.7, "max_candidates": 50, "severity_buckets": {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.0}, "notes": ["A CVE matching a version is a CANDIDATE, not a confirmation.", "A candidate is not a vulnerability.", "A vulnerability is not an exploit.", "An exploit is not an impact.", "Validation on the target is required before any conclusion."]},
    "fingerprinting": {"enabled": True, "min_confidence": 0.7, "active_banner_grab": False, "passive_hints": True, "http_head_request": False, "tls_extension_probe": False, "ssh_banner": False, "smtp_banner": False, "dns_version_probe": False, "max_banner_length": 4096, "notes": ["A banner is a hint, not a fact.", "A version is a claim, not a certainty.", "If evidence is insufficient, the tool returns UNKNOWN.", "Active banner grabbing is disabled by default."]},
    "attack_surface": {"enabled": True, "port_scan": False, "authorized": False, "authorized_targets": [], "include_sensitive": True, "max_services_in_report": 200, "imported_services": [], "notes": ["OPEN \u2260 VULNERABLE.", "A detected service is not a confirmed vulnerability.", "Active scanning is disabled by default.", "No exploitation is performed."]},
    "timeouts": {"default": 10, "dns": 5, "http": 10},
    "confidence": {"enabled": True, "separate": True, "weights": {"data": 0.4, "threat": 0.3, "geo": 0.2, "assessment": 0.1}, "data_weights": {"freshness": 0.4, "status": 0.3, "coverage": 0.3}, "threat_weights": {"coverage": 0.4, "agreement": 0.3, "freshness": 0.3}, "geo_weights": {"country_agreement": 0.5, "field_availability": 0.5}, "labels": {"high": 0.85, "moderate": 0.65, "low": 0.40, "very_low": 0.0}, "notes": ["Confidence is not accuracy.", "Confidence is not certainty.", "Confidence is the tool's own estimation of how much it knows.", "A low-confidence report is not a bad report — it is an honest one."]},
    "scoring": {"enabled": True, "explain": True, "weights": {"threat": 1.0, "infra": 0.8, "data_quality": 0.6, "exposure": 0.7, "anomaly": 0.5, "coverage": 0.4}, "labels": {"very_low": 0.0, "low": 20.0, "moderate": 40.0, "high": 60.0, "very_high": 80.0}, "notes": ["A score is not a verdict.", "A score is not a fact.", "A score is an explainable estimate.", "Every score must answer: WHY this number?"]},
    "reports": {"default_format": "html", "output_dir": "reports/", "include_raw": False, "classification": "UNCLASSIFIED", "formats": ["json", "html", "markdown", "csv", "stix", "misp"], "sections": ["target", "executive", "data_quality", "network", "dns", "cert", "passive_dns", "history", "threat", "correlation", "attack_surface", "technology", "vuln", "anomalies", "evidence", "confidence", "limitations", "next"], "max_anomalies_in_html": 100, "max_candidates_in_html": 50, "notes": ["The report is evidence-driven.", "It does not claim compromise, exploitation, or impact.", "Every finding must be validated in context."]},
    "version": "v42.1",
    "display": {"enabled": True, "mode": "terminal", "show_banner": True,
                "show_all_sections": True, "show_reports_summary": True,
                "show_progress": True, "width": None, "box_style": "rounded",
                "colors": {"primary": "cyan", "accent": "magenta", "success": "green",
                           "warning": "yellow", "danger": "red", "muted": "dim",
                           "highlight": "bold white", "border": "cyan",
                           "label": "bold", "value": ""}},
    "batch": {"enabled": True, "max_workers": 4, "max_workers_hard_limit": 16, "max_targets": 1000, "correlate": True, "quiet": False, "input_file": {"allow_comments": True, "allow_blank_lines": True, "strip_whitespace": True}, "notes": ["Each target is processed in isolation.", "One target's failure does not affect another.", "Cross-target correlation is evidence-driven.", "A shared relationship across targets is not shared intent."]},
    "performance": {"parallel": True, "max_workers": 8, "timeout_budget": 30, "min_timeout_budget": 10, "max_timeout_budget": 120, "default_min_interval": 0.0, "rate_limits": {"abuseipdb": 2.0, "virustotal": 15.0, "threatfox": 1.0, "alienvault": 6.0, "greynoise": 3.0, "spamhaus_drop": 5.0, "urlhaus": 2.0, "feodo": 2.0, "sslbl": 2.0, "cins": 2.0}, "priority_weights": {"reliability": 0.5, "weight": 0.3, "configured_bonus": 0.2}, "circuit_breaker": {"error_rate_threshold": 0.8, "penalty": 1.0}, "cache": {"enabled": True, "ttl_seconds": 3600}, "notes": ["Speed is a property of execution, not a property of evidence.", "Every provider still returns an Evidence object.", "Failed providers are never silently skipped.", "Rate limits are enforced locally per provider.", "Timeout budget caps total provider time."]},
    "cache": {"enabled": True, "db_path": "reconip_cache.db", "ttl_seconds": 3600, "stale_threshold": 7200, "expired_threshold": 86400, "purge_expired": True, "cache_failures": False, "cache_provider_results": True, "cache_dns": True, "cache_whois": True, "cache_certificates": True, "cache_passive_dns": True, "provider_ttls": {"abuseipdb": 1800, "virustotal": 3600, "alienvault": 3600, "greynoise": 1800, "spamhaus_drop": 7200, "threatfox": 1800, "urlhaus": 1800, "feodo": 3600, "sslbl": 3600, "cins": 3600}, "section_ttls": {"dns": 3600, "whois": 86400, "certificate": 86400, "passive_dns": 3600}, "notes": ["Cache is a memory, not a source of truth.", "FRESH cache may skip a query.", "STALE cache is marked and used only as fallback.", "EXPIRED cache is never used.", "Failed providers are never cached."]},
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
# ============================================================
#  AUTH SUPPORT — v44.5 (Stage R4)
#  Declarative, config-driven authentication. Secrets live in
#  environment variables only and are scrubbed from logs/evidence.
# ============================================================
_LOADED_SECRETS: set = set()
_SECRETS_LOCK = threading.Lock()


def _register_secret(secret: Optional[str]) -> None:
    """
    Register a secret for scrubbing. No-op if secret is None or empty.
    """
    if secret and isinstance(secret, str) and len(secret) >= 4:
        try:
            with _SECRETS_LOCK:
                _LOADED_SECRETS.add(secret)
        except Exception:
            _LOADED_SECRETS.add(secret)


def _scrub(text: Any) -> Any:
    """
    Replace any registered secret in a string with '***REDACTED***'.
    Non-strings are returned unchanged.
    """
    if not isinstance(text, str):
        return text
    try:
        secrets = list(_LOADED_SECRETS)
    except Exception:
        return text
    for s in secrets:
        if s and s in text:
            text = text.replace(s, "***REDACTED***")
    return text


def _scrub_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively scrub secrets from a dict. Returns a new dict.
    """
    if not isinstance(d, dict):
        return d
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, str):
            out[k] = _scrub(v)
        elif isinstance(v, dict):
            out[k] = _scrub_dict(v)
        elif isinstance(v, list):
            out[k] = [_scrub(x) if isinstance(x, str) else x for x in v]
        else:
            out[k] = v
    return out


class BaseProvider(ABC):
    """
    Abstract base class for all threat intelligence providers (Stage 3).
    Each provider must implement query(target) -> Optional[Dict].
    """
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)

        # ---- Auth declaration (Stage R4: declarative, config-driven) ----
        self.auth_type = (self.config.get("auth_type") or "api_key_header").lower()
        self.auth_header = self.config.get("auth_header")
        self.auth_param = self.config.get("auth_param")
        self.auth_env = self.config.get("api_key_env")
        self.api_key = os.getenv(self.auth_env) if self.auth_env else None

        # Register for scrubbing
        if self.api_key:
            _register_secret(self.api_key)

        # ---- Reliability metrics ----
        self.reliability = float(self.config.get("reliability", 0.5))
        self.weight = float(self.config.get("weight", 1.0))
        # Runtime metrics
        self.latency: Optional[float] = None
        self.last_success: Optional[str] = None
        self.error_rate = 0.0
        self.total_queries = 0
        self.failed_queries = 0
        # Freshness
        self.freshness_ttl = int(self.config.get("freshness_ttl", 1800))
        self.last_error: Optional[str] = None

        self.logger = logging.getLogger(f"provider.{self.name}")

    def is_configured(self) -> bool:
        """
        A provider is configured if:
          - auth_type == 'none', OR
          - auth_type requires a key AND the env var is set
        """
        if (self.auth_type or "api_key_header").lower() == "none":
            return True
        if not self.auth_env:
            return False
        return bool(self.api_key)

    def _build_auth(self,
                    headers: Dict[str, str],
                    params: Dict[str, Any]) -> None:
        """
        Inject authentication into headers and/or params based on auth_type.

        Mutates headers and params in place. Does NOT log or return secrets.
        """
        if not self.api_key:
            return

        at = (self.auth_type or "api_key_header").lower()

        if at == "api_key_header":
            header_name = self.auth_header or self.config.get("api_key_header") or "Authorization"
            headers[header_name] = self.api_key

        elif at == "api_key_param":
            param_name = self.auth_param or self.config.get("api_key_param") or "key"
            params[param_name] = self.api_key

        elif at == "bearer_token":
            headers["Authorization"] = f"Bearer {self.api_key}"

        elif at == "basic_auth":
            # api_key must be "user:pass"
            token = base64.b64encode(self.api_key.encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        elif at == "none":
            return

        else:
            raise ValueError(f"Unknown auth_type: {self.auth_type}")

    def record_success(self, latency: float):
        self.latency = latency
        self.last_success = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.total_queries += 1

    def record_failure(self, error: str) -> None:
        self.total_queries += 1
        self.failed_queries += 1
        self.error_rate = self.failed_queries / self.total_queries if self.total_queries else 0.0
        scrubbed = _scrub(error)
        self.last_error = scrubbed
        self.logger.warning(f"Provider {self.name} failed: {scrubbed}")

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
        """
        Query the provider with format-aware parsing.

        Returns:
          - dict: successful parse (may be {} for "not in list")
          - None: provider failure
        """
        if not self.is_configured():
            self.last_error = "not_configured"
            return None

        url = self.url_template.format(target=target) if self.url_template else ""
        if not url:
            self.record_failure("no url")
            return None
        headers = dict(self.headers)
        params = {}
        for k, v in (dict(self.params) or {}).items():
            if isinstance(v, str):
                try:
                    params[k] = v.format(target=target)
                except Exception:
                    params[k] = v
            else:
                params[k] = v

        # ---- Auth (Stage R4: declarative per-request injection) ----
        try:
            self._build_auth(headers, params)
        except Exception as e:
            self.record_failure(f"auth_error: {e}")
            return None

        # ---- POST body ----
        body = None
        if self.method == "POST":
            body = {}
            for k, v in (self.config.get("body", {}) or {}).items():
                if isinstance(v, str):
                    try:
                        body[k] = v.format(target=target)
                    except Exception:
                        body[k] = v
                else:
                    body[k] = v

        start = time.time()
        try:
            if self.method == "GET":
                resp = _get_session().get(
                    url, headers=headers, params=params, timeout=self.timeout
                )
            elif self.method == "POST":
                resp = _get_session().post(
                    url, headers=headers, params=params, data=body, timeout=self.timeout
                )
            else:
                self.record_failure(f"unsupported method: {self.method}")
                return None

            resp.raise_for_status()
            latency = time.time() - start
            self.record_success(latency)

            fmt = self.config.get("response_format", "json")
            return self._parse_response(resp, fmt, target)

        except requests.HTTPError as e:
            # Scrub the URL in case a key was injected as a param
            self.record_failure(f"HTTP error: {_scrub(str(e))}")
            return None
        except requests.Timeout:
            self.record_failure("timeout")
            return None
        except Exception as e:
            self.record_failure(f"unexpected: {_scrub(str(e))}")
            return None

    def _parse_response(self, resp, fmt: str, target: str) -> Dict[str, Any]:
        """
        Dispatch response body parsing based on response_format.

        Returns a normalized dict. Never raises for parse errors —
        raises are caught by query() and recorded as failure.
        """
        fmt = (fmt or "json").lower()

        if fmt == "json":
            return self._parse_json(resp, target)

        if fmt == "csv":
            return self._parse_csv(resp, target)

        if fmt == "text_lines":
            return self._parse_text_lines(resp, target)

        if fmt == "text":
            return self._parse_text(resp, target)

        raise ValueError(f"Unknown response_format: {fmt}")

    def _parse_json(self, resp, target: str) -> Dict[str, Any]:
        """
        Parse a JSON response using response_map (dot notation).

        If response_map is empty, returns the raw top-level keys
        wrapped in a normalized shape.
        """
        data = resp.json()
        response_map = self.config.get("response_map") or {}

        if not response_map:
            return {
                "threat_score": None,
                "tags": [],
                "first_seen": None,
                "last_seen": None,
                "evidence": "JSON parsed; no response_map configured",
            }

        result: Dict[str, Any] = {}
        for key, path in response_map.items():
            result[key] = self._extract(data, path) if path else None
        return result

    def _parse_csv(self, resp, target: str) -> Dict[str, Any]:
        """
        Parse a CSV response and locate the target.

        Config:
          csv_map:
            ip: "<column name for IP>"
            tag: "<column name for tag>"
            first_seen: "<column name>"
            last_seen: "<column name>"
          csv_target_column: "<column to match target against>"  # optional

        Returns:
          - dict with threat_score=1.0 if target found
          - dict with threat_score=None if target not found
          - raises on malformed CSV
        """
        reader = csv.DictReader(io.StringIO(resp.text))
        csv_map = self.config.get("csv_map") or {}
        target_col = self.config.get("csv_target_column") or csv_map.get("ip")

        for row in reader:
            if not isinstance(row, dict):
                continue
            # Determine which columns to search
            if target_col and target_col in row:
                val = row[target_col]
                if isinstance(val, str) and val.strip() == target:
                    return self._map_csv_row(row, csv_map)
            else:
                # Fallback: search all values
                if target in (v.strip() for v in row.values() if isinstance(v, str)):
                    return self._map_csv_row(row, csv_map)

        # Target not in list — this is a valid answer
        return {
            "threat_score": None,
            "tags": [],
            "first_seen": None,
            "last_seen": None,
            "evidence": f"target not found in {self.name} CSV",
        }

    def _map_csv_row(self, row: Dict[str, str], csv_map: Dict[str, str]) -> Dict[str, Any]:
        """Convert a matched CSV row into a normalized result."""
        tag = row.get(csv_map.get("tag", ""), "") if csv_map.get("tag") else ""
        first_seen = row.get(csv_map.get("first_seen", "")) if csv_map.get("first_seen") else None
        last_seen = row.get(csv_map.get("last_seen", "")) if csv_map.get("last_seen") else None
        return {
            "threat_score": 1.0,
            "tags": [tag] if tag else [],
            "first_seen": first_seen,
            "last_seen": last_seen,
            "evidence": str(row),
        }

    def _parse_text_lines(self, resp, target: str) -> Dict[str, Any]:
        """
        Parse a plain-text list where each line starts with an IP or CIDR.

        Rules:
          - Lines starting with '#' are skipped.
          - Blank lines are skipped.
          - The first token is taken as the entry (split on whitespace or comma).
          - If the entry is a CIDR, the target is checked for membership.
          - Inline comments after ';' or '#' are stripped.
        """
        for raw_line in (resp.text or "").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Strip inline comments
            for sep in (";", " #"):
                if sep in line:
                    line = line.split(sep, 1)[0].strip()

            if not line:
                continue

            token = line.split()[0].split(",")[0].strip()
            if not token:
                continue

            if "/" in token:
                # CIDR match
                if _ip_in_cidr(target, token):
                    return {
                        "threat_score": 1.0,
                        "tags": ["listed"],
                        "first_seen": None,
                        "last_seen": None,
                        "evidence": line,
                    }
            else:
                if token == target:
                    return {
                        "threat_score": 1.0,
                        "tags": ["listed"],
                        "first_seen": None,
                        "last_seen": None,
                        "evidence": line,
                    }

        # Target not in list
        return {
            "threat_score": None,
            "tags": [],
            "first_seen": None,
            "last_seen": None,
            "evidence": f"target not found in {self.name} list",
        }

    def _parse_text(self, resp, target: str) -> Dict[str, Any]:
        """
        Capture a capped slice of raw text for diagnostic purposes.
        Not intended for threat scoring.
        """
        try:
            max_len = int(self.config.get("max_text_length", 4096))
        except Exception:
            max_len = 4096
        return {
            "threat_score": None,
            "tags": [],
            "first_seen": None,
            "last_seen": None,
            "evidence": (resp.text or "")[:max_len],
        }

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

def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """Return True if ip is inside cidr. Returns False on parse errors."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


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

def load_api_keys(providers: Dict[str, BaseProvider],
                  config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Inspect all providers and classify their auth state (Stage A2).

    Rules:
      - Disabled providers are ignored entirely (no log, no warning).
      - Providers with auth_type='none' require no key.
      - Enabled providers without a key are recorded as 'missing'.
      - Enabled providers without auth_env are recorded as 'misconfigured'.
      - Keys are registered for scrubbing when present.
      - This function never logs. Use _log_auth_summary() for output.

    Returns:
      {
        "present":       [names with keys],
        "missing":       [names enabled but key unset],
        "misconfigured": [names enabled but no auth_env],
        "disabled":      [names with enabled=false],
        "no_auth":       [names with auth_type=none],
        "not_required":  alias of no_auth (back-compat),
        "missing_env":   {name: env var} for missing entries,
      }
    """
    present: List[str] = []
    missing: List[str] = []
    misconfigured: List[str] = []
    disabled: List[str] = []
    no_auth: List[str] = []
    missing_env: Dict[str, str] = {}

    for name, provider in ((providers or {}).items()):
        try:
            enabled = bool(getattr(provider, "enabled", True))
        except Exception:
            enabled = True
        if not enabled:
            disabled.append(name)
            continue

        try:
            auth_type = (getattr(provider, "auth_type", "api_key_header") or "api_key_header").lower()
        except Exception:
            auth_type = "api_key_header"
        if auth_type == "none":
            no_auth.append(name)
            continue

        try:
            auth_env = getattr(provider, "auth_env", None)
        except Exception:
            auth_env = None
        if not auth_env:
            misconfigured.append(name)
            continue

        try:
            key = os.getenv(auth_env)
        except Exception:
            key = None
        if not key:
            missing.append(name)
            try:
                missing_env[name] = auth_env
            except Exception:
                pass
        else:
            present.append(name)
            _register_secret(key)

    # Disabled providers are skipped by load_providers(), so derive them
    # from the declared config (explicit param, else module-global CFG).
    try:
        src = config if isinstance(config, dict) else None
        if src is None:
            try:
                src = CFG
            except Exception:
                src = None
        declared = (src.get("providers", {}) or {}) if isinstance(src, dict) else {}
        if not isinstance(declared, dict):
            declared = {}
        loaded = set((providers or {}).keys())
        for dname, pconfig in declared.items():
            if dname in loaded:
                continue
            if isinstance(pconfig, dict) and not pconfig.get("enabled", True):
                if dname not in disabled:
                    disabled.append(dname)
    except Exception:
        pass

    return {
        "present": present,
        "missing": missing,
        "misconfigured": misconfigured,
        "disabled": disabled,
        "no_auth": no_auth,
        "not_required": list(no_auth),
        "missing_env": missing_env,
    }


def _auth_warning_mode(config: Optional[Dict[str, Any]] = None) -> str:
    """
    Resolve the auth warning mode from config (Stage A2).

    logging.auth_warnings: "summary" (default) | "per_provider" | "off".
    Falls back to the module-global CFG, then to "summary".
    """
    try:
        src = config if isinstance(config, dict) else None
        if src is None:
            try:
                src = CFG
            except Exception:
                src = None
        if isinstance(src, dict):
            lg = src.get("logging", {}) or {}
            if isinstance(lg, dict):
                mode = str(lg.get("auth_warnings", "summary") or "summary").lower()
                if mode in ("summary", "per_provider", "off"):
                    return mode
    except Exception:
        pass
    return "summary"


def _format_auth_summary(auth_info: Dict[str, Any]) -> Tuple[str, str]:
    """
    Build the single-line auth summary as (level, message) (Stage C3.6).

    level is "warning" when any enabled provider is missing or
    misconfigured, otherwise "info". Text matches the summary-mode
    output of _log_auth_summary() exactly.
    """
    try:
        present = list(auth_info.get("present", []) or [])
        missing = list(auth_info.get("missing", []) or [])
        misconfigured = list(auth_info.get("misconfigured", []) or [])
        disabled = list(auth_info.get("disabled", []) or [])
        no_auth = list(auth_info.get("no_auth", []) or auth_info.get("not_required", []) or [])
        missing_env = auth_info.get("missing_env", {}) or {}
    except Exception:
        return "info", "Auth: status unknown."
    offenders: List[str] = []
    for n in list(missing) + list(misconfigured):
        if n not in offenders:
            offenders.append(n)
    if offenders:
        detail_parts: List[str] = []
        for name in offenders:
            if name in misconfigured:
                detail_parts.append(f"{name} (no api_key_env)")
                continue
            env = None
            try:
                env = missing_env.get(name) or _lookup_env_for(name)
            except Exception:
                env = None
            detail_parts.append(f"{name} ({env})" if env else name)
        detail = ", ".join(detail_parts)
        return ("warning",
                f"{len(offenders)} enabled provider(s) "
                f"missing API keys: {detail}. "
                f"These will report NOT_CONFIGURED.")
    return ("info",
            f"Auth: {len(present)} configured, 0 missing, "
            f"{len(disabled)} disabled, {len(no_auth)} no-auth.")


def _progress_is_live(progress: Optional[Any] = None) -> bool:
    """
    True when progress is a live rich handle whose note() draws on the
    terminal (Stage C3.6). A _NoopProgress note() draws nothing, so the
    flagged-record path must not be used for it.
    """
    try:
        return isinstance(progress, _RichProgress)
    except Exception:
        return False


def _emit_auth(level: str, msg: str, progress: Optional[Any] = None) -> None:
    """
    Emit one auth line, terminal occurrence exactly once (Stage C3.6).

    With a live progress handle: note() draws above the bar, and the
    With a live progress handle: note() draws above the bar, and the
    flagged logging record is dropped by console handlers
    (_NoteDedupFilter) while the file handler still records it.
    Without (None or no-op): plain logging call.
    """
    if _progress_is_live(progress):
        try:
            progress.note(f"[{level.upper()}] {msg}")
            noted = True
        except Exception:
            noted = False
        try:
            if noted:
                if level == "warning":
                    logging.warning(msg, extra={"via_note": True})
                else:
                    logging.info(msg, extra={"via_note": True})
            else:
                if level == "warning":
                    logging.warning(msg)
                else:
                    logging.info(msg)
        except Exception:
            pass
        return
    if level == "warning":
        logging.warning(msg)
    else:
        logging.info(msg)


def _log_auth_summary(auth_info: Dict[str, Any],
                      config: Optional[Dict[str, Any]] = None,
                      progress: Optional[Any] = None) -> None:
    """
    Emit exactly one line per run summarizing auth state (Stage A2).

    Rules:
      - If any enabled provider is missing a key -> one WARNING line
        (mode "summary"), legacy per-provider lines (mode "per_provider"),
        or silence (mode "off").
      - Otherwise -> one INFO line.
      - Never warn about disabled or auth_type=none providers.
    """
    try:
        present = list(auth_info.get("present", []) or [])
        missing = list(auth_info.get("missing", []) or [])
        misconfigured = list(auth_info.get("misconfigured", []) or [])
        disabled = list(auth_info.get("disabled", []) or [])
        no_auth = list(auth_info.get("no_auth", []) or auth_info.get("not_required", []) or [])
        missing_env = auth_info.get("missing_env", {}) or {}
    except Exception:
        return
    try:
        mode = _auth_warning_mode(config)
    except Exception:
        mode = "summary"

    # Preserve order, drop duplicates.
    offenders: List[str] = []
    for n in list(missing) + list(misconfigured):
        if n not in offenders:
            offenders.append(n)

    if offenders:
        if mode == "off":
            _emit_auth(
                "info",
                f"Auth: {len(present)} configured, {len(offenders)} missing, "
                f"{len(disabled)} disabled, {len(no_auth)} no-auth.",
                progress,
            )
            return
        if mode == "per_provider":
            for name in offenders:
                if name in misconfigured:
                    try:
                        at = "unknown"
                        try:
                            reg = _PROVIDERS_REGISTRY.get()
                            if isinstance(reg, dict) and name in reg:
                                at = getattr(reg[name], "auth_type", "unknown")
                        except Exception:
                            pass
                        logging.warning(
                            f"Provider {name} declares auth_type={at} "
                            f"but no api_key_env. Set one in config.yaml."
                        )
                    except Exception:
                        pass
                else:
                    env = None
                    try:
                        env = missing_env.get(name) or _lookup_env_for(name)
                    except Exception:
                        env = None
                    logging.warning(
                        f"API key for {name} not set. "
                        f"Set {env if env else '(unknown env var)'} to enable."
                    )
            logging.info(
                f"Auth: {len(present)} configured, "
                f"{len(offenders)} missing, "
                f"{len(no_auth)} not required."
            )
            logging.warning(
                f"Missing API keys for: {', '.join(offenders)}. "
                f"These providers will report NOT_CONFIGURED."
            )
            return
        # ---- Default: one summary WARNING line ----
        _level, _msg = _format_auth_summary(auth_info)
        _emit_auth(_level, _msg, progress)
        return

    # ---- All good: one INFO line ----
    _level, _msg = _format_auth_summary(auth_info)
    _emit_auth(_level, _msg, progress)

# ============================================================
#  PERFORMANCE ENGINE — v43 (Stage 19)
#  Parallel providers + timeout budget + rate limits + pooling.
#  Speed is execution. Evidence is unchanged.
# ============================================================
_thread_local = threading.local()


def _get_session() -> "requests.Session":
    """
    Return a thread-local requests.Session for connection pooling.
    """
    if not hasattr(_thread_local, "session"):
        session = requests.Session()
        # Sensible defaults for connection reuse
        try:
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=4,
                pool_maxsize=8,
                max_retries=0  # retries handled explicitly
            )
            session.mount("https://", adapter)
            session.mount("http://", adapter)
        except Exception:
            pass
        try:
            session.headers.update({"User-Agent": "ReconIP/43"})
        except Exception:
            pass
        _thread_local.session = session
    return _thread_local.session


_RATE_STATE_LOCK = threading.Lock()
_RATE_STATE: Dict[str, Dict[str, float]] = {}


def _acquire_rate_token(provider_name: str,
                        config: Dict[str, Any]) -> float:
    """
    Block until a rate token is available for this provider.
    Returns the actual wait time (seconds).

    Uses a simple minimum-interval model:
      - Each provider has a 'min_interval' (seconds between calls).
      - If the last call was < min_interval ago, sleep the remainder.
    """
    try:
        perf_cfg = config.get("performance", {}) if isinstance(config, dict) else {}
    except Exception:
        perf_cfg = {}
    if not isinstance(perf_cfg, dict):
        perf_cfg = {}
    rate_cfg = perf_cfg.get("rate_limits", {}) if isinstance(perf_cfg.get("rate_limits", {}), dict) else {}
    default_interval = perf_cfg.get("default_min_interval", 0.0)
    try:
        default_interval = float(default_interval)
    except Exception:
        default_interval = 0.0
    try:
        min_interval = float(rate_cfg.get(provider_name, default_interval))
    except Exception:
        min_interval = default_interval

    if min_interval <= 0:
        return 0.0

    now = time.monotonic()
    with _RATE_STATE_LOCK:
        state = _RATE_STATE.setdefault(provider_name, {"last": 0.0})
        elapsed = now - state["last"]
        wait_time = max(0.0, min_interval - elapsed)
        # Reserve the slot before releasing the lock
        state["last"] = now + wait_time

    if wait_time > 0:
        time.sleep(wait_time)
    return wait_time


def provider_priority(name: str,
                      provider: Any,
                      config: Dict[str, Any]) -> int:
    """
    Higher score = run first.

    Signals:
      - reliability (from Stage 3)
      - weight (from Stage 3)
      - configured (API key present)
      - not in circuit-breaker state
    """
    try:
        perf_cfg = config.get("performance", {}) if isinstance(config, dict) else {}
    except Exception:
        perf_cfg = {}
    if not isinstance(perf_cfg, dict):
        perf_cfg = {}
    priority_weights = perf_cfg.get("priority_weights", {
        "reliability": 0.5,
        "weight": 0.3,
        "configured_bonus": 0.2
    })
    if not isinstance(priority_weights, dict):
        priority_weights = {"reliability": 0.5, "weight": 0.3, "configured_bonus": 0.2}

    try:
        rel = float(getattr(provider, "reliability", 0.5) or 0.5)
    except Exception:
        rel = 0.5
    try:
        w = float(getattr(provider, "weight", 1.0) or 1.0)
    except Exception:
        w = 1.0
    try:
        configured = bool(provider.is_configured()) if hasattr(provider, "is_configured") else True
    except Exception:
        configured = True
    try:
        err_rate = float(getattr(provider, "error_rate", 0.0) or 0.0)
    except Exception:
        err_rate = 0.0

    score = 0.0
    try:
        score += rel * float(priority_weights.get("reliability", 0.5))
    except Exception:
        pass
    try:
        score += w * float(priority_weights.get("weight", 0.3))
    except Exception:
        pass
    if configured:
        try:
            score += float(priority_weights.get("configured_bonus", 0.2))
        except Exception:
            pass

    # Circuit breaker: heavily deprioritize if error_rate >= threshold
    try:
        cb_cfg = perf_cfg.get("circuit_breaker", {}) if isinstance(perf_cfg.get("circuit_breaker", {}), dict) else {}
        threshold = float(cb_cfg.get("error_rate_threshold", 0.8))
        penalty = float(cb_cfg.get("penalty", 1.0))
    except Exception:
        threshold, penalty = 0.8, 1.0
    if err_rate >= threshold:
        score -= penalty

    return int(round(score * 1000))


def timeout_budget(config: Dict[str, Any],
                   provider_count: int) -> float:
    """
    Return the total seconds allowed for provider execution.

    Rules:
      - Use configured 'timeout_budget' as a hard cap.
      - If provider_count is small, cap it lower to avoid waiting.
      - Never return <= 0.
    """
    try:
        perf_cfg = config.get("performance", {}) if isinstance(config, dict) else {}
    except Exception:
        perf_cfg = {}
    if not isinstance(perf_cfg, dict):
        perf_cfg = {}
    try:
        budget = float(perf_cfg.get("timeout_budget", 30))
    except Exception:
        budget = 30.0
    try:
        min_budget = float(perf_cfg.get("min_timeout_budget", 10))
    except Exception:
        min_budget = 10.0
    try:
        max_budget = float(perf_cfg.get("max_timeout_budget", 120))
    except Exception:
        max_budget = 120.0

    # Scale down if very few providers
    try:
        if int(provider_count) <= 2:
            budget = min(budget, min_budget * 2)
    except Exception:
        pass

    return max(min_budget, min(max_budget, budget))


# ============================================================
#  CACHE INTELLIGENCE — v43.1 (Stage 20)
#  reconip_cache.db as a first-class layer: FRESH / STALE / EXPIRED.
#  Cache is a memory, not a source of truth.
# ============================================================
_CACHE_DB_LOCK = threading.Lock()


def _cache_resolve_config(config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return the effective config (explicit arg or global CFG)."""
    try:
        if isinstance(config, dict):
            return config
    except Exception:
        pass
    try:
        return CFG if isinstance(CFG, dict) else {}
    except Exception:
        return {}


def cache_init(db_path: str = "reconip_cache.db") -> None:
    """
    Ensure the cache table exists with the correct schema.
    Idempotent. Migrates the legacy Stage-3 schema (k, d, e) forward.
    """
    if not db_path:
        db_path = "reconip_cache.db"
    with _CACHE_DB_LOCK:
        try:
            with sqlite3.connect(db_path, timeout=30) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                cols = set()
                try:
                    cols = {r[1] for r in conn.execute("PRAGMA table_info(cache)").fetchall()}
                except Exception:
                    cols = set()
                if not cols:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS cache (
                            key          TEXT PRIMARY KEY,
                            value        TEXT NOT NULL,
                            source       TEXT NOT NULL,
                            ttl_seconds  INTEGER NOT NULL,
                            cached_at    TEXT NOT NULL,
                            cached_at_unix REAL NOT NULL
                        )
                    """)
                elif "k" in cols and "key" not in cols:
                    # Legacy Stage-3 schema: migrate rows, then replace table.
                    try:
                        legacy = conn.execute("SELECT k, d, e FROM cache").fetchall()
                    except Exception:
                        legacy = []
                    now = time.time()
                    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    conn.execute("DROP TABLE cache")
                    conn.execute("""
                        CREATE TABLE cache (
                            key          TEXT PRIMARY KEY,
                            value        TEXT NOT NULL,
                            source       TEXT NOT NULL,
                            ttl_seconds  INTEGER NOT NULL,
                            cached_at    TEXT NOT NULL,
                            cached_at_unix REAL NOT NULL
                        )
                    """)
                    for k, d, e in legacy:
                        try:
                            remaining = float(e) - now
                        except Exception:
                            continue
                        if remaining <= 0:
                            continue  # drop already-expired legacy rows
                        try:
                            conn.execute(
                                "INSERT OR REPLACE INTO cache "
                                "(key, value, source, ttl_seconds, cached_at, cached_at_unix) "
                                "VALUES (?, ?, ?, ?, ?, ?)",
                                (k, d, "migrated", int(remaining), now_iso, now)
                            )
                        except Exception:
                            continue
                else:
                    # New schema present (possibly partial): add any missing columns.
                    for coldef in (
                        ("value", "TEXT"),
                        ("source", "TEXT"),
                        ("ttl_seconds", "INTEGER"),
                        ("cached_at", "TEXT"),
                        ("cached_at_unix", "REAL"),
                    ):
                        if coldef[0] not in cols:
                            try:
                                conn.execute(f"ALTER TABLE cache ADD COLUMN {coldef[0]} {coldef[1]}")
                            except Exception:
                                pass
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_source ON cache(source)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_cached_at ON cache(cached_at_unix)")
                conn.commit()
        except Exception as e:
            log.debug(f"cache_init: {e}")


def _cache_ttl_for(name: str, config: Dict[str, Any]) -> int:
    """Resolve TTL for a provider: provider_ttls override, else default."""
    try:
        cache_cfg = config.get("cache", {}) if isinstance(config, dict) else {}
    except Exception:
        cache_cfg = {}
    if not isinstance(cache_cfg, dict):
        cache_cfg = {}
    try:
        prov_ttls = cache_cfg.get("provider_ttls", {}) or {}
        if isinstance(prov_ttls, dict) and name in prov_ttls:
            return int(prov_ttls[name])
    except Exception:
        pass
    try:
        return int(cache_cfg.get("ttl_seconds", 3600))
    except Exception:
        return 3600


def cache_set(key: str,
              value: Dict[str, Any],
              config: Optional[Any] = None,
              ttl_seconds: Optional[int] = None,
              source: Optional[str] = None) -> None:
    """
    Store a value in the cache.

    Rules:
      - value must be a JSON-serializable dict (Evidence-shaped).
      - source is inferred from value.get('source') if not provided.
      - ttl_seconds is inferred from config if not provided.
      - Cached values with status == FAILED are NOT cached.
    """
    # Backward compat: legacy call form cache_set(key, value, ttl:int)
    if config is not None and not isinstance(config, dict):
        try:
            ttl_seconds = int(config)
        except Exception:
            pass
        config = None
    cfg = _cache_resolve_config(config)
    try:
        cache_cfg = cfg.get("cache", {}) if isinstance(cfg, dict) else {}
    except Exception:
        cache_cfg = {}
    if not isinstance(cache_cfg, dict):
        cache_cfg = {}
    if not cache_cfg.get("enabled", True):
        return

    # Never cache failures
    if not isinstance(value, dict):
        return
    if value.get("status") == "FAILED":
        return

    db_path = cache_cfg.get("db_path", "reconip_cache.db") or "reconip_cache.db"
    if ttl_seconds is None:
        try:
            ttl_seconds = int(cache_cfg.get("ttl_seconds", 3600))
        except Exception:
            ttl_seconds = 3600
    else:
        try:
            ttl_seconds = int(ttl_seconds)
        except Exception:
            ttl_seconds = 3600
    if source is None:
        try:
            source = value.get("source", "unknown") or "unknown"
        except Exception:
            source = "unknown"

    now = datetime.now(timezone.utc)
    cached_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    cached_at_unix = now.timestamp()

    try:
        payload = json.dumps(value, sort_keys=True, default=str)
    except Exception:
        return

    with _CACHE_DB_LOCK:
        try:
            with sqlite3.connect(db_path, timeout=30) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("""
                    INSERT OR REPLACE INTO cache
                        (key, value, source, ttl_seconds, cached_at, cached_at_unix)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (key, payload, str(source), int(ttl_seconds), cached_at, float(cached_at_unix)))
                conn.commit()
        except Exception as e:
            log.debug(f"cache_set: {e}")


def cache_status(cached_at_unix: float,
                 ttl_seconds: int,
                 config: Optional[Dict[str, Any]] = None) -> str:
    """
    Return FRESH, STALE, or EXPIRED based on age and thresholds.

    FRESH:   age <= ttl_seconds
    STALE:   ttl_seconds < age <= expired_threshold
    EXPIRED: age > expired_threshold

    stale_threshold is the advisory "very stale" marker (see is_very_stale).
    Thresholds are normalized: stale >= ttl, expired >= stale.
    """
    cfg = _cache_resolve_config(config)
    try:
        cache_cfg = cfg.get("cache", {}) if isinstance(cfg, dict) else {}
    except Exception:
        cache_cfg = {}
    if not isinstance(cache_cfg, dict):
        cache_cfg = {}
    try:
        ttl_seconds = int(ttl_seconds)
    except Exception:
        ttl_seconds = 3600
    try:
        stale_threshold = int(cache_cfg.get("stale_threshold", 7200))
    except Exception:
        stale_threshold = 7200
    try:
        expired_threshold = int(cache_cfg.get("expired_threshold", 86400))
    except Exception:
        expired_threshold = 86400

    # Normalize thresholds
    if stale_threshold < ttl_seconds:
        stale_threshold = ttl_seconds
    if expired_threshold < stale_threshold:
        expired_threshold = stale_threshold

    try:
        age = time.time() - float(cached_at_unix)
    except Exception:
        return "EXPIRED"

    if age <= ttl_seconds:
        return "FRESH"
    if age <= expired_threshold:
        return "STALE"
    return "EXPIRED"


def cache_get(key: str,
              config: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieve a cache entry.

    Returns:
      - None if:
          - cache is disabled
          - key does not exist
          - entry is EXPIRED
      - A dict with:
          - 'value': the cached Evidence dict
          - 'status': FRESH | STALE
          - 'cached_at': ISO8601
          - 'age_seconds': float
          - 'ttl_seconds': int
          - 'is_very_stale': bool
          - 'source': str
    """
    cfg = _cache_resolve_config(config)
    try:
        cache_cfg = cfg.get("cache", {}) if isinstance(cfg, dict) else {}
    except Exception:
        cache_cfg = {}
    if not isinstance(cache_cfg, dict):
        cache_cfg = {}
    if not cache_cfg.get("enabled", True):
        return None

    db_path = cache_cfg.get("db_path", "reconip_cache.db") or "reconip_cache.db"

    try:
        with _CACHE_DB_LOCK:
            with sqlite3.connect(db_path, timeout=30) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                row = conn.execute("""
                    SELECT value, source, ttl_seconds, cached_at, cached_at_unix
                    FROM cache WHERE key = ?
                """, (key,)).fetchone()
    except Exception:
        return None

    if not row:
        return None

    value_json, source, ttl_seconds, cached_at, cached_at_unix = row
    try:
        ttl_seconds = int(ttl_seconds)
    except Exception:
        ttl_seconds = 3600
    status = cache_status(cached_at_unix, ttl_seconds, cfg)
    if status == "EXPIRED":
        return None

    try:
        value = json.loads(value_json)
    except Exception:
        return None
    if not isinstance(value, dict):
        return None

    try:
        age_seconds = time.time() - float(cached_at_unix)
    except Exception:
        return None
    try:
        stale_threshold = int(cache_cfg.get("stale_threshold", 7200))
    except Exception:
        stale_threshold = 7200
    is_very_stale = age_seconds > stale_threshold

    return {
        "value": value,
        "status": status,
        "cached_at": cached_at,
        "age_seconds": round(age_seconds, 2),
        "ttl_seconds": int(ttl_seconds),
        "is_very_stale": bool(is_very_stale),
        "source": source
    }


def cache_purge_expired(config: Optional[Dict[str, Any]] = None) -> int:
    """
    Delete EXPIRED cache entries. Returns count of deleted rows.
    Call this once per run or on a schedule.
    """
    cfg = _cache_resolve_config(config)
    try:
        cache_cfg = cfg.get("cache", {}) if isinstance(cfg, dict) else {}
    except Exception:
        cache_cfg = {}
    if not isinstance(cache_cfg, dict):
        cache_cfg = {}
    if not cache_cfg.get("enabled", True):
        return 0
    if not cache_cfg.get("purge_expired", True):
        return 0

    db_path = cache_cfg.get("db_path", "reconip_cache.db") or "reconip_cache.db"
    try:
        expired_threshold = int(cache_cfg.get("expired_threshold", 86400))
    except Exception:
        expired_threshold = 86400
    cutoff = time.time() - expired_threshold

    try:
        with _CACHE_DB_LOCK:
            with sqlite3.connect(db_path, timeout=30) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                cursor = conn.execute(
                    "DELETE FROM cache WHERE cached_at_unix < ?",
                    (cutoff,)
                )
                deleted = cursor.rowcount
                conn.commit()
        return int(deleted or 0)
    except Exception:
        return 0


def cache_stats(config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Return cache statistics: total entries, by source, by status.
    """
    cfg = _cache_resolve_config(config)
    try:
        cache_cfg = cfg.get("cache", {}) if isinstance(cfg, dict) else {}
    except Exception:
        cache_cfg = {}
    if not isinstance(cache_cfg, dict):
        cache_cfg = {}
    if not cache_cfg.get("enabled", True):
        return {"enabled": False}

    db_path = cache_cfg.get("db_path", "reconip_cache.db") or "reconip_cache.db"
    try:
        with _CACHE_DB_LOCK:
            with sqlite3.connect(db_path, timeout=30) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                rows = conn.execute("""
                    SELECT source, ttl_seconds, cached_at_unix
                    FROM cache
                """).fetchall()
    except Exception:
        return {"enabled": True, "error": "cache_read_failed"}

    total = len(rows)
    by_source: Dict[str, int] = {}
    by_status: Dict[str, int] = {"FRESH": 0, "STALE": 0, "EXPIRED": 0}

    for source, ttl_seconds, cached_at_unix in rows:
        try:
            by_source[source] = by_source.get(source, 0) + 1
            status = cache_status(cached_at_unix, ttl_seconds, cfg)
            by_status[status] = by_status.get(status, 0) + 1
        except Exception:
            continue

    return {
        "enabled": True,
        "total": total,
        "by_source": by_source,
        "by_status": by_status
    }


def _section_cache(report: Dict[str, Any],
                   config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Section: cache intelligence summary.
    Attached as report["cache_intelligence"]; the 18-section structure is unchanged.
    """
    try:
        stats = cache_stats(config)
    except Exception:
        stats = {"enabled": False}
    if not isinstance(stats, dict):
        stats = {"enabled": False}
    return {
        "enabled": stats.get("enabled", False),
        "total_entries": stats.get("total", 0),
        "by_source": stats.get("by_source", {}),
        "by_status": stats.get("by_status", {}),
        "notes": [
            "Cache is a memory, not a source of truth.",
            "FRESH cache may skip a query.",
            "STALE cache is marked and used only as fallback.",
            "EXPIRED cache is never used.",
            "Cache never replaces a failed provider — it complements it."
        ]
    }



def _provider_evidence(source: str,
                       value: Any,
                       status: str,
                       reason: str = "") -> Dict[str, Any]:
    """
    Build an Evidence-shaped dict for a non-OK provider state.
    """
    return make_evidence(
        source=source,
        value=value,
        normalized_value=value,
        confidence=0.0,
        status=status,
        ttl_key="threat",
        metadata={"reason": reason}
    ).to_dict()


def _run_one_provider(name: str,
                      provider: Any,
                      target: str,
                      config: Dict[str, Any],
                      deadline: float) -> Dict[str, Any]:
    """
    Run one provider and return a normalized Evidence dict.

    Behavior:
      - Respects rate limits.
      - Checks cache before querying.
      - Enforces the deadline (deadline is time.monotonic()).
      - Never raises — always returns an Evidence-shaped dict.
    """
    try:
        enabled = bool(getattr(provider, "enabled", True))
    except Exception:
        enabled = True
    if not enabled:
        return _provider_evidence(name, None, "NOT_CONFIGURED",
                                  reason="disabled in config")

    try:
        configured = bool(provider.is_configured()) if hasattr(provider, "is_configured") else True
    except Exception:
        configured = True
    if not configured:
        return _provider_evidence(name, None, "NOT_CONFIGURED",
                                  reason="missing API key")

    # Circuit breaker
    try:
        cb_cfg = config.get("performance", {}).get("circuit_breaker", {}) if isinstance(config, dict) else {}
        if not isinstance(cb_cfg, dict):
            cb_cfg = {}
        threshold = float(cb_cfg.get("error_rate_threshold", 0.8))
    except Exception:
        threshold = 0.8
    try:
        err_rate = float(getattr(provider, "error_rate", 0.0) or 0.0)
    except Exception:
        err_rate = 0.0
    if err_rate >= threshold:
        return _provider_evidence(name, None, "FAILED",
                                  reason="circuit breaker open")

    cache_key = f"provider:{name}:{target}"

    # ---- Cache lookup (Stage 20: FRESH / STALE / EXPIRED) ----
    cached = cache_get(cache_key, config)
    if cached is not None:
        # Copy so per-thread mutation never corrupts shared state
        try:
            cached_value = json.loads(json.dumps(cached["value"]))
        except Exception:
            cached_value = dict(cached.get("value", {}))
        if not isinstance(cached_value, dict):
            cached_value = {}
        try:
            cached_value.setdefault("metadata", {})
            cached_value["metadata"].update({
                "cache_hit": True,
                "cache_status": cached["status"],
                "cache_age_seconds": cached["age_seconds"],
                "cache_cached_at": cached["cached_at"],
                "cache_is_very_stale": cached["is_very_stale"]
            })
        except Exception:
            pass
        # FRESH: return without querying provider
        if cached["status"] == "FRESH":
            return cached_value
        # STALE: keep cached value as fallback; attempt a refresh
        # (unless deadline is exhausted)
        try:
            remaining = deadline - time.monotonic()
        except Exception:
            remaining = 1.0
        if remaining <= 0:
            return cached_value
        # Fall through to refresh

    # Rate limit
    try:
        remaining = deadline - time.monotonic()
    except Exception:
        remaining = 1.0
    if remaining <= 0:
        return _provider_evidence(name, None, "FAILED",
                                  reason="timeout budget exhausted")

    try:
        wait_time = _acquire_rate_token(name, config)
    except Exception:
        wait_time = 0.0
    try:
        remaining = deadline - time.monotonic()
    except Exception:
        remaining = 1.0
    if remaining <= 0:
        return _provider_evidence(name, None, "FAILED",
                                  reason="rate limit consumed budget")

    # Query
    try:
        result = provider.query(target)
    except Exception as e:
        try:
            provider.record_failure(str(e))
        except Exception:
            pass
        # If we had a STALE cache, return it instead of failing
        if cached is not None:
            try:
                ev = json.loads(json.dumps(cached["value"]))
            except Exception:
                ev = dict(cached.get("value", {}))
            try:
                ev.setdefault("metadata", {})["cache_refresh_failed"] = True
            except Exception:
                pass
            return ev
        return _provider_evidence(name, None, "FAILED", reason=str(e))

    if result is None:
        if cached is not None:
            try:
                ev = json.loads(json.dumps(cached["value"]))
            except Exception:
                ev = dict(cached.get("value", {}))
            try:
                ev.setdefault("metadata", {})["cache_refresh_failed"] = True
            except Exception:
                pass
            return ev
        try:
            reason = getattr(provider, "last_error", None) or "no result"
        except Exception:
            reason = "no result"
        return _provider_evidence(name, None, "FAILED", reason=str(reason))

    try:
        conf = float(provider.compute_confidence()) if hasattr(provider, "compute_confidence") else 0.5
    except Exception:
        conf = 0.5
    try:
        ev = make_evidence(
            source=name,
            value=result.get("threat_score"),
            normalized_value=result.get("threat_score"),
            confidence=conf,
            status="OK",
            ttl_key="threat",
            metadata=_scrub_dict({
                "reliability": getattr(provider, "reliability", 0.5),
                "weight": getattr(provider, "weight", 1.0),
                "latency": getattr(provider, "latency", None),
                "tags": result.get("tags", []),
                "first_seen": result.get("first_seen"),
                "last_seen": result.get("last_seen"),
                "evidence": result.get("evidence", ""),
                "error_rate": getattr(provider, "error_rate", 0.0),
                "cache_hit": False,
                "cache_status": "MISS",
                "cache_refreshed": cached is not None and cached.get("status") == "STALE",
                "auth_type": getattr(provider, "auth_type", "api_key_header"),
            })
        )
        ev_dict = ev.to_dict()
    except Exception as e:
        return _provider_evidence(name, None, "FAILED", reason=str(e))

    # ---- Store in cache (Stage 20: failures are never cached) ----
    try:
        ttl = _cache_ttl_for(name, config if isinstance(config, dict) else {})
    except Exception:
        ttl = 3600
    try:
        cache_set(cache_key, ev_dict, config, ttl_seconds=ttl, source=name)
    except Exception:
        pass

    return ev_dict


def run_providers_parallel(target: str,
                           providers: Dict[str, Any],
                           config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Run all enabled providers in parallel with:
      - provider prioritization
      - bounded concurrency
      - timeout budget enforcement
      - per-provider rate limits
      - caching

    Returns a list of Evidence-shaped dicts, one per provider.
    """
    try:
        perf_cfg = config.get("performance", {}) if isinstance(config, dict) else {}
    except Exception:
        perf_cfg = {}
    if not isinstance(perf_cfg, dict):
        perf_cfg = {}
    parallel = perf_cfg.get("parallel", True)
    try:
        max_workers = max(1, int(perf_cfg.get("max_workers", 8)))
    except Exception:
        max_workers = 8

    try:
        items = list((providers or {}).items())
    except Exception:
        items = []
    enabled = [(name, p) for name, p in items if getattr(p, "enabled", True)]
    if not enabled:
        return []

    # Prioritize
    try:
        enabled.sort(key=lambda x: provider_priority(x[0], x[1], config), reverse=True)
    except Exception:
        pass

    try:
        budget = float(timeout_budget(config, len(enabled)))
    except Exception:
        budget = 30.0
    deadline = time.monotonic() + budget

    results: List[Optional[Dict[str, Any]]] = [None] * len(enabled)

    if not parallel or len(enabled) == 1:
        for i, (name, provider) in enumerate(enabled):
            try:
                results[i] = _run_one_provider(name, provider, target, config, deadline)
            except Exception as e:
                results[i] = _provider_evidence(name, None, "FAILED", reason=str(e))
        return [r for r in results if r is not None]

    ex = ThreadPoolExecutor(max_workers=max_workers,
                            thread_name_prefix="reconip-provider")
    try:
        future_map = {
            ex.submit(_run_one_provider, name, provider, target, config, deadline): i
            for i, (name, provider) in enumerate(enabled)
        }

        done, not_done = wait(
            list(future_map.keys()),
            timeout=budget,
            return_when=concurrent.futures.ALL_COMPLETED
        )

        # Collect completed
        for future in done:
            idx = future_map[future]
            try:
                results[idx] = future.result()
            except Exception as e:
                results[idx] = _provider_evidence(
                    enabled[idx][0], None, "FAILED", reason=str(e)
                )

        # Cancel stragglers (never block on them: budget is a hard cap)
        for future in not_done:
            idx = future_map[future]
            try:
                future.cancel()
            except Exception:
                pass
            if results[idx] is None:
                results[idx] = _provider_evidence(
                    enabled[idx][0], None, "FAILED",
                    reason="timeout budget exceeded"
                )
    finally:
        # Do NOT wait for stragglers: shutdown detached so the
        # timeout budget is actually enforced (with-block would join).
        try:
            ex.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            try:
                ex.shutdown(wait=False)
            except Exception:
                pass

    return [r for r in results if r is not None]

def _ev_dict_to_evidence(d: Dict[str, Any]) -> Evidence:
    """Convert an Evidence-shaped dict (Stage 19) back to an Evidence object."""
    try:
        meta = d.get("metadata", {}) if isinstance(d, dict) else {}
        if not isinstance(meta, dict):
            meta = {"raw": meta}
        meta.setdefault("data_type", "threat")
        return Evidence(
            source=d.get("source", "unknown"),
            timestamp=d.get("timestamp") or Evidence.now_iso(),
            value=d.get("value"),
            normalized_value=d.get("normalized_value", d.get("value")),
            confidence=float(d.get("confidence", 0.0) or 0.0),
            freshness=d.get("freshness", "UNKNOWN") or "UNKNOWN",
            status=d.get("status", "FAILED") or "FAILED",
            metadata=meta,
        )
    except Exception:
        return make_evidence(source="unknown", value=None, confidence=0.0, status="FAILED", ttl_key="threat")


def run_providers(target: str,
                  providers: Dict[str, BaseProvider],
                  config: Optional[Dict[str, Any]] = None) -> List[Evidence]:
    """
    Backwards-compatible wrapper for Stage 3 callers.
    Delegates to run_providers_parallel().

    Returns List[Evidence] (converted from Evidence-shaped dicts) so
    all downstream Stage 4 aggregation code is unchanged.
    """
    try:
        cfg = config if isinstance(config, dict) else (CFG if isinstance(CFG, dict) else {})
    except Exception:
        cfg = {}
    try:
        dicts = run_providers_parallel(target, providers, cfg)
    except Exception as e:
        logging.error(f"run_providers_parallel failed, no evidence: {e}")
        return []
    evidences: List[Evidence] = []
    for d in dicts or []:
        try:
            if isinstance(d, Evidence):
                evidences.append(d)
            elif isinstance(d, dict):
                evidences.append(_ev_dict_to_evidence(d))
        except Exception:
            continue
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
            cache_init(p)
        except Exception: pass
    def get(s, k):
        t = time.time()
        with s._l:
            v = s.l1.get(k)
            if v and t < v[0]: s.h1 += 1; return v[1]
            if v: del s.l1[k]
        try:
            with _CACHE_DB_LOCK:
                c = sqlite3.connect(s.p, timeout=30)
                try:
                    r = c.execute("SELECT value, ttl_seconds, cached_at_unix FROM cache WHERE key=?", (k,)).fetchone()
                finally:
                    c.close()
            if r:
                try:
                    v = json.loads(r[0])
                except Exception:
                    v = None
                if v is not None:
                    try:
                        expiry = float(r[2]) + int(r[1])
                    except Exception:
                        expiry = 0.0
                    if t < expiry:
                        with s._l: s.l1[k] = (expiry, v)
                        s.h2 += 1; return v
                    try:
                        with _CACHE_DB_LOCK:
                            c = sqlite3.connect(s.p, timeout=30)
                            try:
                                c.execute("DELETE FROM cache WHERE key=?", (k,)); c.commit()
                            finally:
                                c.close()
                    except Exception: pass
        except Exception: pass
        with s._l: s.m += 1
        return None
    def set(s, k, v, ttl):
        try:
            ttl = int(ttl)
        except Exception:
            ttl = 3600
        t = time.time()
        e = t + ttl
        with s._l: s.l1[k] = (e, v)
        try:
            iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            with _CACHE_DB_LOCK:
                c = sqlite3.connect(s.p, timeout=30)
                try:
                    c.execute("INSERT OR REPLACE INTO cache(key, value, source, ttl_seconds, cached_at, cached_at_unix) VALUES(?,?,?,?,?,?)", (k, json.dumps(v, default=str), "http", int(ttl), iso, float(t)))
                    c.commit()
                finally:
                    c.close()
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
#  INFRASTRUCTURE INTELLIGENCE — v33.1 (Stage 6)
# ============================================================
def _resolve_to_ip(target: str) -> Optional[str]:
    """Return the target as an IP string. If domain, resolve to first A record (Stage 6)."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        import dns.resolver
        answers = dns.resolver.resolve(target, "A", raise_on_no_answer=False)
        if answers and answers.rrset:
            return answers[0].to_text()
    except Exception:
        pass
    return None

def _classify_asn(asn_name: str) -> str:
    """Classify ASN type based on name patterns (Stage 6)."""
    name = asn_name.lower()
    if any(k in name for k in ["google", "amazon", "microsoft", "cloudflare", "akamai", "fastly"]):
        return "hosting"
    if any(k in name for k in ["university", "college", "edu"]):
        return "education"
    if any(k in name for k in ["government", "gov", "ministry"]):
        return "government"
    if any(k in name for k in ["telecom", "mobile", "broadband", "isp"]):
        return "isp"
    if any(k in name for k in ["hosting", "datacenter", "vps", "cloud"]):
        return "hosting"
    return "unknown"

def asn_analysis(ip: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Query ASN information for an IP via Team Cymru DNS (Stage 6, no API key).
    """
    result: Dict[str, Any] = {
        "asn": None,
        "asn_name": None,
        "country": None,
        "type": "unknown",
        "source": "team-cymru",
        "confidence": 0.0
    }
    try:
        import dns.resolver
        rev = ".".join(reversed(ip.split(".")))
        query = f"{rev}.origin.asn.cymru.com"
        answers = dns.resolver.resolve(query, "TXT", raise_on_no_answer=False)
        if answers and answers.rrset:
            txt = answers[0].to_text().strip('"')
            parts = [p.strip() for p in txt.split("|")]
            if len(parts) >= 5:
                try:
                    result["asn"] = int(parts[0])
                except Exception:
                    result["asn"] = parts[0]
                result["prefix"] = parts[1]
                result["country"] = parts[2]
                result["rir"] = parts[3]
                result["allocated"] = parts[4]
                result["confidence"] = 0.95
    except Exception as e:
        result["error"] = str(e)
    if result.get("asn"):
        try:
            import dns.resolver
            query = f"AS{result['asn']}.asn.cymru.com"
            answers = dns.resolver.resolve(query, "TXT", raise_on_no_answer=False)
            if answers and answers.rrset:
                txt = answers[0].to_text().strip('"')
                parts = [p.strip() for p in txt.split("|")]
                if len(parts) >= 5:
                    result["asn_name"] = parts[4]
        except Exception:
            pass
    result["type"] = _classify_asn(result.get("asn_name", "") or "")
    return result

def prefix_analysis(ip: str, config: Dict[str, Any], asn_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze the prefix containing the IP (Stage 6)."""
    result: Dict[str, Any] = {
        "prefix": None,
        "netrange": None,
        "cidr": None,
        "prefix_length": None,
        "host_count": None,
        "rir": None,
        "allocated": None,
        "confidence": 0.0
    }
    if asn_data.get("prefix"):
        result["prefix"] = asn_data["prefix"]
        try:
            net = ipaddress.ip_network(asn_data["prefix"], strict=False)
            result["cidr"] = str(net)
            result["prefix_length"] = net.prefixlen
            result["host_count"] = net.num_addresses
            result["netrange"] = f"{net.network_address} - {net.broadcast_address}"
        except Exception:
            pass
    if asn_data.get("rir"):
        result["rir"] = asn_data["rir"]
    if asn_data.get("allocated"):
        result["allocated"] = asn_data["allocated"]
    if result["prefix"]:
        result["confidence"] = 0.9
    return result

def _rdap_lookup(ip: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Query RDAP for IP information via ARIN (Stage 6)."""
    result: Dict[str, Any] = {
        "handle": None,
        "name": None,
        "country": None,
        "org": None,
        "abuse_email": None,
        "netrange": None,
        "cidr": None,
        "created": None,
        "updated": None,
        "status": [],
        "confidence": 0.0,
        "source": "rdap"
    }
    try:
        url = f"https://rdap.arin.net/registry/ip/{ip}"
        timeout = 10
        try:
            timeout = int(config.get("timeouts", {}).get("http", 10))
        except Exception:
            pass
        resp = requests.get(url, timeout=timeout, headers={"Accept": "application/rdap+json"})
        if resp.status_code != 200:
            result["error"] = f"RDAP HTTP {resp.status_code}"
            return result
        data = resp.json()
        result["handle"] = data.get("handle")
        result["name"] = data.get("name")
        for entity in data.get("entities", []):
            if "registrant" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            result["org"] = item[3]
                        if item[0] == "adr":
                            if isinstance(item[3], list) and len(item[3]) >= 7:
                                result["country"] = item[3][6]
        for entity in data.get("entities", []):
            if "abuse" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "email":
                            result["abuse_email"] = item[3]
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                result["created"] = event.get("eventDate")
            elif event.get("eventAction") == "last changed":
                result["updated"] = event.get("eventDate")
        cidr0 = data.get("cidr0_cidrs", [])
        if cidr0:
            c = cidr0[0]
            result["cidr"] = f"{c.get('v4prefix')}/{c.get('length')}"
            result["netrange"] = result["cidr"]
        result["status"] = data.get("status", [])
        result["confidence"] = 0.9
    except Exception as e:
        result["error"] = str(e)
    return result

def _extract_organization(rdap_data: Dict[str, Any], asn_data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": rdap_data.get("org") or asn_data.get("asn_name"),
        "handle": rdap_data.get("handle"),
        "country": rdap_data.get("country") or asn_data.get("country"),
        "abuse_email": rdap_data.get("abuse_email"),
        "source": "rdap+asn",
        "confidence": 0.9 if rdap_data.get("org") else 0.7
    }

def _extract_origin(rdap_data: Dict[str, Any], asn_data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "origin_asn": asn_data.get("asn"),
        "origin_as_name": asn_data.get("asn_name"),
        "routing_status": "unknown",
        "source": "asn",
        "confidence": 0.85 if asn_data.get("asn") else 0.0
    }

def related_infrastructure(ip: str, asn_data: Dict[str, Any], prefix_data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Find related infrastructure: sibling prefixes, related ASNs, shared nameservers (Stage 6).
    """
    result: Dict[str, Any] = {
        "sibling_prefixes": [],
        "related_asns": [],
        "shared_nameservers": [],
        "notes": []
    }
    if prefix_data.get("prefix"):
        try:
            net = ipaddress.ip_network(prefix_data["prefix"], strict=False)
            supernet = net.supernet(prefixlen_diff=1)
            result["sibling_prefixes"].append(str(supernet))
            if net.prefixlen > 24:
                parent = ipaddress.ip_network(f"{ip}/24", strict=False)
                result["sibling_prefixes"].append(str(parent))
        except Exception:
            pass
    org_name = asn_data.get("asn_name", "") or ""
    if org_name:
        result["notes"].append(f"ASN name '{org_name}' may be related to other ASNs in the same organization.")
    return result

def _infra_history(rdap_data: Dict[str, Any], asn_data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "allocated": asn_data.get("allocated"),
        "rdap_created": rdap_data.get("created"),
        "rdap_updated": rdap_data.get("updated"),
        "change_detected": False,
        "notes": []
    }

def _peering_info(asn_data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "asn": asn_data.get("asn"),
        "peers": [],
        "upstreams": [],
        "source": "none",
        "confidence": 0.0,
        "note": "Peering data requires external BGP source."
    }

def infra_profile(target: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build an Infrastructure Profile for an IP or domain target (Stage 6).
    Steps: resolve → ASN → prefix → RDAP → org → origin → related → history → peering
    """
    infra_cfg = config.get("infrastructure", {}) or {}
    include_peering = infra_cfg.get("include_peering", True)
    include_history = infra_cfg.get("include_history", True)
    ip = _resolve_to_ip(target)
    if not ip:
        return {
            "status": "FAILED",
            "reason": "Could not resolve target to an IP address.",
            "ip": None
        }
    asn_data = asn_analysis(ip, config)
    prefix_data = prefix_analysis(ip, config, asn_data)
    rdap_data = _rdap_lookup(ip, config)
    org_data = _extract_organization(rdap_data, asn_data)
    origin_data = _extract_origin(rdap_data, asn_data)
    related = related_infrastructure(ip, asn_data, prefix_data, config)
    history: Dict[str, Any] = {}
    if include_history:
        history = _infra_history(rdap_data, asn_data)
    return {
        "status": "OK",
        "ip": ip,
        "asn": asn_data,
        "prefix": prefix_data,
        "rdap": rdap_data,
        "organization": org_data,
        "origin": origin_data,
        "related_infrastructure": related,
        "history": history,
        "peering": _peering_info(asn_data, config) if include_peering else {}
    }

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
#  DNS INTELLIGENCE ENGINE — v33 (Stage 5)
# ============================================================
DNS_RECORD_TYPES = ["A", "AAAA", "PTR", "NS", "MX", "TXT", "CAA", "SOA", "CNAME"]

def _normalize_dns_record(rtype: str, raw: str) -> str:
    """Normalize DNS record value for consistent comparison (Stage 5)."""
    raw = raw.strip()
    if rtype in ("A", "AAAA"):
        return raw.lower()
    if rtype in ("NS", "CNAME", "PTR"):
        return raw.rstrip(".").lower()
    if rtype == "MX":
        parts = raw.split()
        if len(parts) == 2:
            return f"{parts[0]} {parts[1].rstrip('.').lower()}"
        return raw.lower()
    if rtype == "TXT":
        return raw.strip('"')
    if rtype == "CAA":
        return re.sub(r'\s+', ' ', raw.strip('"')).strip()
    if rtype == "SOA":
        return re.sub(r'\s+', ' ', raw).strip()
    return raw

def dns_collect(target: str, config: Dict[str, Any]) -> List[Evidence]:
    """
    Collect DNS records for a target and return them as Evidence objects (Stage 5).
    Handles both IP targets (PTR) and domain targets (A, AAAA, NS, MX, TXT, CAA, SOA, CNAME).
    """
    evidences: List[Evidence] = []
    # Support both new top-level dns config and legacy sources.dns
    dns_cfg = config.get("dns", {}) or {}
    if not dns_cfg.get("records"):
        # Fallback to legacy
        dns_cfg = config.get("sources", {}).get("dns", {}) or dns_cfg
    record_types = dns_cfg.get("records", DNS_RECORD_TYPES)
    # Also check for legacy record_types key
    if not record_types:
        record_types = DNS_RECORD_TYPES
    timeout = 5
    try:
        timeout = int(config.get("timeouts", {}).get("dns", 5))
    except Exception:
        timeout = 5
    # Also check phase_g or other
    if timeout == 5 and config.get("phase_g", {}).get("dns", {}).get("timeout"):
        try:
            timeout = int(config["phase_g"]["dns"]["timeout"])
        except Exception:
            pass
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    # Detect if target is an IP
    is_ip = False
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False
    # For IP targets, only PTR makes sense
    if is_ip:
        record_types = ["PTR"]
    else:
        record_types = [rt for rt in record_types if rt != "PTR"]
    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype, raise_on_no_answer=False)
            if answers is None or answers.rrset is None:
                evidences.append(make_evidence(
                    source="dns", value=None, normalized_value=None,
                    confidence=0.0, status="PARTIAL", ttl_key="dns",
                    metadata={"record_type": rtype, "reason": "no_answer", "data_type": "dns", "field": rtype, "target": target}
                ))
                continue
            ttl = answers.rrset.ttl
            for rdata in answers:
                raw = rdata.to_text()
                normalized = _normalize_dns_record(rtype, raw)
                evidences.append(make_evidence(
                    source="dns",
                    value=raw,
                    normalized_value=normalized,
                    confidence=0.95,
                    status="OK",
                    ttl_key="dns",
                    metadata={"record_type": rtype, "ttl": ttl, "data_type": "dns", "field": rtype, "target": target, "raw_value": raw}
                ))
        except dns.resolver.NXDOMAIN:
            evidences.append(make_evidence(
                source="dns", value=None, normalized_value=None,
                confidence=0.0, status="PARTIAL", ttl_key="dns",
                metadata={"record_type": rtype, "reason": "NXDOMAIN", "data_type": "dns", "field": rtype, "target": target}
            ))
        except dns.resolver.NoNameservers:
            evidences.append(make_evidence(
                source="dns", value=None, normalized_value=None,
                confidence=0.0, status="FAILED", ttl_key="dns",
                metadata={"record_type": rtype, "reason": "no_nameservers", "data_type": "dns", "field": rtype, "target": target}
            ))
        except dns.exception.Timeout:
            evidences.append(make_evidence(
                source="dns", value=None, normalized_value=None,
                confidence=0.0, status="FAILED", ttl_key="dns",
                metadata={"record_type": rtype, "reason": "timeout", "data_type": "dns", "field": rtype, "target": target}
            ))
        except Exception as e:
            evidences.append(make_evidence(
                source="dns", value=None, normalized_value=None,
                confidence=0.0, status="FAILED", ttl_key="dns",
                metadata={"record_type": rtype, "reason": str(e), "data_type": "dns", "field": rtype, "target": target}
            ))
    return evidences

def _dns_consistency(by_type: Dict[str, List[Evidence]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "a_vs_ptr": None,
        "ns_vs_soa": None,
        "cname_chain": [],
        "duplicate_records": []
    }
    a_records = {ev.normalized_value for ev in by_type.get("A", []) if ev.normalized_value}
    ptr_records = {ev.normalized_value for ev in by_type.get("PTR", []) if ev.normalized_value}
    if a_records or ptr_records:
        result["a_vs_ptr"] = {
            "a_count": len(a_records),
            "ptr_count": len(ptr_records),
            "consistent": len(a_records) == len(ptr_records) if a_records and ptr_records else None
        }
    ns = {ev.normalized_value for ev in by_type.get("NS", []) if ev.normalized_value}
    soa = [ev.normalized_value for ev in by_type.get("SOA", []) if ev.normalized_value]
    if ns or soa:
        soa_primary = None
        if soa:
            parts = soa[0].split()
            if parts:
                soa_primary = parts[0].rstrip(".").lower()
        result["ns_vs_soa"] = {
            "ns_count": len(ns),
            "soa_primary": soa_primary,
            "consistent": (soa_primary in ns) if soa_primary else None
        }
    for rtype, evs in by_type.items():
        values = [ev.normalized_value for ev in evs if ev.normalized_value]
        seen: set = set()
        dupes: set = set()
        for v in values:
            if v in seen:
                dupes.add(v)
            seen.add(v)
        if dupes:
            result["duplicate_records"].append({
                "record_type": rtype,
                "duplicates": sorted(dupes)
            })
    return result

def _dns_ttl_analysis(by_type: Dict[str, List[Evidence]]) -> Dict[str, Any]:
    ttls: List[int] = []
    per_type: Dict[str, Any] = {}
    for rtype, evs in by_type.items():
        type_ttls = [ev.metadata.get("ttl") for ev in evs if ev.metadata.get("ttl") is not None]
        if type_ttls:
            per_type[rtype] = {
                "min": min(type_ttls),
                "max": max(type_ttls),
                "avg": round(sum(type_ttls) / len(type_ttls), 2)
            }
            ttls.extend(type_ttls)
    low_ttl = [t for t in ttls if t < 60]
    high_ttl = [t for t in ttls if t > 86400]
    return {
        "per_type": per_type,
        "overall_min": min(ttls) if ttls else None,
        "overall_max": max(ttls) if ttls else None,
        "overall_avg": round(sum(ttls) / len(ttls), 2) if ttls else None,
        "low_ttl_count": len(low_ttl),
        "high_ttl_count": len(high_ttl),
        "low_ttl_warning": len(low_ttl) > 0,
        "high_ttl_warning": len(high_ttl) > 0
    }

def _identify_mail_provider(host: str) -> str:
    """Map MX host patterns to known providers (Stage 5)."""
    # Try config first
    try:
        cfg = CFG.get("dns", {}).get("known_mail_providers", {}) or {}
        if not cfg:
            cfg = CFG.get("sources", {}).get("dns", {}).get("known_mail_providers", {}) or {}
    except Exception:
        cfg = {}
    if not cfg:
        cfg = {
            "google": ["google.com", "googlemail.com", "gmail.com"],
            "microsoft": ["outlook.com", "office365.com", "protection.outlook.com"],
            "cloudflare": ["cloudflare.net", "cloudflare.com"],
            "amazon": ["amazonaws.com", "ses.amazonaws.com"],
            "proofpoint": ["pphosted.com", "proofpoint.com"],
            "mimecast": ["mimecast.com"],
            "zoho": ["zoho.com"],
            "yandex": ["yandex.net", "yandex.ru"],
        }
    host = host.lower()
    for provider, suffixes in cfg.items():
        if any(host.endswith(s) for s in suffixes):
            return provider
    # Fallback hardcoded
    patterns = {
        "google": ["google.com", "googlemail.com", "gmail.com"],
        "microsoft": ["outlook.com", "office365.com", "protection.outlook.com"],
        "cloudflare": ["cloudflare.net", "cloudflare.com"],
        "amazon": ["amazonaws.com", "ses.amazonaws.com"],
        "proofpoint": ["pphosted.com", "proofpoint.com"],
        "mimecast": ["mimecast.com"],
        "zoho": ["zoho.com"],
        "yandex": ["yandex.net", "yandex.ru"],
    }
    for provider, suffixes in patterns.items():
        if any(host.endswith(s) for s in suffixes):
            return provider
    return "unknown"

def _dns_mail_analysis(by_type: Dict[str, List[Evidence]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "mx_records": [],
        "mx_providers": [],
        "spf": None,
        "dmarc": None,
        "dkim_indicators": []
    }
    for ev in by_type.get("MX", []):
        if not ev.normalized_value:
            continue
        parts = ev.normalized_value.split()
        if len(parts) == 2:
            try:
                priority = int(parts[0])
            except Exception:
                priority = 0
            host = parts[1]
            result["mx_records"].append({"priority": priority, "host": host})
            result["mx_providers"].append(_identify_mail_provider(host))
    for ev in by_type.get("TXT", []):
        if not ev.normalized_value:
            continue
        txt = ev.normalized_value
        if txt.startswith("v=spf1"):
            result["spf"] = txt
        elif txt.startswith("v=DMARC1"):
            result["dmarc"] = txt
        elif "v=DKIM1" in txt or "k=rsa" in txt:
            result["dkim_indicators"].append(txt[:120])
    result["mx_providers"] = sorted(set(result["mx_providers"]))
    return result

def _dns_security_analysis(by_type: Dict[str, List[Evidence]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "spf_present": False,
        "spf_valid": False,
        "dmarc_present": False,
        "dmarc_policy": None,
        "caa_present": False,
        "caa_records": []
    }
    for ev in by_type.get("TXT", []):
        if not ev.normalized_value:
            continue
        txt = ev.normalized_value
        if txt.startswith("v=spf1"):
            result["spf_present"] = True
            result["spf_valid"] = any(txt.endswith(s) for s in ["-all", "~all", "?all"])
        elif txt.startswith("v=DMARC1"):
            result["dmarc_present"] = True
            for part in txt.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    result["dmarc_policy"] = part.split("=")[1].strip()
    for ev in by_type.get("CAA", []):
        if ev.normalized_value:
            result["caa_present"] = True
            result["caa_records"].append(ev.normalized_value)
    return result

def dns_relationships(by_type: Dict[str, List[Evidence]]) -> Dict[str, Any]:
    """
    Build DNS relationships: domain → NS, domain → MX, domain → CNAME → target, MX → provider (Stage 5).
    """
    relationships: Dict[str, Any] = {
        "nameservers": [],
        "mail_servers": [],
        "cname_chains": [],
        "cname_loops": []
    }
    for ev in by_type.get("NS", []):
        if ev.normalized_value:
            relationships["nameservers"].append(ev.normalized_value)
    for ev in by_type.get("MX", []):
        if ev.normalized_value:
            parts = ev.normalized_value.split()
            if len(parts) == 2:
                relationships["mail_servers"].append(parts[1])
    cname_targets = {ev.normalized_value for ev in by_type.get("CNAME", []) if ev.normalized_value}
    for target in cname_targets:
        chain = [target]
        seen = {target}
        current = target
        for _ in range(5):
            try:
                answers = dns.resolver.resolve(current, "CNAME", raise_on_no_answer=False)
                if answers and answers.rrset:
                    next_target = answers[0].to_text().rstrip(".").lower()
                    if next_target in seen:
                        relationships["cname_loops"].append(chain + [next_target])
                        break
                    seen.add(next_target)
                    chain.append(next_target)
                    current = next_target
                else:
                    break
            except Exception:
                break
        if len(chain) > 1:
            relationships["cname_chains"].append(chain)
    return relationships

def _dns_anomalies(by_type: Dict[str, List[Evidence]], analysis: Dict[str, Any], is_ip: bool = False) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    if "A" not in by_type and "AAAA" not in by_type:
        if not is_ip:
            anomalies.append({
                "type": "missing_ip_records",
                "severity": "low",
                "message": "No A or AAAA records found."
            })
    if "NS" not in by_type:
        anomalies.append({
            "type": "missing_ns",
            "severity": "moderate",
            "message": "No NS records found. Delegation may be misconfigured."
        })
    if not is_ip:
        if analysis.get("security", {}).get("spf_present") is False:
            anomalies.append({
                "type": "missing_spf",
                "severity": "moderate",
                "message": "No SPF record found."
            })
        if analysis.get("security", {}).get("dmarc_present") is False:
            anomalies.append({
                "type": "missing_dmarc",
                "severity": "moderate",
                "message": "No DMARC record found."
            })
    if analysis.get("relationships", {}).get("cname_loops"):
        anomalies.append({
            "type": "cname_loop",
            "severity": "high",
            "message": f"CNAME loop detected: {analysis['relationships']['cname_loops']}"
        })
    if analysis.get("ttl", {}).get("low_ttl_warning"):
        anomalies.append({
            "type": "low_ttl",
            "severity": "informational",
            "message": f"{analysis['ttl']['low_ttl_count']} records with TTL < 60s."
        })
    nsoa = analysis.get("consistency", {}).get("ns_vs_soa")
    if nsoa and nsoa.get("consistent") is False:
        anomalies.append({
            "type": "ns_soa_mismatch",
            "severity": "moderate",
            "message": "SOA primary is not in NS records."
        })
    return anomalies

def dns_analyze(evidences: List[Evidence], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze DNS Evidence and produce DNS intelligence (Stage 5).
    """
    dns_cfg = config.get("dns", {}) or {}
    # Fallback to legacy
    if not dns_cfg:
        dns_cfg = config.get("sources", {}).get("dns", {}) or {}
    ttl_analysis = dns_cfg.get("ttl_analysis", True)
    mail_analysis = dns_cfg.get("mail_analysis", True)
    # Detect is_ip via PTR presence or explicit flag
    is_ip = any(ev.metadata.get("record_type") == "PTR" for ev in evidences if ev.status == "OK")
    by_type: Dict[str, List[Evidence]] = {}
    for ev in evidences:
        if ev.status != "OK":
            continue
        rtype = ev.metadata.get("record_type", "UNKNOWN")
        by_type.setdefault(rtype, []).append(ev)
    analysis: Dict[str, Any] = {
        "record_types_present": sorted(by_type.keys()),
        "record_counts": {rt: len(evs) for rt, evs in by_type.items()},
        "consistency": {},
        "ttl": {},
        "mail": {},
        "security": {},
        "relationships": {},
        "anomalies": []
    }
    analysis["consistency"] = _dns_consistency(by_type)
    if ttl_analysis:
        analysis["ttl"] = _dns_ttl_analysis(by_type)
    if mail_analysis:
        analysis["mail"] = _dns_mail_analysis(by_type)
    analysis["security"] = _dns_security_analysis(by_type)
    analysis["relationships"] = dns_relationships(by_type)
    analysis["anomalies"] = _dns_anomalies(by_type, analysis, is_ip=is_ip)
    return analysis

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
#  CERTIFICATE INTELLIGENCE 2.0 — v34 (Stage 7)
#  Single source of truth for TLS / CT certificate correlation.
#  Reuses crt.sh (existing CT source); no new providers.
# ============================================================
def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _is_expired(not_after: Optional[str]) -> bool:
    if not not_after:
        return False
    try:
        dt = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        return dt < datetime.now(timezone.utc)
    except Exception:
        return False


def _is_near_expiry(not_after: Optional[str], days: int = 30) -> bool:
    if not not_after:
        return False
    try:
        dt = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        delta = (dt - datetime.now(timezone.utc)).days
        return 0 <= delta <= days
    except Exception:
        return False


def _get_name_attr(name: x509.Name, oid) -> Optional[str]:
    try:
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None
    except Exception:
        return None


def _key_info(pubkey) -> Tuple[str, Optional[int]]:
    if isinstance(pubkey, rsa.RSAPublicKey):
        return "RSA", pubkey.key_size
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return "EC", pubkey.key_size
    if isinstance(pubkey, dsa.DSAPublicKey):
        return "DSA", pubkey.key_size
    return "unknown", None


def _parse_x509(cert: x509.Certificate, source: str = "unknown") -> Dict[str, Any]:
    """
    Parse a cryptography.x509.Certificate into a structured dict.
    """
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    subject_cn = _get_name_attr(cert.subject, NameOID.COMMON_NAME)
    subject_o = _get_name_attr(cert.subject, NameOID.ORGANIZATION_NAME)
    issuer_cn = _get_name_attr(cert.issuer, NameOID.COMMON_NAME)
    issuer_o = _get_name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    san_domains: List[str] = []
    san_ips: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in ext.value:
            if isinstance(name, x509.DNSName):
                san_domains.append(name.value.lower())
            elif isinstance(name, x509.IPAddress):
                san_ips.append(str(name.value))
    except x509.ExtensionNotFound:
        pass
    if hasattr(cert, "not_valid_before_utc"):
        not_before = cert.not_valid_before_utc.isoformat()
    else:
        not_before = cert.not_valid_before.isoformat()
    if hasattr(cert, "not_valid_after_utc"):
        not_after = cert.not_valid_after_utc.isoformat()
    else:
        not_after = cert.not_valid_after.isoformat()
    now = datetime.now(timezone.utc)
    try:
        if hasattr(cert, "not_valid_after_utc"):
            expired = cert.not_valid_after_utc < now
        else:
            expired = cert.not_valid_after < now.replace(tzinfo=None)
    except Exception:
        expired = False
    near_expiry = False
    try:
        if hasattr(cert, "not_valid_after_utc"):
            delta = (cert.not_valid_after_utc - now).days
        else:
            delta = (cert.not_valid_after - now.replace(tzinfo=None)).days
        near_expiry = 0 <= delta <= 30
    except Exception:
        pass
    pubkey = cert.public_key()
    key_type, key_size = _key_info(pubkey)
    try:
        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    except Exception:
        sig_algo = "unknown"
    wildcard = any(d.startswith("*.") for d in san_domains) or (subject_cn or "").startswith("*.")
    return {
        "source": source,
        "fingerprint_sha256": fingerprint,
        "subject_cn": subject_cn,
        "subject_o": subject_o,
        "issuer_cn": issuer_cn,
        "issuer_o": issuer_o,
        "san_domains": sorted(set(san_domains)),
        "san_ips": sorted(set(san_ips)),
        "san_count": len(san_domains) + len(san_ips),
        "not_before": not_before,
        "not_after": not_after,
        "expired": expired,
        "near_expiry": near_expiry,
        "key_type": key_type,
        "key_size": key_size,
        "signature_algorithm": sig_algo,
        "wildcard": wildcard,
        "serial": str(cert.serial_number),
    }


def live_certificate(ip: str, port: int = 443,
                     timeout: int = 10) -> Optional[Dict[str, Any]]:
    """
    Perform a TLS handshake with the IP and extract the certificate.
    Returns a dict with parsed certificate data, or None on failure.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return None
                cert = x509.load_der_x509_certificate(der)
                return _parse_x509(cert, source="live")
    except Exception as e:
        return {"error": str(e), "source": "live", "status": "FAILED"}


def ct_collect(target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Query CT logs for certificates associated with the target.
    Uses crt.sh JSON endpoint.
    Returns a list of parsed certificate dicts.
    """
    results: List[Dict[str, Any]] = []
    cert_cfg = (config or {}).get("certificate", {}) if isinstance(config, dict) else {}
    timeout = cert_cfg.get("ct_timeout") or (config.get("timeouts", {}).get("http", 10) if isinstance(config, dict) else 10)
    is_ip = _is_ip(target)
    try:
        if is_ip:
            return results
        url = f"https://crt.sh/?q={target}&output=json"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return results
        data = resp.json()
    except Exception:
        return results
    if not isinstance(data, list):
        return results
    seen_fingerprints = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        fp = entry.get("sha256") or entry.get("fingerprint_sha256")
        if not fp:
            cid = str(entry.get("id", ""))
            fp = f"crtsh:{cid}" if cid else None
        if not fp or fp in seen_fingerprints:
            continue
        seen_fingerprints.add(fp)
        name_value = entry.get("name_value", "") or ""
        san_domains = sorted({
            n.strip().lower()
            for n in str(name_value).split("\n")
            if n.strip()
        })
        parsed = {
            "source": "ct",
            "fingerprint_sha256": fp,
            "subject_cn": entry.get("common_name"),
            "issuer_cn": entry.get("issuer_name"),
            "issuer_o": None,
            "san_domains": san_domains,
            "san_ips": [],
            "san_count": len(san_domains),
            "not_before": entry.get("not_before"),
            "not_after": entry.get("not_after"),
            "expired": _is_expired(entry.get("not_after")),
            "near_expiry": _is_near_expiry(entry.get("not_after")),
            "key_type": None,
            "key_size": None,
            "signature_algorithm": None,
            "wildcard": any(d.startswith("*.") for d in san_domains),
            "serial": entry.get("serial_number"),
            "ct_entry_id": entry.get("id"),
        }
        results.append(parsed)
    return results


def certificate_metadata(cert: Dict[str, Any],
                         history: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Build a metadata object for a certificate.
    history: optional dict with first_seen/last_seen from a CT timeline.
    """
    history = history or {}
    return {
        "fingerprint_sha256": cert.get("fingerprint_sha256"),
        "first_seen": history.get("first_seen") or cert.get("not_before"),
        "last_seen": history.get("last_seen") or cert.get("not_after"),
        "current": not cert.get("expired", False),
        "expired": cert.get("expired", False),
        "near_expiry": cert.get("near_expiry", False),
        "issuer_cn": cert.get("issuer_cn"),
        "issuer_o": cert.get("issuer_o"),
        "signature_algorithm": cert.get("signature_algorithm"),
        "key_type": cert.get("key_type"),
        "key_size": cert.get("key_size"),
        "san_count": cert.get("san_count", 0),
        "wildcard": cert.get("wildcard", False)
    }


def ct_correlate(live_cert: Optional[Dict[str, Any]],
                 ct_certs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Correlate the live certificate with CT certificates.
    Identify:
      - Live cert in CT (same fingerprint)
      - Live cert not in CT (private or internal)
      - CT certs matching live SANs
    """
    result: Dict[str, Any] = {
        "live_in_ct": False,
        "live_fingerprint": None,
        "ct_fingerprints": [],
        "matching_sans": [],
        "private_certificate": False
    }
    if not live_cert or live_cert.get("status") == "FAILED":
        return result
    live_fp = live_cert.get("fingerprint_sha256")
    result["live_fingerprint"] = live_fp
    result["ct_fingerprints"] = [c.get("fingerprint_sha256") for c in (ct_certs or [])]
    if live_fp and live_fp in result["ct_fingerprints"]:
        result["live_in_ct"] = True
    elif live_fp:
        result["private_certificate"] = True
    live_sans = set(live_cert.get("san_domains", []) or [])
    for c in (ct_certs or []):
        shared = live_sans & set(c.get("san_domains", []) or [])
        if shared:
            result["matching_sans"].append({
                "fingerprint": c.get("fingerprint_sha256"),
                "shared_sans": sorted(shared)
            })
    return result


def certificate_relationships(certificates: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build relationships:
      - by issuer
      - by fingerprint
      - by shared SAN
      - by wildcard scope
    """
    relationships: Dict[str, Any] = {
        "by_issuer": {},
        "by_fingerprint": {},
        "by_shared_san": [],
        "wildcard_certs": [],
        "expired_certs": [],
        "weak_algo_certs": []
    }
    for cert in (certificates or []):
        issuer = cert.get("issuer_cn") or cert.get("issuer_o") or "unknown"
        relationships["by_issuer"].setdefault(issuer, []).append(
            cert.get("fingerprint_sha256")
        )
    for cert in (certificates or []):
        fp = cert.get("fingerprint_sha256")
        if fp:
            relationships["by_fingerprint"].setdefault(fp, []).append(
                cert.get("subject_cn") or cert.get("source")
            )
    san_map: Dict[str, List[str]] = {}
    for cert in (certificates or []):
        for san in (cert.get("san_domains", []) or []):
            san_map.setdefault(san, []).append(cert.get("fingerprint_sha256"))
    for san, fps in san_map.items():
        if len(set(fps)) > 1:
            relationships["by_shared_san"].append({
                "san": san,
                "certificates": sorted(set(fps))
            })
    relationships["wildcard_certs"] = [
        c.get("fingerprint_sha256") for c in (certificates or []) if c.get("wildcard")
    ]
    relationships["expired_certs"] = [
        c.get("fingerprint_sha256") for c in (certificates or []) if c.get("expired")
    ]
    weak = []
    for c in (certificates or []):
        algo = (c.get("signature_algorithm") or "").lower()
        key_size = c.get("key_size") or 0
        if "sha1" in algo or "md5" in algo:
            weak.append(c.get("fingerprint_sha256"))
        elif c.get("key_type") == "RSA" and key_size and key_size < 2048:
            weak.append(c.get("fingerprint_sha256"))
    relationships["weak_algo_certs"] = weak
    return relationships


def _certificate_anomalies(certificates: List[Dict[str, Any]],
                           relationships: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    try:
        cert_cfg = CFG.get("certificate", {}) if isinstance(CFG, dict) else {}
    except Exception:
        cert_cfg = {}
    max_wildcards = cert_cfg.get("max_wildcards_before_warning", 5)
    max_shared = cert_cfg.get("max_shared_san_before_warning", 3)
    try:
        max_wildcards = int(max_wildcards)
    except Exception:
        max_wildcards = 5
    try:
        max_shared = int(max_shared)
    except Exception:
        max_shared = 3
    if relationships.get("expired_certs"):
        anomalies.append({
            "type": "expired_certificate",
            "severity": "moderate",
            "message": f"{len(relationships['expired_certs'])} expired certificate(s) found."
        })
    if relationships.get("weak_algo_certs"):
        anomalies.append({
            "type": "weak_algorithm",
            "severity": "high",
            "message": f"{len(relationships['weak_algo_certs'])} certificate(s) use weak algorithms."
        })
    wildcards = relationships.get("wildcard_certs", []) or []
    if len(wildcards) > max_wildcards:
        anomalies.append({
            "type": "wildcard_overuse",
            "severity": "informational",
            "message": f"{len(wildcards)} wildcard certificates detected."
        })
    for entry in (relationships.get("by_shared_san", []) or []):
        if len(entry.get("certificates", [])) > max_shared:
            anomalies.append({
                "type": "shared_san_across_certs",
                "severity": "informational",
                "message": f"SAN '{entry['san']}' appears in {len(entry['certificates'])} certificates."
            })
    return anomalies


def certificate_intelligence(target: str,
                             config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Full certificate intelligence pipeline.
    Single source of truth for certificate layer (Stage 7).
    """
    config = config or {}
    cert_cfg = config.get("certificate", {}) if isinstance(config, dict) else {}
    include_expired = cert_cfg.get("include_expired", True)
    include_san = cert_cfg.get("include_san", True)
    include_fingerprint = cert_cfg.get("include_fingerprint", True)
    live_handshake = cert_cfg.get("live_handshake", True)
    timeouts = config.get("timeouts", {}) if isinstance(config, dict) else {}
    live_timeout = timeouts.get("default", 10)
    try:
        live_timeout = int(live_timeout)
    except Exception:
        live_timeout = 10
    live = None
    if live_handshake:
        try:
            live = live_certificate(target, timeout=live_timeout)
        except Exception as e:
            live = {"error": str(e), "source": "live", "status": "FAILED"}
    ct_certs = ct_collect(target, config)
    if not include_expired:
        ct_certs = [c for c in ct_certs if not c.get("expired")]
    if not include_san:
        for c in ([live] if live else []) + ct_certs:
            if isinstance(c, dict):
                c = dict(c)
        # keep SANs internally for correlation; flag only controls exposure
    _ = include_san
    _ = include_fingerprint
    correlation = ct_correlate(live, ct_certs)
    all_certs = ([live] if live and isinstance(live, dict) and live.get("status") != "FAILED" and live.get("fingerprint_sha256") else []) + (ct_certs or [])
    metadata = [certificate_metadata(c) for c in all_certs]
    relationships = certificate_relationships(all_certs)
    anomalies = _certificate_anomalies(all_certs, relationships)
    return {
        "live_certificate": live,
        "ct_certificates": ct_certs,
        "correlation": correlation,
        "metadata": metadata,
        "relationships": relationships,
        "anomalies": anomalies,
        "summary": {
            "total_certificates": len(all_certs),
            "live_in_ct": correlation.get("live_in_ct", False),
            "private_certificate": correlation.get("private_certificate", False),
            "expired_count": len(relationships.get("expired_certs", [])),
            "weak_algo_count": len(relationships.get("weak_algo_certs", [])),
            "wildcard_count": len(relationships.get("wildcard_certs", []))
        }
    }

# ============================================================
#  PASSIVE DNS INTELLIGENCE — v34.1 (Stage 8)
#  Single source of truth for passive DNS timeline layer.
#  Uses existing passive DNS source(s); no new providers.
# ============================================================
def _normalize_timestamp(ts: Any) -> Optional[str]:
    """
    Normalize various timestamp formats to ISO8601 UTC.
    Accepts: int (unix), float (unix), str (ISO8601 or unix string).
    Returns None if unparseable.
    """
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return None
    if isinstance(ts, str):
        ts = ts.strip()
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass
        try:
            dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return None
    return None


def _query_passive_dns_sources(target: str, config: Dict[str, Any],
                               timeout: int) -> List[Dict[str, Any]]:
    """
    Query configured passive DNS sources.
    Returns a list of raw records with fields:
      domain, first_seen, last_seen, count, source, direction
    """
    records: List[Dict[str, Any]] = []
    pdns_cfg = (config or {}).get("passive_dns", {}) if isinstance(config, dict) else {}
    sources = pdns_cfg.get("sources", []) or []
    for source in sources:
        if not isinstance(source, dict):
            continue
        name = source.get("name", "unknown")
        if source.get("enabled") is False:
            continue
        url_template = source.get("url")
        if not url_template:
            continue
        try:
            url = url_template.format(target=target)
            resp = requests.get(url, timeout=timeout)
            if resp.status_code != 200:
                continue
            data = resp.json()
            items = data if isinstance(data, list) else data.get("results", [])
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                records.append({
                    "domain": item.get("domain") or item.get("rrname"),
                    "first_seen": item.get("first_seen") or item.get("time_first"),
                    "last_seen": item.get("last_seen") or item.get("time_last"),
                    "count": item.get("count"),
                    "source": name,
                    "direction": item.get("direction", "ip_to_domain")
                })
        except Exception:
            continue
    return records


def passive_dns_collect(target: str, config: Dict[str, Any]) -> List[Evidence]:
    """
    Collect passive DNS records for a target and return them as Evidence objects.
    Each Evidence represents one observation:
      value = domain (or IP depending on direction)
      metadata:
        first_seen: ISO8601
        last_seen:  ISO8601
        direction:  "domain_to_ip" | "ip_to_domain"
        count:      observation count (if available)
    """
    evidences: List[Evidence] = []
    pdns_cfg = (config or {}).get("passive_dns", {}) if isinstance(config, dict) else {}
    timeout = (config.get("timeouts", {}).get("http", 10) if isinstance(config, dict) else 10)
    try:
        timeout = int(timeout)
    except Exception:
        timeout = 10
    raw_records = _query_passive_dns_sources(target, config, timeout)
    for rec in raw_records:
        domain = rec.get("domain")
        if not domain:
            continue
        first_seen = _normalize_timestamp(rec.get("first_seen"))
        last_seen = _normalize_timestamp(rec.get("last_seen"))
        evidences.append(make_evidence(
            source=rec.get("source", "passive_dns"),
            value=domain,
            normalized_value=str(domain).strip().lower().rstrip("."),
            confidence=rec.get("confidence", 0.6),
            status="OK",
            ttl_key="passive_dns",
            metadata={
                "first_seen": first_seen,
                "last_seen": last_seen,
                "direction": rec.get("direction", "ip_to_domain"),
                "count": rec.get("count"),
                "raw_source": rec.get("source", "passive_dns")
            }
        ))
    return evidences


def passive_dns_timeline(evidences: List[Evidence],
                         config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build a chronological timeline per domain.
    Each entry:
      domain, first_seen, last_seen, lifespan_days, count,
      observations (list of {first_seen, last_seen}),
      lifecycle: ACTIVE | HISTORICAL
    """
    pdns_cfg = (config or {}).get("passive_dns", {}) if isinstance(config, dict) else {}
    active_window_days = pdns_cfg.get("active_window_days", 30)
    try:
        active_window_days = int(active_window_days)
    except Exception:
        active_window_days = 30
    now = datetime.now(timezone.utc)
    grouped: Dict[str, List[Evidence]] = defaultdict(list)
    for ev in (evidences or []):
        if getattr(ev, "status", None) != "OK":
            continue
        key = getattr(ev, "normalized_value", None)
        if not key:
            continue
        grouped[key].append(ev)
    timeline = []
    for domain, evs in grouped.items():
        firsts = [e.metadata.get("first_seen") for e in evs if e.metadata.get("first_seen")]
        lasts = [e.metadata.get("last_seen") for e in evs if e.metadata.get("last_seen")]
        if not firsts and lasts:
            firsts = lasts
        if not lasts and firsts:
            lasts = firsts
        if not firsts or not lasts:
            timeline.append({
                "domain": domain,
                "first_seen": None,
                "last_seen": None,
                "lifespan_days": None,
                "count": sum((e.metadata.get("count") or 0) if isinstance(e.metadata.get("count"), (int, float)) else 0 for e in evs),
                "observations": [],
                "lifecycle": "UNKNOWN"
            })
            continue
        first_seen = min(firsts)
        last_seen = max(lasts)
        try:
            dt_first = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            dt_last = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            lifespan_days = (dt_last - dt_first).days
        except Exception:
            dt_last = None
            lifespan_days = None
        lifecycle = "UNKNOWN"
        if dt_last is not None:
            try:
                if dt_last.tzinfo is None:
                    dt_last = dt_last.replace(tzinfo=timezone.utc)
                age_days = (now - dt_last).days
                lifecycle = "ACTIVE" if age_days <= active_window_days else "HISTORICAL"
            except Exception:
                lifecycle = "UNKNOWN"
        observations = [
            {
                "first_seen": e.metadata.get("first_seen"),
                "last_seen": e.metadata.get("last_seen"),
                "count": e.metadata.get("count"),
                "source": e.source
            }
            for e in evs
        ]
        observations.sort(key=lambda x: (x["first_seen"] or ""))
        total_count = 0
        for e in evs:
            c = e.metadata.get("count")
            if isinstance(c, (int, float)):
                total_count += c
        timeline.append({
            "domain": domain,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "lifespan_days": lifespan_days,
            "count": total_count,
            "observations": observations,
            "lifecycle": lifecycle
        })
    timeline.sort(key=lambda x: (x["last_seen"] or ""), reverse=True)
    return timeline


def passive_dns_stats(timeline: List[Dict[str, Any]],
                      config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute statistics over the passive DNS timeline.
    """
    pdns_cfg = (config or {}).get("passive_dns", {}) if isinstance(config, dict) else {}
    churn_threshold = pdns_cfg.get("churn_threshold", 5)
    short_lived_days = pdns_cfg.get("short_lived_days", 7)
    max_churn = pdns_cfg.get("max_churn_domains", 20)
    try:
        churn_threshold = int(churn_threshold)
    except Exception:
        churn_threshold = 5
    try:
        short_lived_days = int(short_lived_days)
    except Exception:
        short_lived_days = 7
    try:
        max_churn = int(max_churn)
    except Exception:
        max_churn = 20
    timeline = timeline or []
    total = len(timeline)
    active = [t for t in timeline if t.get("lifecycle") == "ACTIVE"]
    historical = [t for t in timeline if t.get("lifecycle") == "HISTORICAL"]
    unknown = [t for t in timeline if t.get("lifecycle") == "UNKNOWN"]
    churn_domains = []
    for t in timeline:
        obs = t.get("observations", []) or []
        if len(obs) >= churn_threshold:
            if t.get("lifespan_days") is not None and t["lifespan_days"] <= short_lived_days:
                churn_domains.append({
                    "domain": t.get("domain"),
                    "observation_count": len(obs),
                    "lifespan_days": t.get("lifespan_days")
                })
            elif t.get("lifespan_days") is None:
                churn_domains.append({
                    "domain": t.get("domain"),
                    "observation_count": len(obs),
                    "lifespan_days": t.get("lifespan_days")
                })
        elif len(obs) >= churn_threshold:
            churn_domains.append({
                "domain": t.get("domain"),
                "observation_count": len(obs),
                "lifespan_days": t.get("lifespan_days")
            })
    lifespans = [t["lifespan_days"] for t in timeline if t.get("lifespan_days") is not None]
    avg_lifespan = round(sum(lifespans) / len(lifespans), 2) if lifespans else None
    firsts = [t["first_seen"] for t in timeline if t.get("first_seen")]
    lasts = [t["last_seen"] for t in timeline if t.get("last_seen")]
    return {
        "total_domains": total,
        "active_count": len(active),
        "historical_count": len(historical),
        "unknown_count": len(unknown),
        "churn_count": len(churn_domains),
        "churn_domains": churn_domains[:max_churn],
        "avg_lifespan_days": avg_lifespan,
        "earliest_first_seen": min(firsts) if firsts else None,
        "latest_last_seen": max(lasts) if lasts else None,
        "churn_threshold": churn_threshold,
        "short_lived_days": short_lived_days
    }


def _passive_dns_anomalies(timeline: List[Dict[str, Any]],
                           stats: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomalies = []
    if (stats or {}).get("churn_count", 0) > 0:
        anomalies.append({
            "type": "dns_churn",
            "severity": "moderate",
            "message": f"{stats['churn_count']} domain(s) show rapid DNS churn."
        })
    if (stats or {}).get("historical_count", 0) > 0:
        anomalies.append({
            "type": "historical_domains",
            "severity": "informational",
            "message": f"{stats['historical_count']} historical domain(s) no longer active."
        })
    for t in (timeline or []):
        if t.get("lifespan_days") is not None and t["lifespan_days"] <= 1:
            anomalies.append({
                "type": "short_lived_domain",
                "severity": "informational",
                "message": f"Domain '{t.get('domain')}' had lifespan of {t['lifespan_days']} day(s)."
            })
    unknown = [t for t in (timeline or []) if t.get("lifecycle") == "UNKNOWN"]
    if unknown:
        anomalies.append({
            "type": "missing_timestamps",
            "severity": "low",
            "message": f"{len(unknown)} domain(s) have no usable timestamps."
        })
    return anomalies


def _related_domains_by_ip(timeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identify domains that share observations (e.g., same IP or same time window).
    This is a lightweight correlation based on overlapping observation windows.
    """
    related = []
    timeline = timeline or []
    for i, a in enumerate(timeline):
        for b in timeline[i+1:]:
            a_first = a.get("first_seen")
            a_last = a.get("last_seen")
            b_first = b.get("first_seen")
            b_last = b.get("last_seen")
            if not (a_first and a_last and b_first and b_last):
                continue
            if a_first <= b_last and b_first <= a_last:
                related.append({
                    "domain_a": a.get("domain"),
                    "domain_b": b.get("domain"),
                    "overlap_start": max(a_first, b_first),
                    "overlap_end": min(a_last, b_last)
                })
    try:
        cap = int((CFG.get("passive_dns", {}) or {}).get("max_related_domains", 50)) if isinstance(CFG, dict) else 50
    except Exception:
        cap = 50
    return related[:cap]


def passive_dns_intelligence(target: str,
                             config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Full passive DNS intelligence pipeline.
    Single source of truth for passive DNS layer (Stage 8).
    """
    config = config or {}
    pdns_cfg = config.get("passive_dns", {}) if isinstance(config, dict) else {}
    build_timeline = pdns_cfg.get("timeline", True)
    evidences = passive_dns_collect(target, config)
    timeline = passive_dns_timeline(evidences, config) if build_timeline else []
    stats = passive_dns_stats(timeline, config)
    anomalies = _passive_dns_anomalies(timeline, stats)
    related = _related_domains_by_ip(timeline)
    return {
        "evidence": [ev.to_dict() for ev in evidences],
        "timeline": timeline,
        "stats": stats,
        "related_domains": related,
        "anomalies": anomalies,
        "summary": {
            "total_domains": stats.get("total_domains"),
            "active": stats.get("active_count"),
            "historical": stats.get("historical_count"),
            "churn": stats.get("churn_count"),
            "avg_lifespan_days": stats.get("avg_lifespan_days")
        }
    }

# ============================================================
#  HISTORICAL INTELLIGENCE — v35 (Stage 9)
#  Single source of truth for change detection layer.
#  Storage: snapshots table inside reconip.db. No new providers.
# ============================================================
def init_snapshot_schema(db_path: str = "reconip.db") -> None:
    """
    Ensure the snapshots table exists in reconip.db.
    """
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                data TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_snapshots_target
            ON snapshots(target)
        """)
        conn.commit()


def _extract_snapshot_fields(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract a compact, comparable snapshot from a full report.
    """
    snapshot: Dict[str, Any] = {}

    # DNS
    dns = report.get("dns_intelligence", {}) or {}
    dns_by_type: Dict[str, List[str]] = {}
    for ev in dns.get("evidence", []) or []:
        if not isinstance(ev, dict):
            continue
        if ev.get("status") != "OK":
            continue
        rtype = (ev.get("metadata", {}) or {}).get("record_type", "UNKNOWN")
        dns_by_type.setdefault(rtype, []).append(ev.get("normalized_value"))
    snapshot["dns"] = {k: sorted(set(map(str, v))) for k, v in dns_by_type.items()}

    # ASN
    infra = report.get("infrastructure_intelligence", {}) or {}
    asn = infra.get("asn", {}) or {}
    snapshot["asn"] = {
        "asn": asn.get("asn"),
        "asn_name": asn.get("asn_name"),
        "country": asn.get("country"),
        "type": asn.get("type")
    }

    # Prefix
    prefix = infra.get("prefix", {}) or {}
    snapshot["prefix"] = {
        "cidr": prefix.get("cidr"),
        "rir": prefix.get("rir"),
        "allocated": prefix.get("allocated")
    }

    # Certificate
    cert = report.get("certificate_intelligence", {}) or {}
    live = cert.get("live_certificate") or {}
    if not isinstance(live, dict):
        live = {}
    snapshot["certificate"] = {
        "fingerprint_sha256": live.get("fingerprint_sha256"),
        "issuer_cn": live.get("issuer_cn"),
        "not_after": live.get("not_after"),
        "san_count": live.get("san_count"),
        "san_domains": sorted(set(live.get("san_domains", []) or []))
    }

    # Domain (passive DNS)
    pdns = report.get("passive_dns_intelligence", {}) or {}
    snapshot["domains"] = sorted({
        t.get("domain") for t in pdns.get("timeline", []) or [] if isinstance(t, dict) and t.get("domain")
    })

    # Threat Intel
    ti = report.get("threat_intelligence", {}) or {}
    snapshot["threat"] = {
        "observed_threat_score": ti.get("observed_threat_score"),
        "threat_confidence": ti.get("threat_confidence"),
        "ok_count": ti.get("ok_count"),
        "failed_count": ti.get("failed_count")
    }

    # WHOIS / RDAP
    rdap = infra.get("rdap", {}) or {}
    org = infra.get("organization", {}) or {}
    snapshot["whois"] = {
        "org": org.get("name"),
        "country": org.get("country"),
        "abuse_email": org.get("abuse_email"),
        "created": rdap.get("created"),
        "updated": rdap.get("updated")
    }

    return snapshot


def snapshot_current_state(target: str,
                           report: Dict[str, Any],
                           config: Dict[str, Any],
                           db_path: str = "reconip.db") -> None:
    """
    Store a compact snapshot of the current report for future comparison.
    Only fields that are stable and comparable are stored.
    """
    snapshot = _extract_snapshot_fields(report)
    with _get_sqlite_lock():
        with sqlite3.connect(db_path, timeout=30) as conn:
            try:
                conn.execute("PRAGMA journal_mode=WAL")
            except Exception:
                pass
            conn.execute(
                "INSERT INTO snapshots (target, timestamp, data) VALUES (?, ?, ?)",
                (
                    target,
                    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    json.dumps(snapshot, sort_keys=True)
                )
            )
            conn.commit()


def load_previous_snapshot(target: str,
                           db_path: str = "reconip.db") -> Optional[Dict[str, Any]]:
    """
    Return the most recent previous snapshot for the target,
    or None if no previous snapshot exists.
    """
    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            "SELECT timestamp, data FROM snapshots "
            "WHERE target = ? ORDER BY id DESC LIMIT 2",
            (target,)
        )
        rows = cursor.fetchall()

    if len(rows) < 2:
        # Only current snapshot exists (or none)
        return None

    # rows[0] is the current (just inserted) snapshot
    # rows[1] is the previous one
    timestamp, data = rows[1]
    try:
        parsed = json.loads(data)
        parsed["_timestamp"] = timestamp
        return parsed
    except Exception:
        return None


def _compare_field(field: str, current: Any, previous: Any) -> Dict[str, Any]:
    """
    Compare a single field and return a structured diff.
    Handles dicts, lists, and scalars.
    """
    result: Dict[str, Any] = {
        "field": field,
        "change_type": "UNCHANGED",
        "changes": []
    }

    # Both missing
    if current is None and previous is None:
        return result

    # Added (previous missing)
    if previous is None and current is not None:
        result["change_type"] = "ADDED"
        result["changes"].append({
            "key": field,
            "old": None,
            "new": current
        })
        return result

    # Removed (current missing)
    if current is None and previous is not None:
        result["change_type"] = "REMOVED"
        result["changes"].append({
            "key": field,
            "old": previous,
            "new": None
        })
        return result

    # Dict comparison
    if isinstance(current, dict) and isinstance(previous, dict):
        for key in sorted(set(current.keys()) | set(previous.keys())):
            cur_val = current.get(key)
            prev_val = previous.get(key)
            if cur_val != prev_val:
                result["changes"].append({
                    "key": f"{field}.{key}",
                    "old": prev_val,
                    "new": cur_val
                })
        if result["changes"]:
            result["change_type"] = "MODIFIED"
        return result

    # List comparison
    if isinstance(current, list) and isinstance(previous, list):
        cur_set = set(map(str, current))
        prev_set = set(map(str, previous))
        added = sorted(cur_set - prev_set)
        removed = sorted(prev_set - cur_set)
        if added:
            result["changes"].append({"key": f"{field}.added", "old": [], "new": added})
        if removed:
            result["changes"].append({"key": f"{field}.removed", "old": removed, "new": []})
        if result["changes"]:
            result["change_type"] = "MODIFIED"
        return result

    # Scalar comparison
    if current != previous:
        result["change_type"] = "MODIFIED"
        result["changes"].append({
            "key": field,
            "old": previous,
            "new": current
        })
    return result


def historical_compare(current: Dict[str, Any],
                       previous: Dict[str, Any],
                       config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare current and previous snapshots field by field.
    Returns a structured comparison dict.
    """
    history_cfg = (config or {}).get("history", {}) if isinstance(config, dict) else {}
    compare_fields = history_cfg.get("compare_fields",
                                     ["dns", "asn", "prefix", "certificate",
                                      "whois", "threat", "domains"])

    comparison: Dict[str, Any] = {
        "previous_timestamp": previous.get("_timestamp"),
        "current_timestamp": current.get("_timestamp"),
        "fields": {}
    }

    for field in compare_fields:
        cur = current.get(field)
        prev = previous.get(field)
        comparison["fields"][field] = _compare_field(field, cur, prev)

    return comparison


def _default_severity_map() -> Dict[str, str]:
    return {
        "certificate.fingerprint_sha256": "critical",
        "certificate.issuer_cn": "high",
        "asn.asn": "critical",
        "asn.asn_name": "moderate",
        "prefix.cidr": "high",
        "prefix.rir": "moderate",
        "dns.NS": "high",
        "dns.MX": "moderate",
        "dns.A": "moderate",
        "dns.AAAA": "moderate",
        "dns.TXT": "low",
        "dns.CAA": "low",
        "whois.abuse_email": "critical",
        "whois.org": "moderate",
        "whois.country": "moderate",
        "threat.observed_threat_score": "high",
        "threat.threat_confidence": "high",
        "domains": "low"
    }


def _classify_change_severity(key: str, change: Dict[str, Any],
                              severity_map: Dict[str, str]) -> str:
    """
    Return the severity for a given change.
    Falls back to 'informational' if not mapped.
    Special handling for threat score deltas.
    """
    # Exact match
    if key in severity_map:
        base = severity_map[key]
        # Escalate threat score changes based on delta
        if key == "threat.observed_threat_score":
            try:
                old = float(change.get("old") or 0)
                new = float(change.get("new") or 0)
                delta = abs(new - old)
                if delta >= 50:
                    return "critical"
                if delta >= 20:
                    return "high"
                if delta >= 10:
                    return "moderate"
                return "low"
            except Exception:
                return base
        return base

    # Prefix match (e.g., "dns.A.added")
    for mapped_key, sev in (severity_map or {}).items():
        if key.startswith(mapped_key + "."):
            return sev

    return "informational"


def change_detection(comparison: Dict[str, Any],
                     config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Assign severity to each change and produce a prioritized list.
    """
    history_cfg = (config or {}).get("history", {}) if isinstance(config, dict) else {}
    severity_map = history_cfg.get("severity_map", _default_severity_map())
    if not isinstance(severity_map, dict):
        severity_map = _default_severity_map()
    max_changes = history_cfg.get("max_changes_in_report", 100)
    try:
        max_changes = int(max_changes)
    except Exception:
        max_changes = 100

    changes = []
    for field, diff in (comparison.get("fields", {}) or {}).items():
        for change in (diff.get("changes", []) or []):
            key = change.get("key", field)
            severity = _classify_change_severity(key, change, severity_map)
            changes.append({
                "field": field,
                "key": key,
                "old": change.get("old"),
                "new": change.get("new"),
                "change_type": diff.get("change_type"),
                "severity": severity
            })

    # Sort by severity
    order = {"critical": 0, "high": 1, "moderate": 2, "low": 3, "informational": 4}
    changes.sort(key=lambda c: order.get(c["severity"], 99))

    changes = changes[:max_changes] if max_changes and max_changes > 0 else changes

    return {
        "total_changes": len(changes),
        "by_severity": {
            "critical": len([c for c in changes if c["severity"] == "critical"]),
            "high": len([c for c in changes if c["severity"] == "high"]),
            "moderate": len([c for c in changes if c["severity"] == "moderate"]),
            "low": len([c for c in changes if c["severity"] == "low"]),
            "informational": len([c for c in changes if c["severity"] == "informational"])
        },
        "changes": changes,
        "previous_timestamp": comparison.get("previous_timestamp"),
        "current_timestamp": comparison.get("current_timestamp")
    }


def historical_intelligence(target: str,
                            current_report: Dict[str, Any],
                            config: Dict[str, Any],
                            db_path: str = "reconip.db") -> Dict[str, Any]:
    """
    Full historical intelligence pipeline.
    """
    config = config or {}
    history_cfg = config.get("history", {}) if isinstance(config, dict) else {}
    if not history_cfg.get("enabled", True):
        return {"enabled": False}

    db_path = history_cfg.get("db_path", db_path) or db_path

    # Step 1: Ensure schema
    init_snapshot_schema(db_path)

    # Step 2: Store current snapshot
    snapshot_current_state(target, current_report, config, db_path)

    # Step 3: Load previous snapshot
    previous = load_previous_snapshot(target, db_path)

    if previous is None:
        return {
            "enabled": True,
            "status": "FIRST_OBSERVATION",
            "message": "No previous snapshot found. Baseline established.",
            "previous_timestamp": None,
            "current_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "changes": [],
            "total_changes": 0
        }

    # Step 4: Current snapshot
    current = _extract_snapshot_fields(current_report)
    current["_timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Step 5: Compare
    comparison = historical_compare(current, previous, config)

    # Step 6: Detect changes
    detection = change_detection(comparison, config)

    return {
        "enabled": True,
        "status": "COMPARED",
        "previous_timestamp": previous.get("_timestamp"),
        "current_timestamp": current.get("_timestamp"),
        "comparison": comparison,
        "detection": detection
    }

# ============================================================
#  ATTACK SURFACE INTELLIGENCE — v37 (Stage 11)
#  Passive inventory of exposed services. OPEN != VULNERABLE.
#  No active scanning unless explicitly authorized in config.
#  No exploitation. This stage inventories, it does not attack.
# ============================================================
# Common port -> service name mapping (static, no scanning)
KNOWN_PORTS: Dict[int, Dict[str, Any]] = {
    21:   {"service": "ftp",      "protocol": "tcp", "risk_class": "high",   "sensitive": True},
    22:   {"service": "ssh",      "protocol": "tcp", "risk_class": "moderate", "sensitive": True},
    23:   {"service": "telnet",   "protocol": "tcp", "risk_class": "critical", "sensitive": True},
    25:   {"service": "smtp",     "protocol": "tcp", "risk_class": "moderate", "sensitive": False},
    53:   {"service": "dns",      "protocol": "tcp/udp", "risk_class": "low", "sensitive": False},
    80:   {"service": "http",     "protocol": "tcp", "risk_class": "low",    "sensitive": False},
    110:  {"service": "pop3",     "protocol": "tcp", "risk_class": "moderate", "sensitive": False},
    143:  {"service": "imap",     "protocol": "tcp", "risk_class": "moderate", "sensitive": False},
    443:  {"service": "https",    "protocol": "tcp", "risk_class": "low",    "sensitive": False},
    445:  {"service": "smb",      "protocol": "tcp", "risk_class": "high",   "sensitive": True},
    993:  {"service": "imaps",    "protocol": "tcp", "risk_class": "low",    "sensitive": False},
    995:  {"service": "pop3s",    "protocol": "tcp", "risk_class": "low",    "sensitive": False},
    1433: {"service": "mssql",    "protocol": "tcp", "risk_class": "high",   "sensitive": True},
    1521: {"service": "oracle",   "protocol": "tcp", "risk_class": "high",   "sensitive": True},
    3306: {"service": "mysql",    "protocol": "tcp", "risk_class": "high",   "sensitive": True},
    3389: {"service": "rdp",      "protocol": "tcp", "risk_class": "critical","sensitive": True},
    5432: {"service": "postgres", "protocol": "tcp", "risk_class": "high",   "sensitive": True},
    5900: {"service": "vnc",      "protocol": "tcp", "risk_class": "critical","sensitive": True},
    6379: {"service": "redis",    "protocol": "tcp", "risk_class": "high",   "sensitive": True},
    8080: {"service": "http-alt", "protocol": "tcp", "risk_class": "low",    "sensitive": False},
    8443: {"service": "https-alt","protocol": "tcp", "risk_class": "low",    "sensitive": False},
    27017:{"service": "mongodb",  "protocol": "tcp", "risk_class": "high",   "sensitive": True},
}


def _collect_passive_services(target: str,
                              report: Dict[str, Any],
                              config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Collect passive service information from existing report data.

    Sources:
      - TLS handshake (port 443 confirmed)
      - DNS (port 53 for DNS servers)
      - MX/NS context
      - Any imported scan results (from config or prior authorized scans)

    NO active scanning is performed here.
    """
    services: List[Dict[str, Any]] = []

    # ---- TLS handshake confirms 443/tcp ----
    cert_intel = report.get("certificate_intelligence", {}) or {}
    live = cert_intel.get("live_certificate") or {}
    if isinstance(live, dict) and live and live.get("source") == "live":
        services.append({
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "service": "https",
            "evidence": "TLS handshake succeeded",
            "source": "live_tls",
            "confidence": 1.0
        })

    # ---- DNS context: PTR target means DNS service ----
    dns = report.get("dns_intelligence", {}) or {}
    dns_analysis = dns.get("analysis", {}) or {}
    record_types = dns_analysis.get("record_types_present", []) or []
    if "PTR" in record_types and "SOA" in record_types:
        services.append({
            "port": 53,
            "protocol": "tcp/udp",
            "state": "open",
            "service": "dns",
            "evidence": "PTR + SOA records indicate authoritative DNS",
            "source": "dns_context",
            "confidence": 0.9
        })

    # ---- Imported passive scan results ----
    as_cfg = (config or {}).get("attack_surface", {}) if isinstance(config, dict) else {}
    imported = as_cfg.get("imported_services", []) or []
    for item in imported:
        if not isinstance(item, dict):
            continue
        if item.get("target") == target or item.get("target") == "*":
            services.append({
                "port": item.get("port"),
                "protocol": item.get("protocol", "tcp"),
                "state": item.get("state", "open"),
                "service": item.get("service"),
                "evidence": item.get("evidence", "imported"),
                "source": item.get("source", "imported"),
                "confidence": item.get("confidence", 0.8)
            })

    return services


def _collect_authorized_scan_services(target: str,
                                      config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Perform an authorized active scan ONLY if explicitly enabled in config.

    Placeholder: does NOT perform scanning by default. Actual scanning is
    out of scope for this stage and requires explicit authorization,
    legal review, and a dedicated stage.
    """
    as_cfg = (config or {}).get("attack_surface", {}) if isinstance(config, dict) else {}
    if not as_cfg.get("port_scan", False):
        return []

    # Authorization gate
    if not as_cfg.get("authorized", False):
        return []

    allowlist = as_cfg.get("authorized_targets", []) or []
    if target not in allowlist and "*" not in allowlist:
        return []

    # No active scanning implemented in this stage.
    # Return empty to avoid accidental active behavior.
    return []


def service_inventory(services: List[Dict[str, Any]],
                      config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize and enrich a list of raw services into a structured inventory.
    """
    as_cfg = (config or {}).get("attack_surface", {}) if isinstance(config, dict) else {}
    include_sensitive = as_cfg.get("include_sensitive", True)

    inventory: List[Dict[str, Any]] = []
    by_port: Dict[str, int] = defaultdict(int)
    by_service: Dict[str, int] = defaultdict(int)
    sensitive_ports: List[Dict[str, Any]] = []

    for svc in services or []:
        if not isinstance(svc, dict):
            continue
        port = svc.get("port")
        if port is None:
            continue
        try:
            port = int(port)
        except Exception:
            continue

        known = KNOWN_PORTS.get(port, {})
        entry = {
            "port": port,
            "protocol": svc.get("protocol") or known.get("protocol", "tcp"),
            "state": svc.get("state", "open"),
            "service": svc.get("service") or known.get("service", "unknown"),
            "risk_class": known.get("risk_class", "unknown"),
            "sensitive": known.get("sensitive", False),
            "evidence": svc.get("evidence", ""),
            "source": svc.get("source", "unknown"),
            "confidence": svc.get("confidence", 0.5)
        }
        inventory.append(entry)

        by_port[entry["protocol"]] += 1
        by_service[entry["service"]] += 1

        if entry["sensitive"]:
            sensitive_ports.append(entry)

    # Deduplicate by (port, protocol)
    seen = set()
    deduped = []
    for e in inventory:
        key = (e["port"], e["protocol"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(e)

    # Sort by port
    deduped.sort(key=lambda x: x["port"])

    return {
        "services": deduped,
        "service_count": len(deduped),
        "sensitive_count": len(sensitive_ports),
        "sensitive_services": sensitive_ports if include_sensitive else [],
        "by_protocol": dict(by_port),
        "by_service": dict(by_service),
        "ports": sorted({e["port"] for e in deduped})
    }


def _is_private_ip(ip: str) -> bool:
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def _classify_exposure(inventory: Dict[str, Any],
                       report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classify exposure: external vs internal, sensitive vs non-sensitive.
    For now, everything on an internet-routable IP is considered external.
    """
    external = []
    internal = []

    # For now, treat all as external unless IP is RFC1918
    ip = (report.get("infrastructure_intelligence", {}) or {}).get("ip", "") or ""
    is_private = _is_private_ip(ip)

    for svc in inventory.get("services", []) or []:
        if is_private:
            internal.append(svc)
        else:
            external.append(svc)

    return {
        "external_count": len(external),
        "internal_count": len(internal),
        "external_services": external,
        "internal_services": internal,
        "classification": "internal" if is_private else "external"
    }


def _attack_surface_anomalies(inventory: Dict[str, Any],
                              report: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    asn_type = ((report.get("infrastructure_intelligence", {}) or {}).get("asn", {}) or {}).get("type", "unknown")

    for svc in inventory.get("services", []) or []:
        # Sensitive administrative ports
        if svc.get("sensitive") and svc.get("state") == "open":
            anomalies.append({
                "type": "sensitive_service_exposed",
                "severity": "high" if svc.get("risk_class") == "critical" else "moderate",
                "message": f"Sensitive service '{svc.get('service')}' on port {svc.get('port')}/{svc.get('protocol')} is exposed.",
                "port": svc.get("port"),
                "service": svc.get("service")
            })

        # Unexpected DNS service on non-DNS ASN
        if svc.get("service") == "dns" and asn_type not in ("hosting", "isp"):
            anomalies.append({
                "type": "unexpected_dns_service",
                "severity": "low",
                "message": f"DNS service on port {svc.get('port')} for ASN type '{asn_type}'.",
                "port": svc.get("port")
            })

        # Telnet is legacy and insecure
        if svc.get("service") == "telnet":
            anomalies.append({
                "type": "legacy_service",
                "severity": "high",
                "message": f"Legacy service 'telnet' detected on port {svc.get('port')}.",
                "port": svc.get("port")
            })

        # Cleartext protocols on internet-facing services
        if svc.get("service") in ("ftp", "http", "pop3", "imap", "smtp") and svc.get("state") == "open":
            anomalies.append({
                "type": "cleartext_service",
                "severity": "low",
                "message": f"Cleartext service '{svc.get('service')}' on port {svc.get('port')}.",
                "port": svc.get("port")
            })

    return anomalies


def attack_surface(target: str,
                   report: Dict[str, Any],
                   config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Full attack surface intelligence pipeline.

    Strict rules:
      - Passive by default.
      - No scanning unless explicitly authorized.
      - OPEN != VULNERABLE.
      - No exploitation.
    """
    as_cfg = (config or {}).get("attack_surface", {}) if isinstance(config, dict) else {}
    if not as_cfg.get("enabled", True):
        return {"enabled": False}

    # Step 1: Passive collection
    passive = _collect_passive_services(target, report, config)

    # Step 2: Authorized active scan (disabled by default)
    active = _collect_authorized_scan_services(target, config)

    # Step 3: Merge
    all_services = (passive or []) + (active or [])

    # Step 4: Inventory
    inventory = service_inventory(all_services, config)

    # Step 5: Anomalies
    anomalies = _attack_surface_anomalies(inventory, report)

    # Step 6: Exposure classification
    exposure = _classify_exposure(inventory, report)

    # Step 7: Notes
    notes = [
        "OPEN \u2260 VULNERABLE. An open port is exposure, not a weakness.",
        "A detected service is a fingerprint, not a confirmed vulnerability.",
        "No exploitation is performed in this stage.",
        "Active scanning is disabled by default and requires explicit authorization.",
        "All services listed here must be validated before drawing security conclusions."
    ]

    return {
        "enabled": True,
        "services": inventory["services"],
        "service_count": inventory["service_count"],
        "sensitive_services": inventory["sensitive_services"],
        "sensitive_count": inventory["sensitive_count"],
        "by_protocol": inventory["by_protocol"],
        "by_service": inventory["by_service"],
        "ports": inventory["ports"],
        "exposure": exposure,
        "anomalies": anomalies,
        "notes": notes,
        "summary": {
            "total_services": inventory["service_count"],
            "sensitive_services": inventory["sensitive_count"],
            "anomalies": len(anomalies),
            "scan_mode": "active" if active else "passive"
        }
    }

# ============================================================
#  TECHNOLOGY FINGERPRINTING — v38 (Stage 12)
#  Passive by default. A banner is a hint, not a fact.
#  Never guess a version: insufficient evidence -> UNKNOWN.
# ============================================================
# HTTP Server header -> product + optional version
HTTP_SERVER_SIGNATURES: List[Dict[str, Any]] = [
    {"pattern": r"nginx/?([\d.]+)?",       "product": "nginx",     "class": "web_server", "confidence": 0.95},
    {"pattern": r"Apache/?([\d.]+)?",      "product": "apache",    "class": "web_server", "confidence": 0.95},
    {"pattern": r"Caddy",                  "product": "caddy",     "class": "web_server", "confidence": 0.90},
    {"pattern": r"Microsoft-IIS/?([\d.]+)?", "product": "iis",     "class": "web_server", "confidence": 0.95},
    {"pattern": r"cloudflare",             "product": "cloudflare","class": "cdn",        "confidence": 0.90},
    {"pattern": r"LiteSpeed",              "product": "litespeed", "class": "web_server", "confidence": 0.90},
    {"pattern": r"openresty/?([\d.]+)?",   "product": "openresty", "class": "web_server", "confidence": 0.90},
    {"pattern": r"gunicorn/?([\d.]+)?",    "product": "gunicorn",  "class": "app_server", "confidence": 0.85},
    {"pattern": r"uvicorn",                "product": "uvicorn",   "class": "app_server", "confidence": 0.85},
    {"pattern": r"Werkzeug/?([\d.]+)?",    "product": "werkzeug",  "class": "app_server", "confidence": 0.85},
    {"pattern": r"Kestrel",                "product": "kestrel",   "class": "app_server", "confidence": 0.85},
]

# TLS extension / cipher hints
TLS_SIGNATURES: List[Dict[str, Any]] = [
    {"pattern": r"OpenSSL", "product": "openssl", "class": "tls_stack", "confidence": 0.75},
    {"pattern": r"BoringSSL", "product": "boringssl", "class": "tls_stack", "confidence": 0.80},
    {"pattern": r"Go", "product": "go_tls", "class": "tls_stack", "confidence": 0.70},
]

# SSH banner
SSH_SIGNATURES: List[Dict[str, Any]] = [
    {"pattern": r"OpenSSH[_ ]([\d.p]+)", "product": "openssh", "class": "ssh_server", "confidence": 0.95},
    {"pattern": r"dropbear[_ ]?([\d.]+)?", "product": "dropbear", "class": "ssh_server", "confidence": 0.90},
    {"pattern": r"libssh[_ ]?([\d.]+)?", "product": "libssh", "class": "ssh_server", "confidence": 0.85},
]

# DNS software hints (from version.bind / behavior — passive only)
DNS_SIGNATURES: List[Dict[str, Any]] = [
    {"pattern": r"BIND ([\d.]+)", "product": "bind", "class": "dns_server", "confidence": 0.95},
    {"pattern": r"PowerDNS", "product": "powerdns", "class": "dns_server", "confidence": 0.90},
    {"pattern": r"Knot", "product": "knot", "class": "dns_server", "confidence": 0.90},
    {"pattern": r"CoreDNS", "product": "coredns", "class": "dns_server", "confidence": 0.90},
    {"pattern": r"Unbound", "product": "unbound", "class": "dns_server", "confidence": 0.90},
]

# SMTP banner
SMTP_SIGNATURES: List[Dict[str, Any]] = [
    {"pattern": r"Postfix", "product": "postfix", "class": "mail_server", "confidence": 0.90},
    {"pattern": r"Exim ([\d.]+)", "product": "exim", "class": "mail_server", "confidence": 0.90},
    {"pattern": r"Sendmail", "product": "sendmail", "class": "mail_server", "confidence": 0.90},
]

# ============================================================
#  VULNERABILITY INTELLIGENCE — v39 (Stage 13)
#  Candidate != Confirmed. Match != Vulnerable.
#  No version + confidence -> no CPE. No range match -> no CVE.
# ============================================================
# Internal product -> (vendor, product) for CPE construction
CPE_PRODUCT_MAP: Dict[str, Tuple[str, str]] = {
    # Web servers
    "nginx":      ("nginx", "nginx"),
    "apache":     ("apache", "http_server"),
    "caddy":      ("caddyserver", "caddy"),
    "iis":        ("microsoft", "internet_information_services"),
    "litespeed":  ("litespeedtech", "litespeed_web_server"),
    "openresty":  ("openresty", "openresty"),
    "gunicorn":   ("gunicorn", "gunicorn"),
    "uvicorn":    ("encode", "uvicorn"),
    "werkzeug":   ("pallets", "werkzeug"),
    "kestrel":    ("microsoft", "kestrel"),

    # TLS stacks
    "openssl":    ("openssl", "openssl"),
    "boringssl":  ("google", "boringssl"),
    "go_tls":     ("golang", "go"),

    # SSH
    "openssh":    ("openbsd", "openssh"),
    "dropbear":   ("dropbear", "dropbear_ssh_server"),
    "libssh":     ("libssh", "libssh"),

    # DNS
    "bind":       ("isc", "bind"),
    "powerdns":   ("powerdns", "authoritative_server"),
    "knot":       ("cz.nic", "knot_dns"),
    "coredns":    ("coredns", "coredns"),
    "unbound":    ("nlnetlabs", "unbound"),

    # Mail
    "postfix":    ("postfix", "postfix"),
    "exim":       ("exim", "exim"),
    "sendmail":   ("sendmail", "sendmail"),

    # CDN
    "cloudflare": ("cloudflare", "cloudflare"),
}

# Minimal offline CVE index (fallback when no NVD API key is configured)
OFFLINE_CVE_INDEX: Dict[str, List[Dict[str, Any]]] = {
    "cpe:2.3:a:nginx:nginx": [
        {
            "cve": "CVE-2024-24989",
            "severity": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "affected_range": "< 1.24.1",
            "description": "NULL pointer dereference in nginx HTTP/3 module.",
            "published": "2024-02-14"
        },
        {
            "cve": "CVE-2023-44487",
            "severity": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "affected_range": ">= 1.25.0, < 1.25.3",
            "description": "HTTP/2 Rapid Reset attack.",
            "published": "2023-10-10"
        }
    ],
    "cpe:2.3:a:apache:http_server": [
        {
            "cve": "CVE-2023-44487",
            "severity": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "affected_range": ">= 2.4.0, < 2.4.58",
            "description": "HTTP/2 Rapid Reset attack.",
            "published": "2023-10-10"
        }
    ],
    "cpe:2.3:a:openssl:openssl": [
        {
            "cve": "CVE-2023-5678",
            "severity": 5.3,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "affected_range": ">= 3.0.0, < 3.0.13",
            "description": "Excessive time spent in DH check.",
            "published": "2023-11-06"
        }
    ],
    "cpe:2.3:a:openbsd:openssh": [
        {
            "cve": "CVE-2023-48795",
            "severity": 5.9,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
            "affected_range": ">= 8.0, < 9.6",
            "description": "Terrapin attack on SSH.",
            "published": "2023-12-18"
        }
    ]
}


def _parse_version(version: str) -> Optional[Tuple[int, ...]]:
    """
    Parse a version string into a tuple of integers for comparison.
    Returns None if the version cannot be parsed.
    """
    if not version:
        return None
    parts = re.split(r"[.\-_]", str(version).strip())
    nums = []
    for p in parts:
        if p.isdigit():
            nums.append(int(p))
        else:
            # Extract leading digits if present (e.g., "1a" -> 1)
            m = re.match(r"(\d+)", p)
            if m:
                nums.append(int(m.group(1)))
            else:
                break
    return tuple(nums) if nums else None


def _version_in_range(version: str, affected_range: str) -> Optional[bool]:
    """
    Check if a version is within an affected range.

    Supported range formats:
      "< 1.24.1"
      "<= 1.24.1"
      "> 1.24.0, < 1.24.1"
      ">= 1.25.0, < 1.25.3"
      "*"
    """
    if not version or not affected_range:
        return None

    v = _parse_version(version)
    if not v:
        return None

    if affected_range.strip() == "*":
        return True

    # Split on comma for compound ranges
    clauses = [c.strip() for c in affected_range.split(",")]
    for clause in clauses:
        m = re.match(r"(<=|>=|<|>|=)\s*([\d.\-_a-zA-Z]+)", clause)
        if not m:
            return None
        op, ref = m.group(1), m.group(2)
        ref_v = _parse_version(ref)
        if not ref_v:
            return None

        # Pad to same length
        max_len = max(len(v), len(ref_v))
        v_p = v + (0,) * (max_len - len(v))
        r_p = ref_v + (0,) * (max_len - len(ref_v))

        if op == "<"  and not (v_p <  r_p): return False
        if op == "<=" and not (v_p <= r_p): return False
        if op == ">"  and not (v_p >  r_p): return False
        if op == ">=" and not (v_p >= r_p): return False
        if op == "="  and not (v_p == r_p): return False

    return True


def technology_to_cpe(technology: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Convert a technology dict (product, version, confidence) into a CPE.

    Rules:
      - Product must be in CPE_PRODUCT_MAP.
      - Version must be present AND confidence must be >= threshold.
      - If version is missing or confidence is low, return None.
    """
    product = ((technology or {}).get("product") or "").lower()
    version = (technology or {}).get("version")
    confidence = (technology or {}).get("confidence", 0.0)
    evidence = (technology or {}).get("evidence", []) or []

    if not product or product not in CPE_PRODUCT_MAP:
        return None

    if not version:
        return None

    vendor, cpe_product = CPE_PRODUCT_MAP[product]
    cpe = f"cpe:2.3:a:{vendor}:{cpe_product}:{version}:*:*:*:*:*:*:*"

    return {
        "cpe": cpe,
        "product": product,
        "vendor": vendor,
        "version": version,
        "confidence": confidence,
        "evidence": evidence
    }


def _extract_cvss(metrics: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in (metrics or {}) and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            return {
                "score": data.get("baseScore"),
                "vector": data.get("vectorString")
            }
    return {"score": None, "vector": None}


def _extract_description(cve: Dict[str, Any]) -> str:
    for desc in (cve or {}).get("descriptions", []) or []:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _extract_affected_range(cve: Dict[str, Any],
                            cpe_entry: Dict[str, Any]) -> str:
    """
    Extract affected range from NVD configurations.
    Falls back to '*' if unknown.
    """
    for config_node in (cve or {}).get("configurations", []) or []:
        if not isinstance(config_node, dict):
            continue
        for node in config_node.get("nodes", []) or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch", []) or []:
                if not isinstance(match, dict):
                    continue
                if match.get("vulnerable"):
                    start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                    end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                    if start and end:
                        return f">= {start}, <= {end}"
                    if end:
                        return f"< {end}"
                    if start:
                        return f">= {start}"
    return "*"


def cpe_to_cve(cpe_entry: Dict[str, Any],
               config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Map a CPE entry to a list of CVEs.

    Uses:
      - NVD API if API key is configured.
      - Offline index otherwise.
    """
    vuln_cfg = (config or {}).get("vulnerability", {}) if isinstance(config, dict) else {}
    nvd_api_key_env = vuln_cfg.get("nvd_api_key_env", "NVD_API_KEY")
    nvd_api_key = os.getenv(nvd_api_key_env)
    timeout = ((config or {}).get("timeouts", {}) or {}).get("http", 10)
    try:
        timeout = int(timeout)
    except Exception:
        timeout = 10

    cpe = (cpe_entry or {}).get("cpe", "")
    version = (cpe_entry or {}).get("version", "")

    # ---- NVD API path ----
    if nvd_api_key and vuln_cfg.get("use_nvd_api", False):
        try:
            # NVD API 2.0: virtualMatchString
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"virtualMatchString": cpe, "resultsPerPage": 50}
            headers = {"apiKey": nvd_api_key}
            resp = requests.get(url, params=params, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for item in data.get("vulnerabilities", []) or []:
                    cve = (item or {}).get("cve", {}) or {}
                    metrics = cve.get("metrics", {}) or {}
                    severity = _extract_cvss(metrics)
                    results.append({
                        "cve": cve.get("id"),
                        "severity": severity.get("score"),
                        "vector": severity.get("vector"),
                        "affected_range": _extract_affected_range(cve, cpe_entry),
                        "description": _extract_description(cve),
                        "published": cve.get("published")
                    })
                return results
        except Exception:
            pass  # fall through to offline

    # ---- Offline fallback ----
    # Match by vendor:product prefix (strip version from CPE)
    cpe_prefix = ":".join(cpe.split(":")[:5])  # cpe:2.3:a:vendor:product
    results = []
    for key, entries in OFFLINE_CVE_INDEX.items():
        if key.startswith(cpe_prefix):
            for entry in entries or []:
                results.append(entry)
    return results


def vulnerability_candidates(report: Dict[str, Any],
                             config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produce vulnerability candidates from technology intelligence.

    Rules:
      - Only technologies with confident versions are considered.
      - Only candidates are produced — never confirmed vulnerabilities.
      - Every candidate carries evidence and a validation requirement.
    """
    vuln_cfg = (config or {}).get("vulnerability", {}) if isinstance(config, dict) else {}
    if not vuln_cfg.get("enabled", True):
        return {"enabled": False}

    require_validation = vuln_cfg.get("require_validation", True)
    min_tech_confidence = vuln_cfg.get("min_technology_confidence", 0.7)
    try:
        min_tech_confidence = float(min_tech_confidence)
    except Exception:
        min_tech_confidence = 0.7
    max_candidates = vuln_cfg.get("max_candidates", 50)
    try:
        max_candidates = int(max_candidates)
    except Exception:
        max_candidates = 50

    tech_intel = report.get("technology_intelligence", {}) or {}
    technologies = []
    for result in tech_intel.get("results", []) or []:
        if not isinstance(result, dict):
            continue
        for tech in result.get("technology", []) or []:
            if not isinstance(tech, dict):
                continue
            technologies.append({
                "port": result.get("port"),
                "service": result.get("service"),
                "product": tech.get("product"),
                "version": tech.get("version"),
                "confidence": tech.get("confidence"),
                "evidence": tech.get("evidence", []) or []
            })

    candidates: List[Dict[str, Any]] = []
    cpes_built: List[Dict[str, Any]] = []

    for tech in technologies:
        # Gate 1: technology confidence
        try:
            conf_val = float(tech.get("confidence", 0.0) or 0.0)
        except Exception:
            continue
        if conf_val < min_tech_confidence:
            continue

        # Gate 2: version must be present
        if not tech.get("version"):
            continue

        # Step 1: Technology -> CPE
        cpe_entry = technology_to_cpe(tech)
        if not cpe_entry:
            continue
        cpes_built.append(cpe_entry)

        # Step 2: CPE -> CVEs
        cves = cpe_to_cve(cpe_entry, config)
        if not cves:
            continue

        # Step 3: Filter by affected range
        for cve in cves:
            if not isinstance(cve, dict):
                continue
            in_range = _version_in_range(cpe_entry["version"], cve.get("affected_range", "*"))
            if in_range is not True:
                continue

            candidates.append({
                "technology": {
                    "product": tech["product"],
                    "version": tech["version"],
                    "confidence": tech["confidence"]
                },
                "cpe": cpe_entry["cpe"],
                "cve": cve.get("cve"),
                "severity": cve.get("severity"),
                "vector": cve.get("vector"),
                "affected_range": cve.get("affected_range"),
                "description": cve.get("description"),
                "published": cve.get("published"),
                "match_type": "range" if cve.get("affected_range") != "*" else "wildcard",
                "confidence": round(min(float(tech["confidence"]), 0.9), 3),
                "evidence": [
                    f"technology:{tech['product']}@{tech['version']}",
                    f"version_confidence:{tech['confidence']}",
                    f"cpe:{cpe_entry['cpe']}",
                    f"port:{tech['port']}"
                ],
                "status": "CANDIDATE" if not require_validation else "NEEDS_VALIDATION",
                "notes": (
                    "This is a candidate. Validation on the target is required "
                    "before any conclusion can be drawn."
                )
            })

    # Sort by severity desc, then confidence desc
    candidates.sort(key=lambda c: (
        -((c.get("severity") or 0) if isinstance(c.get("severity"), (int, float)) else 0),
        -(c.get("confidence", 0) if isinstance(c.get("confidence"), (int, float)) else 0)
    ))
    candidates = candidates[:max_candidates] if max_candidates and max_candidates > 0 else candidates

    # Summary
    severity_buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for c in candidates:
        s = c.get("severity")
        if s is None:
            severity_buckets["unknown"] += 1
        elif s >= 9.0:
            severity_buckets["critical"] += 1
        elif s >= 7.0:
            severity_buckets["high"] += 1
        elif s >= 4.0:
            severity_buckets["medium"] += 1
        else:
            severity_buckets["low"] += 1

    notes = [
        "A CVE matching a version is a CANDIDATE, not a confirmation.",
        "A candidate is not a vulnerability.",
        "A vulnerability is not an exploit.",
        "An exploit is not an impact.",
        "Validation on the target is required before any conclusion.",
        "No exploitation is performed in this stage."
    ]

    return {
        "enabled": True,
        "candidates": candidates,
        "cpes_built": cpes_built,
        "summary": {
            "technologies_analyzed": len(technologies),
            "cpes_built": len(cpes_built),
            "candidates": len(candidates),
            "by_severity": severity_buckets,
            "require_validation": require_validation,
            "min_technology_confidence": min_tech_confidence
        },
        "notes": notes
    }


def _banner_grab_authorized(ip: str, port: int,
                            protocol: str,
                            config: Dict[str, Any],
                            timeout: int = 5) -> Optional[str]:
    """
    Perform a banner grab ONLY if explicitly authorized.

    Gates:
      - fingerprinting.enabled == true
      - fingerprinting.active_banner_grab == true
      - attack_surface.authorized == true
      - ip in attack_surface.authorized_targets

    Returns the banner string, or None.
    """
    fp_cfg = (config or {}).get("fingerprinting", {}) if isinstance(config, dict) else {}
    as_cfg = (config or {}).get("attack_surface", {}) if isinstance(config, dict) else {}

    if not fp_cfg.get("enabled", True):
        return None
    if not fp_cfg.get("active_banner_grab", False):
        return None
    if not as_cfg.get("authorized", False):
        return None
    if ip not in (as_cfg.get("authorized_targets", []) or []) and "*" not in (as_cfg.get("authorized_targets", []) or []):
        return None

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # For HTTP, send a minimal request
            if str(protocol).lower() in ("http", "https", "http-alt", "https-alt"):
                request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
                sock.sendall(request.encode())
            # For SSH, the server sends the banner first
            try:
                data = sock.recv(4096)
                banner = data.decode("utf-8", errors="replace").strip()
                max_len = fp_cfg.get("max_banner_length", 4096)
                try:
                    max_len = int(max_len)
                except Exception:
                    max_len = 4096
                return banner[:max_len] if banner else None
            except socket.timeout:
                return None
    except Exception:
        return None


def _passive_banner_from_report(service: Dict[str, Any],
                                report: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract passive fingerprint hints from already-collected data.
    No network activity.
    """
    hints: Dict[str, str] = {}

    # TLS handshake may have recorded cipher/ALPN (if available)
    cert_intel = report.get("certificate_intelligence", {}) or {}
    live = cert_intel.get("live_certificate") or {}
    if isinstance(live, dict) and service.get("port") == 443 and live:
        if live.get("issuer_cn"):
            hints["tls_issuer"] = live["issuer_cn"]
        if live.get("signature_algorithm"):
            hints["tls_sig_algo"] = live["signature_algorithm"]
        if live.get("key_type"):
            hints["tls_key_type"] = live["key_type"]

    # DNS context
    dns = report.get("dns_intelligence", {}) or {}
    if service.get("service") == "dns":
        dns_analysis = dns.get("analysis", {}) or {}
        if dns_analysis.get("record_types_present"):
            hints["dns_records"] = ",".join(dns_analysis["record_types_present"])

    return hints


def _match_signatures(text: str, signatures: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Match a string against a list of signature dicts.
    Returns the first match with captured version (if any), or None.
    """
    if not text:
        return None
    for sig in signatures or []:
        m = re.search(sig["pattern"], text, re.IGNORECASE)
        if m:
            version = None
            try:
                if m.groups():
                    version = m.group(1) or None
            except Exception:
                version = None
            return {
                "product": sig["product"],
                "class": sig["class"],
                "version": version,
                "confidence": sig["confidence"],
                "pattern": sig["pattern"]
            }
    return None


def version_confidence(base_confidence: float,
                       version: Optional[str],
                       evidence_sources: List[str]) -> float:
    """
    Adjust confidence based on:
      - Whether a version was extracted
      - Number of independent evidence sources
      - Evidence reliability

    Rules:
      - No version -> confidence reduced by 30%
      - Version from single source -> base confidence
      - Version from multiple sources -> +10% (capped at 1.0)
      - Version from banner only -> -10%
    """
    conf = base_confidence

    if not version:
        conf *= 0.7

    source_count = len(set(evidence_sources or []))
    if source_count >= 2:
        conf = min(1.0, conf + 0.10)
    elif source_count == 1 and "banner" in (evidence_sources or []):
        conf = max(0.0, conf - 0.10)

    return round(max(0.0, min(1.0, conf)), 3)


def fingerprint_technology(service: Dict[str, Any],
                           report: Dict[str, Any],
                           config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fingerprint technology for a single service.

    Returns:
    {
        "port": int,
        "protocol": str,
        "service": str,
        "banner": str | None,
        "technology": [...],
        "status": "OK" | "INSUFFICIENT_EVIDENCE" | "UNKNOWN",
        "notes": [...]
    }
    """
    fp_cfg = (config or {}).get("fingerprinting", {}) if isinstance(config, dict) else {}
    min_confidence = fp_cfg.get("min_confidence", 0.7)
    try:
        min_confidence = float(min_confidence)
    except Exception:
        min_confidence = 0.7
    timeout = ((config or {}).get("timeouts", {}) or {}).get("default", 10)
    try:
        timeout = int(timeout)
    except Exception:
        timeout = 10

    result = {
        "port": service.get("port"),
        "protocol": service.get("protocol"),
        "service": service.get("service"),
        "banner": None,
        "technology": [],
        "status": "UNKNOWN",
        "notes": []
    }

    # ---- Gather evidence ----
    evidence_sources: List[str] = []
    banner = None

    # 1. Passive hints from report
    hints = _passive_banner_from_report(service, report)
    if hints:
        evidence_sources.append("passive_report")

    # 2. Authorized banner grab
    ip = (report.get("infrastructure_intelligence", {}) or {}).get("ip")
    if ip:
        try:
            grabbed = _banner_grab_authorized(ip, service.get("port", 0),
                                              service.get("service", ""),
                                              config, timeout=timeout)
        except Exception:
            grabbed = None
        if grabbed:
            banner = grabbed
            evidence_sources.append("banner")
    result["banner"] = banner

    # ---- Match signatures ----
    svc = (service.get("service") or "").lower()
    candidates: List[Dict[str, Any]] = []

    if svc in ("http", "https", "http-alt", "https-alt"):
        if banner:
            m = _match_signatures(banner, HTTP_SERVER_SIGNATURES)
            if m:
                candidates.append(m)

    if svc in ("ssh",):
        if banner:
            m = _match_signatures(banner, SSH_SIGNATURES)
            if m:
                candidates.append(m)

    if svc in ("dns",):
        # Only match if a version.bind response was captured (not implemented here)
        # For now, no DNS fingerprint without active query
        pass

    if svc in ("smtp",):
        if banner:
            m = _match_signatures(banner, SMTP_SIGNATURES)
            if m:
                candidates.append(m)

    # TLS hints (passive, from certificate)
    if hints.get("tls_issuer"):
        # Issuer alone is not enough for TLS stack; skip false positives
        pass

    # ---- Build technology list ----
    for cand in candidates:
        conf = version_confidence(cand["confidence"], cand.get("version"), evidence_sources)
        if conf < min_confidence:
            continue
        result["technology"].append({
            "product": cand["product"],
            "class": cand["class"],
            "version": cand.get("version"),
            "confidence": conf,
            "evidence": evidence_sources
        })

    # ---- Status ----
    if result["technology"]:
        result["status"] = "OK"
    elif evidence_sources:
        result["status"] = "INSUFFICIENT_EVIDENCE"
        result["notes"].append(
            "Evidence collected but no technology signature matched. Version unknown."
        )
    else:
        result["status"] = "UNKNOWN"
        result["notes"].append(
            "No banner or passive hints available. Cannot fingerprint technology."
        )

    # ---- Explicit rule ----
    if not result["technology"]:
        result["notes"].append(
            "No version claimed. Guessing is disabled by design."
        )

    return result


def technology_intelligence(report: Dict[str, Any],
                            config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Full technology fingerprinting pipeline across all attack surface services.
    """
    fp_cfg = (config or {}).get("fingerprinting", {}) if isinstance(config, dict) else {}
    if not fp_cfg.get("enabled", True):
        return {"enabled": False}

    as_intel = report.get("attack_surface_intelligence", {}) or {}
    services = as_intel.get("services", []) or []

    results: List[Dict[str, Any]] = []
    by_class: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for svc in services:
        fp = fingerprint_technology(svc, report, config)
        results.append(fp)
        for tech in fp.get("technology", []) or []:
            by_class[tech["class"]].append({
                "port": fp["port"],
                "product": tech["product"],
                "version": tech["version"],
                "confidence": tech["confidence"]
            })

    # Summary
    total_technologies = sum(len(r.get("technology", []) or []) for r in results)
    ok_count = len([r for r in results if r["status"] == "OK"])
    insufficient = len([r for r in results if r["status"] == "INSUFFICIENT_EVIDENCE"])
    unknown = len([r for r in results if r["status"] == "UNKNOWN"])

    notes = [
        "A banner is a hint, not a fact.",
        "A version is a claim, not a certainty.",
        "If evidence is insufficient, the tool returns UNKNOWN — it does not guess.",
        "Confidence reflects evidence quality, not threat level."
    ]

    return {
        "enabled": True,
        "results": results,
        "by_class": dict(by_class),
        "summary": {
            "services_analyzed": len(services),
            "technologies_identified": total_technologies,
            "ok": ok_count,
            "insufficient_evidence": insufficient,
            "unknown": unknown,
            "min_confidence": fp_cfg.get("min_confidence", 0.7)
        },
        "notes": notes
    }

# ============================================================
#  ANOMALY DETECTION ENGINE — v40 (Stage 14)
#  Deviation from expectation, not a verdict. Evidence, not conclusion.
#  No fabricated anomalies: zero is reported only after real checks run.
# ============================================================
ANOMALY_SEVERITIES = ["INFORMATIONAL", "LOW", "MODERATE", "HIGH"]
ANOMALY_SEVERITY_ORDER = {s: i for i, s in enumerate(ANOMALY_SEVERITIES)}


def _anomaly(category: str,
             subtype: str,
             severity: str,
             message: str,
             evidence: Optional[List[Any]] = None,
             source_sections: Optional[List[str]] = None,
             confidence: float = 0.5,
             metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Build a structured anomaly object.
    """
    if severity not in ANOMALY_SEVERITY_ORDER:
        severity = "INFORMATIONAL"

    return {
        "category": category,
        "subtype": subtype,
        "severity": severity,
        "message": message,
        "evidence": evidence or [],
        "source_sections": source_sections or [],
        "confidence": round(max(0.0, min(1.0, confidence)), 3),
        "metadata": metadata or {}
    }


def classify_anomaly(category: str,
                     subtype: str,
                     context: Optional[Dict[str, Any]] = None) -> str:
    """
    Return a canonical severity for a given anomaly category + subtype.
    Context can override the default severity when needed.
    """
    context = context or {}

    # Default severity map
    severity_map: Dict[Tuple[str, str], str] = {
        # DNS
        ("dns", "ns_soa_mismatch"):        "MODERATE",
        ("dns", "a_ptr_mismatch"):         "MODERATE",
        ("dns", "cname_loop"):             "HIGH",
        ("dns", "missing_spf"):            "LOW",
        ("dns", "missing_dmarc"):          "LOW",
        ("dns", "duplicate_records"):      "INFORMATIONAL",
        ("dns", "low_ttl"):                "INFORMATIONAL",
        ("dns", "conflicting_records"):    "MODERATE",

        # Certificate
        ("cert", "expired"):               "MODERATE",
        ("cert", "near_expiry"):           "INFORMATIONAL",
        ("cert", "weak_algorithm"):        "HIGH",
        ("cert", "weak_key_size"):         "HIGH",
        ("cert", "self_signed"):           "MODERATE",
        ("cert", "hostname_mismatch"):     "HIGH",
        ("cert", "wildcard_overuse"):      "INFORMATIONAL",
        ("cert", "live_not_in_ct"):        "INFORMATIONAL",
        ("cert", "shared_san_many"):       "INFORMATIONAL",

        # ASN
        ("asn", "type_service_mismatch"):  "MODERATE",
        ("asn", "country_mismatch"):       "MODERATE",
        ("asn", "multiple_asn_claims"):    "MODERATE",
        ("asn", "name_org_mismatch"):      "LOW",

        # History
        ("history", "certificate_change"): "HIGH",
        ("history", "asn_change"):         "HIGH",
        ("history", "ns_change"):          "MODERATE",
        ("history", "abuse_contact_change"): "HIGH",
        ("history", "threat_score_change"): "HIGH",
        ("history", "org_change"):         "MODERATE",
        ("history", "record_added"):       "INFORMATIONAL",
        ("history", "record_removed"):     "LOW",

        # Infrastructure
        ("infra", "shared_cert_unrelated_asn"):   "HIGH",
        ("infra", "shared_ns_unrelated_org"):     "MODERATE",
        ("infra", "unexpected_cdn_origin"):       "MODERATE",
        ("infra", "prefix_overlap"):              "INFORMATIONAL",
        ("infra", "peer_mismatch"):               "LOW",

        # Provider
        ("provider", "score_disagreement"):       "HIGH",
        ("provider", "high_variance"):            "MODERATE",
        ("provider", "single_provider_flag"):     "MODERATE",
        ("provider", "low_coverage"):             "MODERATE",
        ("provider", "failed_providers"):         "LOW",

        # Stale
        ("stale", "evidence_stale"):              "MODERATE",
        ("stale", "provider_stale"):              "MODERATE",
        ("stale", "snapshot_stale"):              "LOW",
        ("stale", "threat_data_stale"):           "HIGH",
    }

    default = severity_map.get((category, subtype), "INFORMATIONAL")

    # Context overrides
    if context.get("force_severity") in ANOMALY_SEVERITY_ORDER:
        return context["force_severity"]

    # Escalate provider disagreement based on magnitude
    if category == "provider" and subtype == "score_disagreement":
        try:
            delta = float(context.get("delta", 0))
            if delta >= 50:
                return "HIGH"
            if delta >= 20:
                return "MODERATE"
            return "LOW"
        except Exception:
            pass

    # Escalate historical threat score change
    if category == "history" and subtype == "threat_score_change":
        try:
            delta = float(context.get("delta", 0))
            if delta >= 50:
                return "HIGH"
            if delta >= 20:
                return "MODERATE"
            return "LOW"
        except Exception:
            pass

    return default


def _check_dns(report: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    dns = report.get("dns_intelligence", {}) or {}
    analysis = dns.get("analysis", {}) or {}
    if not analysis:
        return anomalies

    # NS vs SOA mismatch
    nsoa = (analysis.get("consistency", {}) or {}).get("ns_vs_soa")
    if isinstance(nsoa, dict) and nsoa.get("consistent") is False:
        anomalies.append(_anomaly(
            category="dns",
            subtype="ns_soa_mismatch",
            severity=classify_anomaly("dns", "ns_soa_mismatch"),
            message="SOA primary is not listed in NS records.",
            evidence=[nsoa],
            source_sections=["dns_intelligence"],
            confidence=0.85
        ))

    # A vs PTR mismatch
    ap = (analysis.get("consistency", {}) or {}).get("a_vs_ptr")
    if isinstance(ap, dict) and ap.get("consistent") is False:
        anomalies.append(_anomaly(
            category="dns",
            subtype="a_ptr_mismatch",
            severity=classify_anomaly("dns", "a_ptr_mismatch"),
            message="A record and PTR record disagree.",
            evidence=[ap],
            source_sections=["dns_intelligence"],
            confidence=0.8
        ))

    # CNAME loops
    loops = (analysis.get("relationships", {}) or {}).get("cname_loops", []) or []
    if loops:
        anomalies.append(_anomaly(
            category="dns",
            subtype="cname_loop",
            severity=classify_anomaly("dns", "cname_loop"),
            message=f"{len(loops)} CNAME loop(s) detected.",
            evidence=loops,
            source_sections=["dns_intelligence"],
            confidence=0.95
        ))

    # Missing SPF
    security = analysis.get("security", {}) or {}
    if security.get("spf_present") is False:
        anomalies.append(_anomaly(
            category="dns",
            subtype="missing_spf",
            severity=classify_anomaly("dns", "missing_spf"),
            message="No SPF record found.",
            evidence=[],
            source_sections=["dns_intelligence"],
            confidence=0.9
        ))

    # Missing DMARC
    if security.get("dmarc_present") is False:
        anomalies.append(_anomaly(
            category="dns",
            subtype="missing_dmarc",
            severity=classify_anomaly("dns", "missing_dmarc"),
            message="No DMARC record found.",
            evidence=[],
            source_sections=["dns_intelligence"],
            confidence=0.9
        ))

    # Duplicate records
    dupes = (analysis.get("consistency", {}) or {}).get("duplicate_records", []) or []
    if dupes:
        anomalies.append(_anomaly(
            category="dns",
            subtype="duplicate_records",
            severity=classify_anomaly("dns", "duplicate_records"),
            message=f"{len(dupes)} duplicate DNS record group(s) found.",
            evidence=dupes,
            source_sections=["dns_intelligence"],
            confidence=0.95
        ))

    # Low TTL
    ttl = analysis.get("ttl", {}) or {}
    if ttl.get("low_ttl_warning"):
        anomalies.append(_anomaly(
            category="dns",
            subtype="low_ttl",
            severity=classify_anomaly("dns", "low_ttl"),
            message=f"{ttl.get('low_ttl_count', 0)} record(s) with TTL below threshold.",
            evidence=[ttl],
            source_sections=["dns_intelligence"],
            confidence=0.9
        ))

    return anomalies


def _check_cert(report: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    cert = report.get("certificate_intelligence", {}) or {}
    if not cert:
        return anomalies

    # Live certificate checks
    live = cert.get("live_certificate") or {}
    if isinstance(live, dict) and live and live.get("source") == "live":
        if live.get("expired"):
            anomalies.append(_anomaly(
                category="cert",
                subtype="expired",
                severity=classify_anomaly("cert", "expired"),
                message="Live certificate is expired.",
                evidence=[{
                    "fingerprint": live.get("fingerprint_sha256"),
                    "not_after": live.get("not_after")
                }],
                source_sections=["certificate_intelligence"],
                confidence=0.95
            ))

        if live.get("near_expiry"):
            anomalies.append(_anomaly(
                category="cert",
                subtype="near_expiry",
                severity=classify_anomaly("cert", "near_expiry"),
                message="Live certificate is near expiry.",
                evidence=[{
                    "fingerprint": live.get("fingerprint_sha256"),
                    "not_after": live.get("not_after")
                }],
                source_sections=["certificate_intelligence"],
                confidence=0.9
            ))

        algo = (live.get("signature_algorithm") or "").lower()
        if "sha1" in algo or "md5" in algo:
            anomalies.append(_anomaly(
                category="cert",
                subtype="weak_algorithm",
                severity=classify_anomaly("cert", "weak_algorithm"),
                message=f"Live certificate uses weak algorithm: {algo}.",
                evidence=[{"signature_algorithm": algo}],
                source_sections=["certificate_intelligence"],
                confidence=0.95
            ))

        key_type = live.get("key_type")
        key_size = live.get("key_size") or 0
        try:
            key_size = int(key_size)
        except Exception:
            key_size = 0
        if key_type == "RSA" and key_size and key_size < 2048:
            anomalies.append(_anomaly(
                category="cert",
                subtype="weak_key_size",
                severity=classify_anomaly("cert", "weak_key_size"),
                message=f"Live certificate uses weak RSA key size: {key_size}.",
                evidence=[{"key_type": key_type, "key_size": key_size}],
                source_sections=["certificate_intelligence"],
                confidence=0.95
            ))

    # Relationships
    relationships = cert.get("relationships", {}) or {}

    if relationships.get("expired_certs"):
        anomalies.append(_anomaly(
            category="cert",
            subtype="expired",
            severity=classify_anomaly("cert", "expired"),
            message=f"{len(relationships['expired_certs'])} expired certificate(s) found.",
            evidence=relationships["expired_certs"],
            source_sections=["certificate_intelligence"],
            confidence=0.9
        ))

    if relationships.get("weak_algo_certs"):
        anomalies.append(_anomaly(
            category="cert",
            subtype="weak_algorithm",
            severity=classify_anomaly("cert", "weak_algorithm"),
            message=f"{len(relationships['weak_algo_certs'])} certificate(s) use weak algorithms.",
            evidence=relationships["weak_algo_certs"],
            source_sections=["certificate_intelligence"],
            confidence=0.9
        ))

    wildcards = relationships.get("wildcard_certs", []) or []
    if len(wildcards) > 5:
        anomalies.append(_anomaly(
            category="cert",
            subtype="wildcard_overuse",
            severity=classify_anomaly("cert", "wildcard_overuse"),
            message=f"{len(wildcards)} wildcard certificates detected.",
            evidence=wildcards,
            source_sections=["certificate_intelligence"],
            confidence=0.85
        ))

    # Live cert not in CT
    correlation = cert.get("correlation", {}) or {}
    if correlation.get("private_certificate"):
        anomalies.append(_anomaly(
            category="cert",
            subtype="live_not_in_ct",
            severity=classify_anomaly("cert", "live_not_in_ct"),
            message="Live certificate was not found in CT logs (private or internal).",
            evidence=[{"fingerprint": correlation.get("live_fingerprint")}],
            source_sections=["certificate_intelligence"],
            confidence=0.8
        ))

    # Shared SAN across many certs
    for entry in relationships.get("by_shared_san", []) or []:
        if isinstance(entry, dict) and len(entry.get("certificates", []) or []) > 3:
            anomalies.append(_anomaly(
                category="cert",
                subtype="shared_san_many",
                severity=classify_anomaly("cert", "shared_san_many"),
                message=f"SAN '{entry.get('san')}' appears in {len(entry['certificates'])} certificates.",
                evidence=[entry],
                source_sections=["certificate_intelligence"],
                confidence=0.85
            ))

    return anomalies


def _check_asn(report: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    infra = report.get("infrastructure_intelligence", {}) or {}
    if not infra:
        return anomalies

    asn = infra.get("asn", {}) or {}
    org = infra.get("organization", {}) or {}
    rdap = infra.get("rdap", {}) or {}
    attack = report.get("attack_surface_intelligence", {}) or {}

    asn_type = asn.get("type", "unknown")

    # ASN type vs service type mismatch
    for svc in attack.get("services", []) or []:
        if not isinstance(svc, dict):
            continue
        service = svc.get("service", "")
        # DNS on non-hosting/non-isp ASN
        if service == "dns" and asn_type not in ("hosting", "isp", "education", "government"):
            anomalies.append(_anomaly(
                category="asn",
                subtype="type_service_mismatch",
                severity=classify_anomaly("asn", "type_service_mismatch"),
                message=f"DNS service on ASN type '{asn_type}'.",
                evidence=[{"port": svc.get("port"), "service": service, "asn_type": asn_type}],
                source_sections=["infrastructure_intelligence", "attack_surface_intelligence"],
                confidence=0.7
            ))
        # Mail on residential ASN
        if service in ("smtp", "imap", "pop3") and asn_type == "isp":
            anomalies.append(_anomaly(
                category="asn",
                subtype="type_service_mismatch",
                severity=classify_anomaly("asn", "type_service_mismatch"),
                message="Mail service on ISP ASN — may be residential mail host.",
                evidence=[{"port": svc.get("port"), "service": service, "asn_type": asn_type}],
                source_sections=["infrastructure_intelligence", "attack_surface_intelligence"],
                confidence=0.6
            ))

    # ASN country vs RDAP/WHOIS country mismatch
    asn_country = (asn.get("country") or "").upper()
    rdap_country = (org.get("country") or rdap.get("country") or "").upper()
    if asn_country and rdap_country and asn_country != rdap_country:
        anomalies.append(_anomaly(
            category="asn",
            subtype="country_mismatch",
            severity=classify_anomaly("asn", "country_mismatch"),
            message=f"ASN country ({asn_country}) differs from RDAP/WHOIS country ({rdap_country}).",
            evidence=[{"asn_country": asn_country, "rdap_country": rdap_country}],
            source_sections=["infrastructure_intelligence"],
            confidence=0.8
        ))

    # ASN name vs org name mismatch (basic)
    asn_name = (asn.get("asn_name") or "").lower()
    org_name = (org.get("name") or "").lower()
    if asn_name and org_name:
        # Simple heuristic: check if any word from org_name appears in asn_name
        words = [w for w in re.split(r"\W+", org_name) if len(w) > 3]
        if words and not any(w in asn_name for w in words):
            anomalies.append(_anomaly(
                category="asn",
                subtype="name_org_mismatch",
                severity=classify_anomaly("asn", "name_org_mismatch"),
                message="ASN name and organization name do not appear related.",
                evidence=[{"asn_name": asn.get("asn_name"), "org_name": org.get("name")}],
                source_sections=["infrastructure_intelligence"],
                confidence=0.6
            ))

    return anomalies


def _history_key_to_subtype(key: str) -> str:
    if "certificate.fingerprint" in key:
        return "certificate_change"
    if key.startswith("asn."):
        return "asn_change"
    if key.startswith("dns.NS"):
        return "ns_change"
    if key.startswith("whois.abuse_email"):
        return "abuse_contact_change"
    if key.startswith("threat."):
        return "threat_score_change"
    if key.startswith("whois.org"):
        return "org_change"
    if ".added" in key:
        return "record_added"
    if ".removed" in key:
        return "record_removed"
    return "unknown"


def _extract_delta(change: Dict[str, Any]) -> Optional[float]:
    try:
        old = float(change.get("old") or 0)
        new = float(change.get("new") or 0)
        return abs(new - old)
    except Exception:
        return None


def _check_history(report: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    history = report.get("historical_intelligence", {}) or {}
    if history.get("status") != "COMPARED":
        return anomalies

    detection = history.get("detection", {}) or {}
    for change in detection.get("changes", []) or []:
        if not isinstance(change, dict):
            continue
        key = change.get("key", "")
        severity = str(change.get("severity", "informational")).upper()
        if severity not in ANOMALY_SEVERITY_ORDER:
            severity = "INFORMATIONAL"

        # Map key -> subtype
        subtype = _history_key_to_subtype(key)

        anomalies.append(_anomaly(
            category="history",
            subtype=subtype,
            severity=severity,
            message=f"Historical change detected: {key}",
            evidence=[{
                "key": key,
                "old": change.get("old"),
                "new": change.get("new"),
                "change_type": change.get("change_type")
            }],
            source_sections=["historical_intelligence"],
            confidence=0.9,
            metadata={"delta": _extract_delta(change)}
        ))

    return anomalies


def _check_infra(report: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    corr = report.get("correlation_intelligence", {}) or {}
    graph = corr.get("graph", {}) or {}

    # Shared certificate across unrelated ASNs
    for entry in (corr.get("shared", {}) or {}).get("shared_certificates", []) or []:
        if not isinstance(entry, dict):
            continue
        shared_by = entry.get("shared_by", []) or []
        if len(shared_by) < 2:
            continue
        # Check if the shared IPs belong to different ASNs
        asns = set()
        for ip_id in shared_by:
            for edge in graph.get("edges", []) or []:
                if isinstance(edge, dict) and edge.get("source") == ip_id and edge.get("type") == "belongs_to_asn":
                    asns.add(edge.get("target"))
        if len(asns) > 1:
            anomalies.append(_anomaly(
                category="infra",
                subtype="shared_cert_unrelated_asn",
                severity=classify_anomaly("infra", "shared_cert_unrelated_asn"),
                message=f"Certificate shared across {len(asns)} different ASNs.",
                evidence=[{"certificate": entry.get("entity"), "asns": sorted(asns), "shared_by": shared_by}],
                source_sections=["correlation_intelligence"],
                confidence=0.8
            ))

    # Shared nameserver across unrelated organizations
    for entry in (corr.get("shared", {}) or {}).get("shared_nameservers", []) or []:
        if not isinstance(entry, dict):
            continue
        shared_by = entry.get("shared_by", []) or []
        if len(shared_by) < 2:
            continue
        orgs = set()
        for ip_id in shared_by:
            for edge in graph.get("edges", []) or []:
                if isinstance(edge, dict) and edge.get("source") == ip_id and edge.get("type") == "belongs_to_asn":
                    asn_id = edge.get("target")
                    for e2 in graph.get("edges", []) or []:
                        if isinstance(e2, dict) and e2.get("source") == asn_id and e2.get("type") == "owned_by":
                            orgs.add(e2.get("target"))
        if len(orgs) > 1:
            anomalies.append(_anomaly(
                category="infra",
                subtype="shared_ns_unrelated_org",
                severity=classify_anomaly("infra", "shared_ns_unrelated_org"),
                message=f"Nameserver shared across {len(orgs)} different organizations.",
                evidence=[{"nameserver": entry.get("entity"), "orgs": sorted(orgs)}],
                source_sections=["correlation_intelligence"],
                confidence=0.75
            ))

    return anomalies


def _check_provider(report: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    ti = report.get("threat_intelligence", {}) or {}
    if not ti:
        return anomalies

    normalized = ti.get("normalized", []) or []
    ok = [r for r in normalized if isinstance(r, dict) and r.get("status") == "OK"]

    # Low coverage
    coverage = ti.get("evidence_coverage", 1.0)
    try:
        coverage = float(coverage)
    except Exception:
        coverage = 1.0
    if coverage < 0.5 and len(normalized) > 0:
        anomalies.append(_anomaly(
            category="provider",
            subtype="low_coverage",
            severity=classify_anomaly("provider", "low_coverage"),
            message=f"Threat intelligence coverage is low: {coverage * 100:.1f}%.",
            evidence=[{"coverage": coverage, "ok_count": len(ok), "total": len(normalized)}],
            source_sections=["threat_intelligence"],
            confidence=0.9
        ))

    # Failed providers
    failed_count = ti.get("failed_count", 0)
    try:
        failed_count = int(failed_count)
    except Exception:
        failed_count = 0
    if failed_count > 0:
        anomalies.append(_anomaly(
            category="provider",
            subtype="failed_providers",
            severity=classify_anomaly("provider", "failed_providers"),
            message=f"{failed_count} provider(s) failed. Absence of data is not absence of threat.",
            evidence=[ti.get("failures", {})],
            source_sections=["threat_intelligence"],
            confidence=0.95
        ))

    # Score disagreement
    if len(ok) >= 2:
        try:
            scores = [float(r.get("threat_score", 0.0) or 0.0) for r in ok]
        except Exception:
            scores = []
        if scores:
            min_s = min(scores)
            max_s = max(scores)
            delta = (max_s - min_s) * 100  # to 0-100 scale
            if delta >= 20:
                anomalies.append(_anomaly(
                    category="provider",
                    subtype="score_disagreement",
                    severity=classify_anomaly("provider", "score_disagreement",
                                               context={"delta": delta}),
                    message=f"Providers disagree on threat score (delta={delta:.1f}).",
                    evidence=[{"scores": scores, "providers": [r.get("source") for r in ok]}],
                    source_sections=["threat_intelligence"],
                    confidence=0.85,
                    metadata={"delta": delta}
                ))

            # High variance
            mean = sum(scores) / len(scores)
            variance = sum((s - mean) ** 2 for s in scores) / len(scores)
            if variance > 0.05:
                anomalies.append(_anomaly(
                    category="provider",
                    subtype="high_variance",
                    severity=classify_anomaly("provider", "high_variance"),
                    message=f"High variance in provider scores: {variance:.4f}.",
                    evidence=[{"variance": variance, "scores": scores}],
                    source_sections=["threat_intelligence"],
                    confidence=0.8
                ))

            # Single provider flag
            flagged = [r for r in ok if float(r.get("threat_score", 0.0) or 0.0) >= 0.5]
            if len(flagged) == 1 and len(ok) >= 3:
                anomalies.append(_anomaly(
                    category="provider",
                    subtype="single_provider_flag",
                    severity=classify_anomaly("provider", "single_provider_flag"),
                    message=f"Only 1 of {len(ok)} providers flagged this target.",
                    evidence=[{"flagged_provider": flagged[0].get("source"),
                               "score": flagged[0].get("threat_score")}],
                    source_sections=["threat_intelligence"],
                    confidence=0.7
                ))

    return anomalies


def _check_stale(report: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    anomaly_cfg = (config or {}).get("anomaly", {}) if isinstance(config, dict) else {}
    max_stale_seconds = anomaly_cfg.get("max_stale_seconds", 86400)
    try:
        max_stale_seconds = int(max_stale_seconds)
    except Exception:
        max_stale_seconds = 86400
    now = datetime.now(timezone.utc)

    # Check evidence freshness
    all_evidence: List[Dict[str, Any]] = []
    for section in ("dns_intelligence", "certificate_intelligence", "passive_dns_intelligence"):
        sec = report.get(section, {}) or {}
        for ev in sec.get("evidence", []) or []:
            if isinstance(ev, dict):
                all_evidence.append(ev)

    stale_count = 0
    for ev in all_evidence:
        ts = ev.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age = (now - dt).total_seconds()
            if age > max_stale_seconds:
                stale_count += 1
        except Exception:
            continue

    if stale_count > 0:
        anomalies.append(_anomaly(
            category="stale",
            subtype="evidence_stale",
            severity=classify_anomaly("stale", "evidence_stale"),
            message=f"{stale_count} evidence item(s) are older than {max_stale_seconds}s.",
            evidence=[{"stale_count": stale_count, "max_stale_seconds": max_stale_seconds}],
            source_sections=["dns_intelligence", "certificate_intelligence", "passive_dns_intelligence"],
            confidence=0.9
        ))

    # Threat data stale
    ti = report.get("threat_intelligence", {}) or {}
    freshness = ti.get("data_freshness", 1.0)
    try:
        freshness = float(freshness)
    except Exception:
        freshness = 1.0
    if freshness < 0.5:
        anomalies.append(_anomaly(
            category="stale",
            subtype="threat_data_stale",
            severity=classify_anomaly("stale", "threat_data_stale"),
            message=f"Threat data freshness is low: {freshness * 100:.1f}%.",
            evidence=[{"data_freshness": freshness}],
            source_sections=["threat_intelligence"],
            confidence=0.85
        ))

    # Snapshot stale
    history = report.get("historical_intelligence", {}) or {}
    prev_ts = history.get("previous_timestamp")
    if prev_ts:
        try:
            dt = datetime.fromisoformat(str(prev_ts).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_days = (now - dt).days
            if age_days > 30:
                anomalies.append(_anomaly(
                    category="stale",
                    subtype="snapshot_stale",
                    severity=classify_anomaly("stale", "snapshot_stale"),
                    message=f"Previous snapshot is {age_days} days old.",
                    evidence=[{"previous_timestamp": prev_ts, "age_days": age_days}],
                    source_sections=["historical_intelligence"],
                    confidence=0.9
                ))
        except Exception:
            pass

    return anomalies


def anomaly_checks(report: Dict[str, Any],
                   config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run all enabled anomaly checks.
    Returns:
    {
        "checks_executed": [...],
        "anomalies": [...],
        "by_severity": {...},
        "by_category": {...}
    }
    """
    anomaly_cfg = (config or {}).get("anomaly", {}) if isinstance(config, dict) else {}
    enabled_checks = anomaly_cfg.get("checks",
                                     ["dns", "cert", "asn", "history", "infra", "provider", "stale"])

    check_map = {
        "dns": _check_dns,
        "cert": _check_cert,
        "asn": _check_asn,
        "history": _check_history,
        "infra": _check_infra,
        "provider": _check_provider,
        "stale": _check_stale,
    }

    executed: List[str] = []
    anomalies: List[Dict[str, Any]] = []

    for name in enabled_checks or []:
        fn = check_map.get(name)
        if not fn:
            continue
        try:
            results = fn(report, config)
            anomalies.extend(results or [])
            executed.append(name)
        except Exception as e:
            # A failed check is not an anomaly — it is a check error.
            # Record it but do not fabricate anomalies.
            anomalies.append(_anomaly(
                category=name,
                subtype="check_error",
                severity="INFORMATIONAL",
                message=f"Anomaly check '{name}' raised an error: {e}",
                evidence=[],
                source_sections=[],
                confidence=0.0
            ))
            executed.append(name)

    return {
        "checks_executed": executed,
        "anomalies": anomalies
    }


def anomaly_report(report: Dict[str, Any],
                   config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Full anomaly detection pipeline.
    """
    anomaly_cfg = (config or {}).get("anomaly", {}) if isinstance(config, dict) else {}
    if not anomaly_cfg.get("enabled", True):
        return {"enabled": False}

    # Step 1: Run checks
    result = anomaly_checks(report, config)
    executed = result["checks_executed"]
    anomalies = result["anomalies"]

    # Step 2: Sort by severity (HIGH first)
    anomalies.sort(key=lambda a: -ANOMALY_SEVERITY_ORDER.get(a.get("severity"), 0))

    # Step 3: Aggregate
    by_severity = {s: 0 for s in ANOMALY_SEVERITIES}
    by_category: Dict[str, int] = defaultdict(int)
    for a in anomalies:
        by_severity[a["severity"]] = by_severity.get(a["severity"], 0) + 1
        by_category[a["category"]] += 1

    # Step 4: Cap report size
    max_in_report = anomaly_cfg.get("max_anomalies_in_report", 200)
    try:
        max_in_report = int(max_in_report)
    except Exception:
        max_in_report = 200
    capped = anomalies[:max_in_report] if max_in_report and max_in_report > 0 else anomalies

    # Step 5: Notes
    notes = [
        "An anomaly is a deviation from expectation, not a verdict.",
        "An anomaly is evidence, not a conclusion.",
        "An anomaly requires interpretation.",
        "Severity reflects deviation level, not threat level.",
        "A clean report means checks were executed and no deviations were found.",
        "A check error is not an anomaly — it is a check failure."
    ]

    return {
        "enabled": True,
        "checks_executed": executed,
        "checks_executed_count": len(executed),
        "total_anomalies": len(anomalies),
        "by_severity": by_severity,
        "by_category": dict(by_category),
        "anomalies": capped,
        "notes": notes,
        "summary": {
            "checks_executed": len(executed),
            "total_anomalies": len(anomalies),
            "informational": by_severity.get("INFORMATIONAL", 0),
            "low": by_severity.get("LOW", 0),
            "moderate": by_severity.get("MODERATE", 0),
            "high": by_severity.get("HIGH", 0)
        }
    }
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
#  THREAT INTELLIGENCE ENGINE 2.0 — v32.1 (Stage 4)
# ============================================================
def normalize_result(source: str, raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize a provider's raw result into a standard structure (Stage 4).
    Output: {source, threat_score 0-1, raw_score, tags, first_seen, last_seen, evidence, status, confidence, reliability, weight, latency, freshness}
    """
    if raw is None:
        return {
            "source": source,
            "threat_score": 0.0,
            "raw_score": None,
            "tags": [],
            "first_seen": None,
            "last_seen": None,
            "evidence": "",
            "status": "FAILED",
            "confidence": 0.0,
            "reliability": 0.0,
            "weight": 0.0,
            "latency": None,
            "freshness": "UNKNOWN"
        }
    # Preserve status from raw if present (Stage 4 — never treat failure as OK)
    raw_status = raw.get("status") if isinstance(raw.get("status"), str) else None
    status = raw_status if raw_status in ("OK", "FAILED", "NOT_CONFIGURED") else "OK"
    # If raw indicates failure via explicit status, propagate
    if raw_status in ("FAILED", "NOT_CONFIGURED"):
        status = raw_status
    raw_score = raw.get("threat_score")
    if raw_score is None and status == "OK":
        # "not in list" — this is a valid answer, not a threat and not a failure
        normalized = 0.0
        tags = raw.get("tags", []) or []
        if not tags:
            tags = ["not_listed"]
    else:
        normalized = 0.0
        try:
            if raw_score is not None and status == "OK":
                val = float(raw_score)
                if val > 1.0:
                    val = val / 100.0
                normalized = max(0.0, min(1.0, val))
            elif status != "OK":
                normalized = 0.0
        except (TypeError, ValueError):
            normalized = 0.0
        tags = raw.get("tags", []) or []
    return {
        "source": source,
        "threat_score": round(normalized, 4),
        "raw_score": raw_score,
        "tags": tags,
        "first_seen": raw.get("first_seen"),
        "last_seen": raw.get("last_seen"),
        "evidence": raw.get("evidence", "") or "",
        "status": status,
        "confidence": raw.get("confidence", 0.5) if status == "OK" else 0.0,
        "reliability": raw.get("reliability", 0.5) if status == "OK" else 0.0,
        "weight": raw.get("weight", 1.0) if status == "OK" else 0.0,
        "latency": raw.get("latency"),
        "freshness": raw.get("freshness", "UNKNOWN") if status == "OK" else "UNKNOWN"
    }

def detect_provider_failure(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Identify which providers failed or were not configured (Stage 4).
    Never treat failure as 'no threat'.
    """
    failed = [r["source"] for r in results if r.get("status") == "FAILED"]
    not_configured = [r["source"] for r in results if r.get("status") == "NOT_CONFIGURED"]
    ok = [r["source"] for r in results if r.get("status") == "OK"]
    return {
        "failed": failed,
        "not_configured": not_configured,
        "ok": ok,
        "failure_count": len(failed),
        "not_configured_count": len(not_configured),
        "ok_count": len(ok),
        "warning": (
            "Some providers failed. Their absence does NOT indicate absence of threat."
            if failed or not_configured else None
        )
    }

def _threat_confidence_stage4(normalized_results: List[Dict[str, Any]], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute threat confidence and related metrics (Stage 4).
    Returns {observed_threat_score 0-100, evidence_coverage 0-1, provider_agreement 0-1, data_freshness 0-1, threat_confidence 0-1, provider_count, ok_count, failed_count, not_configured_count}
    """
    ti_cfg = config.get("threat_intelligence", {}) if isinstance(config, dict) else {}
    min_coverage = float(ti_cfg.get("min_coverage", 0.5))
    agreement_bonus = float(ti_cfg.get("agreement_bonus", 0.1))
    disagreement_penalty = float(ti_cfg.get("disagreement_penalty", 0.2))
    total = len(normalized_results)
    ok_results = [r for r in normalized_results if r.get("status") == "OK"]
    failed = [r for r in normalized_results if r.get("status") == "FAILED"]
    not_configured = [r for r in normalized_results if r.get("status") == "NOT_CONFIGURED"]
    coverage = (len(ok_results) / total) if total > 0 else 0.0
    if ok_results:
        weighted_sum = sum(r.get("threat_score", 0) * r.get("weight", 1.0) * r.get("confidence", 0.5) for r in ok_results)
        weight_sum = sum(r.get("weight", 1.0) * r.get("confidence", 0.5) for r in ok_results)
        observed = (weighted_sum / weight_sum) if weight_sum > 0 else 0.0
    else:
        observed = 0.0
    observed_score = round(observed * 100, 2)
    if len(ok_results) > 1:
        scores = [r.get("threat_score", 0) for r in ok_results]
        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        normalized_variance = min(variance / 0.25, 1.0)
        agreement = 1.0 - normalized_variance
    elif len(ok_results) == 1:
        agreement = 0.5
    else:
        agreement = 0.0
    agreement = round(agreement, 4)
    freshness_map = {"FRESH": 1.0, "STALE": 0.5, "EXPIRED": 0.1, "UNKNOWN": 0.0}
    if ok_results:
        freshness_avg = sum(freshness_map.get(r.get("freshness", "UNKNOWN"), 0.0) for r in ok_results) / len(ok_results)
    else:
        freshness_avg = 0.0
    data_freshness = round(freshness_avg, 4)
    base = observed * coverage * data_freshness
    if agreement > 0.75:
        base += agreement_bonus
    elif agreement < 0.4 and len(ok_results) > 1:
        base -= disagreement_penalty
    if coverage < min_coverage:
        base *= 0.5
    threat_conf = max(0.0, min(1.0, round(base, 4)))
    return {
        "observed_threat_score": observed_score,
        "evidence_coverage": round(coverage, 4),
        "provider_agreement": agreement,
        "data_freshness": data_freshness,
        "threat_confidence": threat_conf,
        "provider_count": total,
        "ok_count": len(ok_results),
        "failed_count": len(failed),
        "not_configured_count": len(not_configured)
    }

def aggregate(raw_results: List[Dict[str, Any]], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Full Threat Intelligence aggregation pipeline (Stage 4).
    Input: raw_results list of dicts with source + raw fields
    Output: {normalized, failures, metrics, summary}
    """
    normalized = [normalize_result(r.get("source", "unknown"), r) for r in raw_results]
    failures = detect_provider_failure(normalized)
    metrics = _threat_confidence_stage4(normalized, config)
    summary_parts = []
    summary_parts.append(f"Observed Threat Score: {metrics['observed_threat_score']}/100")
    summary_parts.append(f"Coverage: {metrics['evidence_coverage'] * 100:.1f}%")
    summary_parts.append(f"Agreement: {metrics['provider_agreement'] * 100:.1f}%")
    summary_parts.append(f"Threat Confidence: {metrics['threat_confidence'] * 100:.1f}%")
    if failures.get("warning"):
        summary_parts.append(f"⚠ {failures['warning']}")
    return {
        "normalized": normalized,
        "failures": failures,
        "metrics": metrics,
        "summary": " | ".join(summary_parts)
    }

def data_confidence_evidence(evidences: List[Evidence]) -> float:
    """
    Data confidence from Evidence objects (Stage 4, separate from threat confidence).
    """
    if not evidences:
        return 0.0
    ok = [e for e in evidences if getattr(e, 'status', '') == "OK"]
    if not ok:
        return 0.0
    avg_conf = sum(float(getattr(e, 'confidence', 0)) for e in ok) / len(ok)
    coverage = len(ok) / len(evidences)
    return round(avg_conf * coverage, 4)

# ============================================================
#  CONFIDENCE ENGINE — v41 (Stage 15)
#  Four distinct, explainable metrics:
#    Data Confidence, Threat Confidence, Geo Confidence, Assessment Confidence.
#  Confidence is not accuracy. Confidence is not certainty.
#  Confidence is the tool's own estimation of how much it knows.
# ============================================================
def _conf_get(ev: Any, key: str, default: Any = None) -> Any:
    """Get key from dict or attribute from Evidence/Ev objects."""
    try:
        if isinstance(ev, dict):
            return ev.get(key, default)
        if hasattr(ev, "to_dict"):
            try:
                d = ev.to_dict()
                if isinstance(d, dict) and key in d:
                    return d.get(key, default)
            except Exception:
                pass
        if hasattr(ev, key):
            return getattr(ev, key)
    except Exception:
        pass
    return default

def _conf_to_dict(ev: Any) -> Dict[str, Any]:
    """Normalize evidence (dict or object) to dict for scoring."""
    if isinstance(ev, dict):
        return ev
    if hasattr(ev, "to_dict"):
        try:
            d = ev.to_dict()
            if isinstance(d, dict):
                return d
        except Exception:
            pass
    try:
        return {
            "source": getattr(ev, "source", getattr(ev, "provider", "unknown")),
            "status": getattr(ev, "status", "UNKNOWN"),
            "confidence": float(getattr(ev, "confidence", getattr(ev, "reliability", 0.0)) or 0.0),
            "freshness": getattr(ev, "freshness", "UNKNOWN"),
        }
    except Exception:
        return {"source": "unknown", "status": "UNKNOWN", "confidence": 0.0, "freshness": "UNKNOWN"}

def data_confidence(report: Optional[Dict[str, Any]] = None,
                    config: Optional[Dict[str, Any]] = None,
                    *args: Any, **kwargs: Any) -> Dict[str, Any]:
    """
    Compute Data Confidence.

    Inputs:
      - Evidence objects across all sections
      - Evidence freshness
      - Evidence status (OK / FAILED / PARTIAL / NOT_CONFIGURED)
      - Provider reliability (if available)

    Output:
    {
        "score": float 0.0 – 1.0,
        "components": {...},
        "explanation": str
    }
    """
    # Backward compatibility: legacy call data_confidence(evs, trusted, cs, _ps)
    # where first arg is a list of Ev/Evidence. Dispatch to Stage 14 logic.
    if args or kwargs or isinstance(report, list):
        try:
            evs = report if isinstance(report, list) else []
            trusted = config if isinstance(config, dict) else {}
            cs = args[0] if len(args) >= 1 else kwargs.get("cs", [])
            _ps = args[1] if len(args) >= 2 else kwargs.get("_ps", None)
            if cs is None:
                cs = []
            return _data_confidence_legacy(evs, trusted, cs, _ps)
        except Exception:
            pass
        # Fall through to Stage 15 if legacy fails and report looks like dict
        if not isinstance(report, dict):
            return {
                "score": 0.0,
                "components": {"total_evidence": 0, "ok_count": 0, "freshness_avg": 0.0, "status_avg": 0.0, "coverage": 0.0},
                "explanation": "No evidence collected. Data confidence is undefined."
            }
    if report is None:
        report = {}
    if config is None:
        config = CFG if isinstance(CFG, dict) else {}
    conf_cfg = config.get("confidence", {}) if isinstance(config, dict) else {}
    weight_freshness = conf_cfg.get("data_weights", {}).get("freshness", 0.4)
    weight_status = conf_cfg.get("data_weights", {}).get("status", 0.3)
    weight_coverage = conf_cfg.get("data_weights", {}).get("coverage", 0.3)

    # Collect all evidence
    evidences: List[Dict[str, Any]] = []
    try:
        for section in (
            "dns_intelligence",
            "certificate_intelligence",
            "passive_dns_intelligence",
            "threat_intelligence",
        ):
            sec = report.get(section, {}) if isinstance(report, dict) else {}
            if not isinstance(sec, dict):
                continue
            for ev in sec.get("evidence", []) or []:
                try:
                    evidences.append(_conf_to_dict(ev))
                except Exception:
                    continue

        # Include provider evidence explicitly
        ti = report.get("threat_intelligence", {}) if isinstance(report, dict) else {}
        if isinstance(ti, dict):
            for norm in ti.get("normalized", []) or []:
                try:
                    nd = _conf_to_dict(norm) if not isinstance(norm, dict) else norm
                    evidences.append({
                        "source": nd.get("source"),
                        "status": nd.get("status"),
                        "confidence": nd.get("confidence", 0.0),
                        "freshness": nd.get("freshness", "UNKNOWN")
                    })
                except Exception:
                    continue
    except Exception:
        pass

    total = len(evidences)
    if total == 0:
        return {
            "score": 0.0,
            "components": {
                "total_evidence": 0,
                "ok_count": 0,
                "freshness_avg": 0.0,
                "status_avg": 0.0,
                "coverage": 0.0
            },
            "explanation": "No evidence collected. Data confidence is undefined."
        }

    ok = [e for e in evidences if _conf_get(e, "status") == "OK"]
    freshness_map = {"FRESH": 1.0, "STALE": 0.5, "EXPIRED": 0.1, "UNKNOWN": 0.0}

    # Freshness score
    freshness_scores = [freshness_map.get(_conf_get(e, "freshness", "UNKNOWN"), 0.0) for e in ok]
    freshness_avg = sum(freshness_scores) / len(freshness_scores) if freshness_scores else 0.0

    # Status score
    status_scores = [1.0 if _conf_get(e, "status") == "OK" else 0.0 for e in evidences]
    status_avg = sum(status_scores) / total if total > 0 else 0.0

    # Coverage
    coverage = len(ok) / total if total > 0 else 0.0

    # Weighted score
    score = (
        freshness_avg * weight_freshness +
        status_avg * weight_status +
        coverage * weight_coverage
    )
    score = round(max(0.0, min(1.0, score)), 4)

    return {
        "score": score,
        "components": {
            "total_evidence": total,
            "ok_count": len(ok),
            "freshness_avg": round(freshness_avg, 4),
            "status_avg": round(status_avg, 4),
            "coverage": round(coverage, 4)
        },
        "explanation": (
            f"Data confidence based on {total} evidence item(s), "
            f"{len(ok)} OK, freshness={freshness_avg:.2f}, "
            f"coverage={coverage:.2f}."
        )
    }

def threat_confidence(report: Optional[Any] = None,
                      config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Compute Threat Confidence.

    Inputs:
      - Provider agreement
      - Normalized threat scores
      - Coverage
      - Failure rate

    Output:
    {
        "score": float 0.0 – 1.0,
        "components": {...},
        "explanation": str
    }
    """
    # Backward compatibility: legacy call threat_confidence(normalized_list, config)
    if isinstance(report, list):
        try:
            return _threat_confidence_stage4(report, config if isinstance(config, dict) else {})
        except Exception as e:
            return {
                "observed_threat_score": 0.0, "evidence_coverage": 0.0,
                "provider_agreement": 0.0, "data_freshness": 0.0,
                "threat_confidence": 0.0, "provider_count": len(report),
                "ok_count": 0, "failed_count": 0, "not_configured_count": 0
            }
    if report is None:
        report = {}
    if config is None:
        config = CFG if isinstance(CFG, dict) else {}
    ti = report.get("threat_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(ti, dict):
        ti = {}
    normalized = ti.get("normalized", []) or []
    # Normalize entries that may be objects
    norm_list: List[Dict[str, Any]] = []
    for r in normalized:
        if isinstance(r, dict):
            norm_list.append(r)
        else:
            try:
                norm_list.append(_conf_to_dict(r))
            except Exception:
                continue
    normalized = norm_list
    total = len(normalized)
    if total == 0:
        return {
            "score": 0.0,
            "components": {
                "provider_count": 0,
                "ok_count": 0,
                "coverage": 0.0,
                "agreement": 0.0,
                "observed_score": 0.0,
                "freshness": 0.0
            },
            "explanation": "No threat providers configured or executed."
        }

    ok = [r for r in normalized if _conf_get(r, "status") == "OK"]
    failed = [r for r in normalized if _conf_get(r, "status") == "FAILED"]
    not_configured = [r for r in normalized if _conf_get(r, "status") == "NOT_CONFIGURED"]

    coverage = len(ok) / total if total > 0 else 0.0
    failure_rate = (len(failed) + len(not_configured)) / total if total > 0 else 0.0

    # Observed score (weighted)
    if ok:
        try:
            weighted_sum = sum(float(_conf_get(r, "threat_score", 0) or 0) * float(_conf_get(r, "weight", 1.0) or 0) * float(_conf_get(r, "confidence", 0.5) or 0) for r in ok)
            weight_sum = sum(float(_conf_get(r, "weight", 1.0) or 0) * float(_conf_get(r, "confidence", 0.5) or 0) for r in ok)
            observed = (weighted_sum / weight_sum) if weight_sum > 0 else 0.0
        except Exception:
            observed = 0.0
    else:
        observed = 0.0

    # Agreement
    if len(ok) > 1:
        try:
            scores = [float(_conf_get(r, "threat_score", 0) or 0) for r in ok]
            mean = sum(scores) / len(scores)
            variance = sum((s - mean) ** 2 for s in scores) / len(scores)
            normalized_variance = min(variance / 0.25, 1.0)
            agreement = 1.0 - normalized_variance
        except Exception:
            agreement = 0.0
    elif len(ok) == 1:
        agreement = 0.5
    else:
        agreement = 0.0

    # Freshness
    freshness_map = {"FRESH": 1.0, "STALE": 0.5, "EXPIRED": 0.1, "UNKNOWN": 0.0}
    if ok:
        try:
            freshness_avg = sum(freshness_map.get(_conf_get(r, "freshness", "UNKNOWN"), 0.0) for r in ok) / len(ok)
        except Exception:
            freshness_avg = 0.0
    else:
        freshness_avg = 0.0

    # Confidence
    try:
        score = observed * coverage * freshness_avg * (1.0 - failure_rate)
    except Exception:
        score = 0.0

    # Agreement bonus / penalty
    conf_cfg = config.get("threat_intelligence", {}) if isinstance(config, dict) else {}
    try:
        agreement_bonus = float(conf_cfg.get("agreement_bonus", 0.1))
    except Exception:
        agreement_bonus = 0.1
    try:
        disagreement_penalty = float(conf_cfg.get("disagreement_penalty", 0.2))
    except Exception:
        disagreement_penalty = 0.2
    if agreement > 0.75:
        score += agreement_bonus
    elif agreement < 0.4 and len(ok) > 1:
        score -= disagreement_penalty

    score = round(max(0.0, min(1.0, score)), 4)

    return {
        "score": score,
        "components": {
            "provider_count": total,
            "ok_count": len(ok),
            "failed_count": len(failed),
            "not_configured_count": len(not_configured),
            "coverage": round(coverage, 4),
            "failure_rate": round(failure_rate, 4),
            "agreement": round(agreement, 4),
            "observed_score": round(observed * 100, 2),
            "freshness": round(freshness_avg, 4)
        },
        "explanation": (
            f"Threat confidence based on {len(ok)}/{total} providers, "
            f"coverage={coverage:.2f}, agreement={agreement:.2f}, "
            f"failure_rate={failure_rate:.2f}."
        )
    }

def geo_confidence(report: Optional[Dict[str, Any]] = None,
                   config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Compute Geo Confidence.

    Inputs:
      - Anycast detection
      - CDN detection
      - Source agreement (country/region/city)
      - Availability of each field

    Output:
    {
        "score": float 0.0 – 1.0,
        "components": {...},
        "explanation": str
    }
    """
    if report is None:
        report = {}
    if config is None:
        config = CFG if isinstance(CFG, dict) else {}
    infra = report.get("infrastructure_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(infra, dict):
        infra = {}
    asn = infra.get("asn", {}) if isinstance(infra, dict) else {}
    rdap = infra.get("rdap", {}) if isinstance(infra, dict) else {}
    org = infra.get("organization", {}) if isinstance(infra, dict) else {}
    if not isinstance(asn, dict):
        asn = {}
    if not isinstance(rdap, dict):
        rdap = {}
    if not isinstance(org, dict):
        org = {}

    # Anycast detection
    anycast = report.get("anycast", False) if isinstance(report, dict) else False
    # Normalize to bool
    anycast = bool(anycast) if isinstance(anycast, bool) else (str(anycast).lower() == "true" if isinstance(anycast, str) else bool(anycast))
    asn_type = asn.get("type", "unknown")

    # Sources of geo
    sources = []
    if asn.get("country"):
        sources.append(("asn", asn["country"]))
    if rdap.get("country"):
        sources.append(("rdap", rdap["country"]))
    if org.get("country"):
        sources.append(("organization", org["country"]))

    countries = [c for _, c in sources if c]
    unique_countries = set(countries)

    # Country agreement
    if len(sources) == 0:
        country_agreement = 0.0
    elif len(unique_countries) == 1:
        country_agreement = 1.0
    else:
        country_agreement = 1.0 / len(unique_countries)

    # Field availability
    fields_present = 0
    if asn.get("country"):
        fields_present += 1
    if rdap.get("country"):
        fields_present += 1
    if org.get("country"):
        fields_present += 1
    field_availability = fields_present / 3.0

    # Penalties
    penalty_anycast = 0.5 if anycast else 0.0
    penalty_cdn = 0.3 if asn_type == "hosting" and anycast else 0.0
    penalty_disagreement = 0.0 if country_agreement >= 0.99 else (1.0 - country_agreement) * 0.5

    score = (
        country_agreement * 0.5 +
        field_availability * 0.5
    )
    score = max(0.0, score - penalty_anycast - penalty_cdn - penalty_disagreement)
    score = round(min(1.0, score), 4)

    return {
        "score": score,
        "components": {
            "sources": [{"name": n, "country": c} for n, c in sources],
            "unique_countries": sorted(unique_countries),
            "country_agreement": round(country_agreement, 4),
            "field_availability": round(field_availability, 4),
            "anycast": anycast,
            "asn_type": asn_type,
            "penalty_anycast": round(penalty_anycast, 4),
            "penalty_cdn": round(penalty_cdn, 4),
            "penalty_disagreement": round(penalty_disagreement, 4)
        },
        "explanation": (
            f"Geo confidence based on {len(sources)} source(s), "
            f"agreement={country_agreement:.2f}, "
            f"anycast={anycast}, "
            f"penalties applied."
        )
    }

def assessment_confidence(data: Optional[Dict[str, Any]] = None,
                          threat: Optional[Dict[str, Any]] = None,
                          geo: Optional[Dict[str, Any]] = None,
                          config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Compute overall Assessment Confidence.

    Inputs:
      - Data Confidence score
      - Threat Confidence score
      - Geo Confidence score
      - Weights from config

    Output:
    {
        "score": float 0.0 – 1.0,
        "components": {...},
        "explanation": str
    }
    """
    if data is None:
        data = {}
    if threat is None:
        threat = {}
    if geo is None:
        geo = {}
    if config is None:
        config = CFG if isinstance(CFG, dict) else {}
    if not isinstance(data, dict):
        data = {"score": 0.0}
    if not isinstance(threat, dict):
        threat = {"score": 0.0}
    if not isinstance(geo, dict):
        geo = {"score": 0.0}
    conf_cfg = config.get("confidence", {}) if isinstance(config, dict) else {}
    weights = conf_cfg.get("weights", {"data": 0.4, "threat": 0.3, "geo": 0.2, "assessment": 0.1})
    if not isinstance(weights, dict):
        weights = {"data": 0.4, "threat": 0.3, "geo": 0.2, "assessment": 0.1}

    try:
        w_data = float(weights.get("data", 0.4))
    except Exception:
        w_data = 0.4
    try:
        w_threat = float(weights.get("threat", 0.3))
    except Exception:
        w_threat = 0.3
    try:
        w_geo = float(weights.get("geo", 0.2))
    except Exception:
        w_geo = 0.2

    # The "assessment" weight is reserved for future use; it is not
    # applied to itself to avoid self-reference.
    total_weight = w_data + w_threat + w_geo
    if total_weight <= 0:
        total_weight = 1.0

    try:
        d_score = float(data.get("score", 0.0) or 0.0)
    except Exception:
        d_score = 0.0
    try:
        t_score = float(threat.get("score", 0.0) or 0.0)
    except Exception:
        t_score = 0.0
    try:
        g_score = float(geo.get("score", 0.0) or 0.0)
    except Exception:
        g_score = 0.0

    score = (
        d_score * w_data +
        t_score * w_threat +
        g_score * w_geo
    ) / total_weight

    score = round(max(0.0, min(1.0, score)), 4)

    # Human label (thresholds from config if present, else spec defaults)
    try:
        labels = conf_cfg.get("labels", {}) if isinstance(conf_cfg, dict) else {}
        th_high = float(labels.get("high", 0.85))
        th_mod = float(labels.get("moderate", 0.65))
        th_low = float(labels.get("low", 0.40))
    except Exception:
        th_high, th_mod, th_low = 0.85, 0.65, 0.40
    if score >= th_high:
        label = "HIGH"
    elif score >= th_mod:
        label = "MODERATE"
    elif score >= th_low:
        label = "LOW"
    else:
        label = "VERY_LOW"

    return {
        "score": score,
        "label": label,
        "components": {
            "data_confidence": d_score,
            "threat_confidence": t_score,
            "geo_confidence": g_score,
            "weights": {"data": w_data, "threat": w_threat, "geo": w_geo}
        },
        "explanation": (
            f"Assessment confidence {label} ({score:.2f}) "
            f"= data({d_score:.2f})*{w_data} + "
            f"threat({t_score:.2f})*{w_threat} + "
            f"geo({g_score:.2f})*{w_geo}."
        )
    }

def confidence_engine(report: Optional[Dict[str, Any]] = None,
                      config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Full confidence pipeline.
    """
    if report is None:
        report = {}
    if config is None:
        config = CFG if isinstance(CFG, dict) else {}
    conf_cfg = config.get("confidence", {}) if isinstance(config, dict) else {}
    if not conf_cfg.get("enabled", True):
        return {"enabled": False}

    data = data_confidence(report, config)
    # Avoid recursion into legacy: data_confidence(report, config) with dict
    # routes to Stage 15 path above.
    threat = threat_confidence(report, config)
    geo = geo_confidence(report, config)
    assessment = assessment_confidence(data, threat, geo, config)

    notes = [
        "Confidence is not accuracy.",
        "Confidence is not certainty.",
        "Confidence is the tool's own estimation of how much it knows.",
        "A low-confidence report is not a bad report — it is an honest one.",
        "Data Confidence, Threat Confidence, and Geo Confidence answer different questions.",
        "Assessment Confidence is a weighted combination, not a source of truth."
    ]

    return {
        "enabled": True,
        "data_confidence": data,
        "threat_confidence": threat,
        "geo_confidence": geo,
        "assessment_confidence": assessment,
        "separate": conf_cfg.get("separate", True),
        "notes": notes,
        "summary": {
            "data": data.get("score", 0.0),
            "threat": threat.get("score", 0.0),
            "geo": geo.get("score", 0.0),
            "assessment": assessment.get("score", 0.0),
            "assessment_label": assessment.get("label", "UNKNOWN")
        }
    }

# ============================================================
#  INTELLIGENCE SCORING — v41.1 (Stage 16)
#  Six distinct, explainable scores, each with WHY? breakdown.
#  A score is not a verdict. A score is not a fact.
#  A score is an explainable estimate.
# ============================================================
SCORE_LABELS = [
    (0.0,  "VERY_LOW"),
    (20.0, "LOW"),
    (40.0, "MODERATE"),
    (60.0, "HIGH"),
    (80.0, "VERY_HIGH"),
]


def _score_label(score: float) -> str:
    """
    Map a 0–100 score to a human-readable label.
    """
    try:
        s = float(score)
    except Exception:
        return "VERY_LOW"
    label = "VERY_LOW"
    for threshold, name in SCORE_LABELS:
        if s >= threshold:
            label = name
    return label


def _sfloat(v: Any, default: float = 0.0) -> float:
    """Safe float conversion."""
    try:
        if v is None:
            return default
        return float(v)
    except Exception:
        return default


def _sget(d: Any, key: str, default: Any = None) -> Any:
    """Get key from dict or attribute from object."""
    try:
        if isinstance(d, dict):
            return d.get(key, default)
        if hasattr(d, key):
            return getattr(d, key)
    except Exception:
        pass
    return default


def explain_score(score_name: str,
                  components: List[Dict[str, Any]],
                  config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build an explainable score from weighted components.

    Each component:
    {
        "name": str,
        "value": float 0.0 – 1.0,
        "weight": float,
        "evidence": str,
        "source_section": str
    }

    Output:
    {
        "name": str,
        "value": float 0.0 – 100.0,
        "label": str,
        "components": [...],
        "explanation": str,
        "contributions": [...]
    }
    """
    try:
        scoring_cfg = config.get("scoring", {}) if isinstance(config, dict) else {}
    except Exception:
        scoring_cfg = {}
    explain = scoring_cfg.get("explain", True) if isinstance(scoring_cfg, dict) else True

    comps = components or []
    try:
        total_weight = sum(_sfloat(c.get("weight", 1.0), 1.0) for c in comps)
    except Exception:
        total_weight = 1.0
    if total_weight <= 0:
        total_weight = 1.0

    contributions = []
    weighted_sum = 0.0
    for c in comps:
        try:
            w = _sfloat(c.get("weight", 1.0), 1.0)
            v = max(0.0, min(1.0, _sfloat(c.get("value", 0.0), 0.0)))
            contribution = v * w
            weighted_sum += contribution
            contributions.append({
                "name": c.get("name", "unknown"),
                "value": round(v, 4),
                "weight": round(w, 4),
                "contribution": round(contribution, 4),
                "evidence": c.get("evidence", ""),
                "source_section": c.get("source_section", "")
            })
        except Exception:
            continue

    normalized = weighted_sum / total_weight if total_weight > 0 else 0.0
    score_value = round(normalized * 100, 2)
    label = _score_label(score_value)

    if explain:
        try:
            parts = [f"{c['name']}={c['value']:.2f}*{c['weight']:.2f}" for c in contributions]
            explanation = f"{score_name} = ({' + '.join(parts)}) / {total_weight:.2f} \u00d7 100 = {score_value}" if parts else f"{score_name} = {score_value}"
        except Exception:
            explanation = f"{score_name} = {score_value}"
    else:
        explanation = f"{score_name} = {score_value}"

    return {
        "name": score_name,
        "value": score_value,
        "label": label,
        "components": contributions,
        "explanation": explanation
    }


def _score_threat(report: Dict[str, Any],
                  config: Dict[str, Any]) -> Dict[str, Any]:
    """
    THREAT SCORE: how likely is this target to be malicious?

    Model:
      base      = observed threat from providers  (0.0 – 1.0)
      modifier  = 0.5 + 0.5 × (agreement × coverage)  (0.5 – 1.0)
      score     = base × modifier × 100  (0.0 – 100.0)

    Rationale:
      - "Observed" is the only true threat signal.
      - "Agreement" and "Coverage" are confidence modifiers.
      - They scale the signal but must never create it.
      - A clean target with perfect coverage still scores 0.
      - A malicious target with poor coverage is discounted, not eliminated.
    """
    ti = report.get("threat_intelligence", {}) or {}
    if not isinstance(ti, dict):
        ti = {}
    normalized = ti.get("normalized", []) or []
    if not isinstance(normalized, list):
        normalized = []
    ok = [r for r in normalized if isinstance(r, dict) and r.get("status") == "OK"]

    # ---- Base: weighted observed threat score ----
    if ok:
        try:
            weighted_sum = sum(
                _sfloat(r.get("threat_score", 0.0), 0.0)
                * _sfloat(r.get("weight", 1.0), 1.0)
                * _sfloat(r.get("confidence", 0.0), 0.0)
                for r in ok
            )
            weight_sum = sum(
                _sfloat(r.get("weight", 1.0), 1.0)
                * _sfloat(r.get("confidence", 0.0), 0.0)
                for r in ok
            )
            observed = (weighted_sum / weight_sum) if weight_sum > 0 else 0.0
        except Exception:
            observed = 0.0
    else:
        observed = 0.0

    # ---- Modifier 1: provider agreement ----
    if len(ok) > 1:
        try:
            scores = [_sfloat(r.get("threat_score", 0.0), 0.0) for r in ok]
            mean = sum(scores) / len(scores)
            variance = sum((s - mean) ** 2 for s in scores) / len(scores)
            agreement = 1.0 - min(variance / 0.25, 1.0)
        except Exception:
            agreement = 0.0
    elif len(ok) == 1:
        agreement = 0.5
    else:
        agreement = 0.0

    # ---- Modifier 2: provider coverage ----
    total = len(normalized)
    coverage = (len(ok) / total) if total > 0 else 0.0

    # ---- Final score ----
    modifier = 0.5 + 0.5 * (agreement * coverage)
    score = observed * modifier * 100.0

    # ---- Component breakdown for explainability ----
    components: List[Dict[str, Any]] = [
        {
            "name": "observed_provider_score",
            "value": observed,
            "weight": 1.0,          # signal weight
            "contribution": round(observed, 4),
            "evidence": f"{len(ok)} provider(s) responded",
            "source_section": "threat_intelligence",
        },
        {
            "name": "provider_agreement",
            "value": agreement,
            "weight": 0.0,          # modifier, not additive
            "contribution": 0.0,
            "evidence": f"agreement among {len(ok)} provider(s)",
            "source_section": "threat_intelligence",
        },
        {
            "name": "provider_coverage",
            "value": coverage,
            "weight": 0.0,          # modifier, not additive
            "contribution": 0.0,
            "evidence": f"{len(ok)}/{total} providers responded",
            "source_section": "threat_intelligence",
        },
        {
            "name": "modifier",
            "value": modifier,
            "weight": 0.0,          # modifier applied to base
            "contribution": round(modifier, 4),
            "evidence": f"modifier = 0.5 + 0.5 × ({agreement:.2f} × {coverage:.2f})",
            "source_section": "threat_intelligence",
        },
    ]

    result = explain_score("THREAT SCORE", components, config)

    # ---- Override the score with the modifier-based value ----
    # explain_score() computes a weighted average, which is not what we want.
    # We set the value directly.
    result["value"] = round(score, 2)
    result["label"] = _score_label(score)
    result["explanation"] = (
        f"THREAT SCORE = observed({observed:.2f}) "
        f"× modifier({modifier:.2f}) × 100 = {score:.1f}"
    )
    result["formula"] = "observed × modifier × 100"
    result["modifier_breakdown"] = {
        "agreement": round(agreement, 4),
        "coverage": round(coverage, 4),
        "modifier": round(modifier, 4),
    }

    return result


def _score_infrastructure(report: Dict[str, Any],
                          config: Dict[str, Any]) -> Dict[str, Any]:
    """
    INFRASTRUCTURE SCORE: how significant is the infrastructure?
    """
    infra = report.get("infrastructure_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(infra, dict):
        infra = {}
    asn = infra.get("asn", {}) if isinstance(infra, dict) else {}
    prefix = infra.get("prefix", {}) if isinstance(infra, dict) else {}
    related = infra.get("related_infrastructure", {}) if isinstance(infra, dict) else {}
    if not isinstance(asn, dict):
        asn = {}
    if not isinstance(prefix, dict):
        prefix = {}
    if not isinstance(related, dict):
        related = {}

    components: List[Dict[str, Any]] = []

    # Component 1: ASN type
    asn_type = asn.get("type", "unknown") or "unknown"
    type_scores = {
        "hosting":    0.7,
        "isp":        0.5,
        "education":  0.6,
        "government": 0.8,
        "unknown":    0.3
    }
    components.append({
        "name": "asn_type",
        "value": type_scores.get(asn_type, 0.3),
        "weight": 0.3,
        "evidence": f"ASN type = {asn_type}",
        "source_section": "infrastructure_intelligence"
    })

    # Component 2: prefix size (larger = more significant)
    try:
        prefix_len = int(prefix.get("prefix_length", 24) or 24)
    except Exception:
        prefix_len = 24
    if prefix_len <= 8:
        prefix_score = 1.0
    elif prefix_len <= 16:
        prefix_score = 0.8
    elif prefix_len <= 24:
        prefix_score = 0.5
    else:
        prefix_score = 0.3
    components.append({
        "name": "prefix_size",
        "value": prefix_score,
        "weight": 0.2,
        "evidence": f"prefix length = /{prefix_len}",
        "source_section": "infrastructure_intelligence"
    })

    # Component 3: peering presence
    peering = infra.get("peering", {}) if isinstance(infra, dict) else {}
    if not isinstance(peering, dict):
        peering = {}
    peers = peering.get("peers", []) or []
    try:
        peer_count = len(peers)
    except Exception:
        peer_count = 0
    peering_score = 0.5 if peering.get("peers") else 0.2
    components.append({
        "name": "peering",
        "value": peering_score,
        "weight": 0.15,
        "evidence": f"peers = {peer_count}",
        "source_section": "infrastructure_intelligence"
    })

    # Component 4: related infrastructure
    try:
        sibs = related.get("sibling_prefixes", []) or []
        sibling_count = len(sibs)
    except Exception:
        sibling_count = 0
    related_score = min(1.0, sibling_count / 5.0)
    components.append({
        "name": "related_infrastructure",
        "value": related_score,
        "weight": 0.15,
        "evidence": f"{sibling_count} sibling prefix(es)",
        "source_section": "infrastructure_intelligence"
    })

    # Component 5: allocation age (older = more established)
    allocated = asn.get("allocated") or prefix.get("allocated")
    age_score = 0.5
    if allocated:
        try:
            dt = datetime.fromisoformat(str(allocated).replace("Z", "+00:00"))
            years = (datetime.now(timezone.utc) - dt).days / 365.0
            age_score = min(1.0, max(0.0, years / 20.0))
        except Exception:
            pass
    components.append({
        "name": "allocation_age",
        "value": age_score,
        "weight": 0.2,
        "evidence": f"allocated = {allocated or 'unknown'}",
        "source_section": "infrastructure_intelligence"
    })

    return explain_score("INFRASTRUCTURE SCORE", components, config)


def _score_data_quality(report: Dict[str, Any],
                        config: Dict[str, Any]) -> Dict[str, Any]:
    """
    DATA QUALITY SCORE: how reliable is the collected data?
    """
    conf = report.get("confidence_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(conf, dict):
        conf = {}
    data_conf = conf.get("data_confidence", {}) if isinstance(conf, dict) else {}
    if not isinstance(data_conf, dict):
        data_conf = {}
    components_raw = data_conf.get("components", {}) if isinstance(data_conf, dict) else {}
    if not isinstance(components_raw, dict):
        components_raw = {}

    components: List[Dict[str, Any]] = [
        {
            "name": "freshness",
            "value": _sfloat(components_raw.get("freshness_avg", 0.0), 0.0),
            "weight": 0.4,
            "evidence": f"freshness_avg = {components_raw.get('freshness_avg', 0.0)}",
            "source_section": "confidence_intelligence"
        },
        {
            "name": "status",
            "value": _sfloat(components_raw.get("status_avg", 0.0), 0.0),
            "weight": 0.3,
            "evidence": f"status_avg = {components_raw.get('status_avg', 0.0)}",
            "source_section": "confidence_intelligence"
        },
        {
            "name": "coverage",
            "value": _sfloat(components_raw.get("coverage", 0.0), 0.0),
            "weight": 0.3,
            "evidence": f"coverage = {components_raw.get('coverage', 0.0)}",
            "source_section": "confidence_intelligence"
        }
    ]

    return explain_score("DATA QUALITY SCORE", components, config)


def _score_exposure(report: Dict[str, Any],
                    config: Dict[str, Any]) -> Dict[str, Any]:
    """
    EXPOSURE SCORE: how much is exposed to the internet?
    """
    as_intel = report.get("attack_surface_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(as_intel, dict):
        as_intel = {}
    services = as_intel.get("services", []) or []
    sensitive = as_intel.get("sensitive_services", []) or []
    exposure = as_intel.get("exposure", {}) or {}
    if not isinstance(exposure, dict):
        exposure = {}
    try:
        svc_len = len(services)
    except Exception:
        svc_len = 0
    try:
        sens_len = len(sensitive)
    except Exception:
        sens_len = 0

    components: List[Dict[str, Any]] = []

    # Component 1: number of services
    svc_score = min(1.0, svc_len / 20.0)
    components.append({
        "name": "service_count",
        "value": svc_score,
        "weight": 0.25,
        "evidence": f"{svc_len} service(s) exposed",
        "source_section": "attack_surface_intelligence"
    })

    # Component 2: sensitive services
    sensitive_score = min(1.0, sens_len / 5.0)
    components.append({
        "name": "sensitive_services",
        "value": sensitive_score,
        "weight": 0.4,
        "evidence": f"{sens_len} sensitive service(s)",
        "source_section": "attack_surface_intelligence"
    })

    # Component 3: external exposure
    external_ratio = 0.0
    try:
        if exposure.get("external_count") is not None:
            total = (exposure.get("external_count", 0) or 0) + (exposure.get("internal_count", 0) or 0)
            if total > 0:
                external_ratio = (exposure.get("external_count", 0) or 0) / total
    except Exception:
        external_ratio = 0.0
    try:
        ext_n = exposure.get("external_count", 0)
    except Exception:
        ext_n = 0
    components.append({
        "name": "external_exposure",
        "value": max(0.0, min(1.0, external_ratio)),
        "weight": 0.2,
        "evidence": f"external = {ext_n}",
        "source_section": "attack_surface_intelligence"
    })

    # Component 4: exposure classification
    classification = exposure.get("classification", "unknown") or "unknown"
    class_score = 1.0 if classification == "external" else 0.3
    components.append({
        "name": "classification",
        "value": class_score,
        "weight": 0.15,
        "evidence": f"classification = {classification}",
        "source_section": "attack_surface_intelligence"
    })

    return explain_score("EXPOSURE SCORE", components, config)


def _score_anomaly(report: Dict[str, Any],
                   config: Dict[str, Any]) -> Dict[str, Any]:
    """
    ANOMALY SCORE: how many deviations were detected?
    """
    anomaly = report.get("anomaly_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(anomaly, dict):
        anomaly = {}
    by_severity = anomaly.get("by_severity", {}) or {}
    if not isinstance(by_severity, dict):
        by_severity = {}

    components: List[Dict[str, Any]] = []

    # Component 1: HIGH severity anomalies
    try:
        high = int(by_severity.get("HIGH", 0) or 0)
    except Exception:
        high = 0
    components.append({
        "name": "high_severity",
        "value": min(1.0, high / 3.0),
        "weight": 0.5,
        "evidence": f"{high} HIGH severity anomaly(ies)",
        "source_section": "anomaly_intelligence"
    })

    # Component 2: MODERATE severity anomalies
    try:
        moderate = int(by_severity.get("MODERATE", 0) or 0)
    except Exception:
        moderate = 0
    components.append({
        "name": "moderate_severity",
        "value": min(1.0, moderate / 5.0),
        "weight": 0.3,
        "evidence": f"{moderate} MODERATE severity anomaly(ies)",
        "source_section": "anomaly_intelligence"
    })

    # Component 3: LOW severity anomalies
    try:
        low = int(by_severity.get("LOW", 0) or 0)
    except Exception:
        low = 0
    components.append({
        "name": "low_severity",
        "value": min(1.0, low / 10.0),
        "weight": 0.15,
        "evidence": f"{low} LOW severity anomaly(ies)",
        "source_section": "anomaly_intelligence"
    })

    # Component 4: informational anomalies
    try:
        info = int(by_severity.get("INFORMATIONAL", 0) or 0)
    except Exception:
        info = 0
    components.append({
        "name": "informational",
        "value": min(1.0, info / 20.0),
        "weight": 0.05,
        "evidence": f"{info} INFORMATIONAL anomaly(ies)",
        "source_section": "anomaly_intelligence"
    })

    return explain_score("ANOMALY SCORE", components, config)


def _score_coverage(report: Dict[str, Any],
                    config: Dict[str, Any]) -> Dict[str, Any]:
    """
    INTELLIGENCE COVERAGE: how complete is the report?
    """
    sections = [
        ("dns_intelligence", "evidence"),
        ("infrastructure_intelligence", "asn"),
        ("certificate_intelligence", "live_certificate"),
        ("passive_dns_intelligence", "timeline"),
        ("threat_intelligence", "normalized"),
        ("attack_surface_intelligence", "services"),
        ("technology_intelligence", "results"),
        ("vulnerability_intelligence", "candidates"),
        ("correlation_intelligence", "graph"),
        ("historical_intelligence", "detection"),
        ("anomaly_intelligence", "anomalies"),
        ("confidence_intelligence", "summary"),
    ]

    components: List[Dict[str, Any]] = []
    for section, key in sections:
        try:
            sec = report.get(section, {}) if isinstance(report, dict) else {}
            has_data = bool(sec.get(key)) if isinstance(sec, dict) else False
        except Exception:
            has_data = False
        components.append({
            "name": f"section:{section}",
            "value": 1.0 if has_data else 0.0,
            "weight": 1.0,
            "evidence": f"{'populated' if has_data else 'empty'}",
            "source_section": section
        })

    # Provider coverage as separate component
    try:
        ti = report.get("threat_intelligence", {}) if isinstance(report, dict) else {}
        if not isinstance(ti, dict):
            ti = {}
        normalized = ti.get("normalized", []) or []
        ok = [r for r in normalized if _sget(r, "status") == "OK"]
        provider_ratio = len(ok) / len(normalized) if normalized else 0.0
    except Exception:
        normalized = []
        ok = []
        provider_ratio = 0.0
    components.append({
        "name": "provider_coverage",
        "value": max(0.0, min(1.0, provider_ratio)),
        "weight": 2.0,
        "evidence": f"{len(ok)}/{len(normalized)} providers OK",
        "source_section": "threat_intelligence"
    })

    return explain_score("INTELLIGENCE COVERAGE", components, config)


def compute_scores(report: Dict[str, Any],
                   config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute all six intelligence scores.
    """
    try:
        scoring_cfg = config.get("scoring", {}) if isinstance(config, dict) else {}
    except Exception:
        scoring_cfg = {}
    if not scoring_cfg.get("enabled", True):
        return {"enabled": False}

    scores = {
        "threat_score": _score_threat(report, config),
        "infrastructure_score": _score_infrastructure(report, config),
        "data_quality_score": _score_data_quality(report, config),
        "exposure_score": _score_exposure(report, config),
        "anomaly_score": _score_anomaly(report, config),
        "intelligence_coverage": _score_coverage(report, config),
    }

    notes = [
        "A score is not a verdict.",
        "A score is not a fact.",
        "A score is an explainable estimate.",
        "Every score answers a different question.",
        "Every score must be read alongside its components and evidence.",
        "A high score in one dimension does not imply a high score in another."
    ]

    return {
        "enabled": True,
        "scores": scores,
        "summary": {
            "threat": scores["threat_score"]["value"],
            "infrastructure": scores["infrastructure_score"]["value"],
            "data_quality": scores["data_quality_score"]["value"],
            "exposure": scores["exposure_score"]["value"],
            "anomaly": scores["anomaly_score"]["value"],
            "coverage": scores["intelligence_coverage"]["value"],
        },
        "notes": notes
    }


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

def _data_confidence_legacy(evs, trusted, cs, _ps):
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
        if getattr(e, 'data_type', '') != "dns": continue
        if field is not None and getattr(e, 'field', '') != field: continue
        # Stage 5 compat: handle both Ev (raw_value dict) and Evidence (metadata)
        rv = getattr(e, 'raw_value', None)
        meta = getattr(e, 'metadata', {}) or {}
        # Try raw_value dict
        rv_dict = {}
        if isinstance(rv, dict):
            rv_dict = rv
        elif isinstance(meta.get("raw_value"), dict):
            rv_dict = meta["raw_value"]
        else:
            rv_dict = meta
        if direction is not None and rv_dict.get("direction") != direction: continue
        if name is not None and rv_dict.get("name") != name: continue
        out.append(e)
    return out

def anomaly_conf(ids):
    if not ids: return 0.0
    return round(min(95, 60 + 10 * (len(ids) - 1)), 1)

def detect_anomalies(ip, domain, evs):
    a = []; sm = PG["anomaly_severity"]
    # Helper for raw extraction (Stage 5 compat)
    def _raw_get(ev, key):
        rv = getattr(ev, 'raw_value', None)
        if isinstance(rv, dict):
            v = rv.get(key)
            if v is not None:
                return v
        meta = getattr(ev, 'metadata', {}) or {}
        if isinstance(meta.get("raw_value"), dict):
            v = meta["raw_value"].get(key)
            if v is not None:
                return v
        return meta.get(key)
    ptrs = dns_evs(evs, field="PTR", direction="reverse")
    hosts = sorted({getattr(e, 'value', None) for e in ptrs if getattr(e, 'value', None) is not None})
    peids = defaultdict(list)
    for e in ptrs: peids[getattr(e, 'value', None)].append(getattr(e, 'id', ''))
    fwd = [e for e in evs if getattr(e, 'data_type', '') == "dns" and getattr(e, 'field', '') in ("A", "AAAA")
           and _raw_get(e, "direction") == "forward_from_ptr"]
    fbyhost = defaultdict(list)
    for e in fwd:
        h = _raw_get(e, "name")
        if h: fbyhost[h].append((getattr(e, 'value', None), getattr(e, 'id', '')))
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
                                if e.data_type == "dns" and e.field == rt and e.value is not None})
    def _raw_get(ev, key):
        rv = getattr(ev, 'raw_value', None)
        if isinstance(rv, dict):
            v = rv.get(key)
            if v is not None:
                return v
        meta = getattr(ev, 'metadata', {}) or {}
        if isinstance(meta.get("raw_value"), dict):
            v = meta["raw_value"].get(key)
            if v is not None:
                return v
        return meta.get(key)
    ptrs = [e for e in evs if getattr(e, 'data_type', '') == "dns" and getattr(e, 'field', '') == "PTR"
            and _raw_get(e, "direction") == "reverse"]
    hosts = sorted({getattr(e, 'value', None) for e in ptrs if getattr(e, 'value', None) is not None})
    cons = []
    for h in hosts:
        fwd = [getattr(e, 'value', None) for e in evs if getattr(e, 'data_type', '') == "dns"
               and getattr(e, 'field', '') in ("A", "AAAA")
               and _raw_get(e, "name") == h
               and _raw_get(e, "direction") == "forward_from_ptr"
               and getattr(e, 'value', None) is not None]
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

def build_graph_legacy(result):
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
#  CORRELATION ENGINE — v36 (Stage 10)
#  Single source of truth for correlation layer.
#  Reads all intelligence layers; modifies none. No new providers.
#  Relationship != maliciousness: shared infrastructure is evidence,
#  not a verdict.
# ============================================================
def _node(node_id: str, node_type: str, **attrs) -> Dict[str, Any]:
    return {
        "id": node_id,
        "type": node_type,
        "attributes": attrs
    }


def _edge(source: str, target: str, edge_type: str, **attrs) -> Dict[str, Any]:
    return {
        "source": source,
        "target": target,
        "type": edge_type,
        "attributes": attrs
    }


def _count_by_key(items: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    result: Dict[str, int] = defaultdict(int)
    for item in items:
        result[item.get(key, "unknown")] += 1
    return dict(result)


def build_graph(report: Dict[str, Any],
                target: Optional[str] = None,
                config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Build a logical graph from all intelligence layers in the report.

    When called with a single argument (legacy phase_k usage), delegates
    to build_graph_legacy and returns the legacy (nodes, edges) tuple.
    Otherwise returns:
    {
        "nodes": [...],
        "edges": [...],
        "index": {node_id: node_dict}
    }
    """
    if target is None and config is None:
        return build_graph_legacy(report)
    config = config or {}
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    node_ids: Set[str] = set()

    def add_node(node: Dict[str, Any]) -> None:
        if node["id"] not in node_ids:
            node_ids.add(node["id"])
            nodes.append(node)

    def add_edge(edge: Dict[str, Any]) -> None:
        edges.append(edge)

    # ---- IP ----
    ip = target
    infra = report.get("infrastructure_intelligence", {}) or {}
    if isinstance(infra, dict) and infra.get("ip"):
        ip = infra["ip"]
    ip_node_id = f"ip:{ip}"
    add_node(_node(ip_node_id, "ip", value=ip))

    # ---- ASN ----
    asn = infra.get("asn", {}) or {}
    if not isinstance(asn, dict):
        asn = {}
    if asn.get("asn"):
        asn_id = f"asn:{asn['asn']}"
        add_node(_node(asn_id, "asn",
                       number=asn.get("asn"),
                       name=asn.get("asn_name"),
                       country=asn.get("country"),
                       type=asn.get("type")))
        add_edge(_edge(ip_node_id, asn_id, "belongs_to_asn"))

    # ---- Prefix ----
    prefix = infra.get("prefix", {}) or {}
    if not isinstance(prefix, dict):
        prefix = {}
    if prefix.get("cidr"):
        prefix_id = f"prefix:{prefix['cidr']}"
        add_node(_node(prefix_id, "prefix",
                       cidr=prefix.get("cidr"),
                       rir=prefix.get("rir"),
                       allocated=prefix.get("allocated")))
        add_edge(_edge(ip_node_id, prefix_id, "in_prefix"))
        if asn.get("asn"):
            add_edge(_edge(f"asn:{asn['asn']}", prefix_id, "announces"))

    # ---- Organization ----
    org = infra.get("organization", {}) or {}
    if not isinstance(org, dict):
        org = {}
    if org.get("name"):
        org_id = f"org:{org['name']}"
        add_node(_node(org_id, "organization",
                       name=org.get("name"),
                       country=org.get("country"),
                       abuse_email=org.get("abuse_email")))
        if asn.get("asn"):
            add_edge(_edge(f"asn:{asn['asn']}", org_id, "owned_by"))

    # ---- DNS ----
    dns = report.get("dns_intelligence", {}) or {}
    for ev in dns.get("evidence", []) or []:
        if not isinstance(ev, dict):
            continue
        if ev.get("status") != "OK":
            continue
        rtype = (ev.get("metadata", {}) or {}).get("record_type", "UNKNOWN")
        value = ev.get("normalized_value")
        if not value:
            continue

        if rtype in ("A", "AAAA"):
            ip_target_id = f"ip:{value}"
            add_node(_node(ip_target_id, "ip", value=value))
            add_edge(_edge(ip_node_id, ip_target_id, "resolves_to",
                           record_type=rtype))

        elif rtype == "PTR":
            domain_id = f"domain:{value}"
            add_node(_node(domain_id, "domain", value=value))
            add_edge(_edge(ip_node_id, domain_id, "has_ptr"))

        elif rtype == "NS":
            ns_id = f"nameserver:{value}"
            add_node(_node(ns_id, "nameserver", value=value))
            add_edge(_edge(ip_node_id, ns_id, "has_nameserver"))

        elif rtype == "MX":
            parts = str(value).split()
            host = parts[-1] if parts else value
            mx_id = f"mailserver:{host}"
            add_node(_node(mx_id, "mailserver", value=host))
            add_edge(_edge(ip_node_id, mx_id, "has_mailserver"))

        elif rtype == "CNAME":
            domain_id = f"domain:{value}"
            add_node(_node(domain_id, "domain", value=value))
            add_edge(_edge(ip_node_id, domain_id, "has_cname"))

    # ---- Certificate ----
    cert_intel = report.get("certificate_intelligence", {}) or {}
    live = cert_intel.get("live_certificate") or {}
    if not isinstance(live, dict):
        live = {}
    fp = live.get("fingerprint_sha256")
    if fp:
        cert_id = f"certificate:{fp}"
        add_node(_node(cert_id, "certificate",
                       fingerprint=fp,
                       issuer=live.get("issuer_cn"),
                       not_after=live.get("not_after"),
                       wildcard=live.get("wildcard")))
        add_edge(_edge(ip_node_id, cert_id, "uses_certificate"))

        for san in live.get("san_domains", []) or []:
            san_id = f"san:{san}"
            add_node(_node(san_id, "san", value=san))
            add_edge(_edge(cert_id, san_id, "certificate_covers"))

    for cert in cert_intel.get("ct_certificates", []) or []:
        if not isinstance(cert, dict):
            continue
        ct_fp = cert.get("fingerprint_sha256")
        if not ct_fp:
            continue
        ct_id = f"certificate:{ct_fp}"
        add_node(_node(ct_id, "certificate",
                       fingerprint=ct_fp,
                       issuer=cert.get("issuer_cn"),
                       not_after=cert.get("not_after"),
                       wildcard=cert.get("wildcard")))
        for san in cert.get("san_domains", []) or []:
            san_id = f"san:{san}"
            add_node(_node(san_id, "san", value=san))
            add_edge(_edge(ct_id, san_id, "certificate_covers"))

    # ---- Passive DNS ----
    pdns = report.get("passive_dns_intelligence", {}) or {}
    for entry in pdns.get("timeline", []) or []:
        if not isinstance(entry, dict):
            continue
        domain = entry.get("domain")
        if not domain:
            continue
        pdns_id = f"passive_dns:{domain}"
        add_node(_node(pdns_id, "passive_dns_domain",
                       value=domain,
                       lifecycle=entry.get("lifecycle"),
                       first_seen=entry.get("first_seen"),
                       last_seen=entry.get("last_seen")))
        add_edge(_edge(ip_node_id, pdns_id, "appears_in_passive_dns"))

    # ---- History ----
    history = report.get("historical_intelligence", {}) or {}
    if isinstance(history, dict) and history.get("status") == "COMPARED":
        history_id = f"history:{ip}"
        add_node(_node(history_id, "history",
                       total_changes=(history.get("detection", {}) or {}).get("total_changes"),
                       previous_timestamp=history.get("previous_timestamp"),
                       current_timestamp=history.get("current_timestamp")))
        add_edge(_edge(ip_node_id, history_id, "has_history"))

    # ---- Threat Intel ----
    ti = report.get("threat_intelligence", {}) or {}
    if isinstance(ti, dict) and ti:
        ti_id = f"threat:{ip}"
        add_node(_node(ti_id, "threat_intel",
                       observed_threat_score=ti.get("observed_threat_score"),
                       threat_confidence=ti.get("threat_confidence"),
                       coverage=ti.get("evidence_coverage")))
        add_edge(_edge(ip_node_id, ti_id, "has_threat_intel"))

    # Build index for fast lookup
    index = {n["id"]: n for n in nodes}

    return {
        "nodes": nodes,
        "edges": edges,
        "index": index,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "node_types": _count_by_key(nodes, "type"),
            "edge_types": _count_by_key(edges, "type")
        }
    }


def find_shared(graph: Dict[str, Any],
                min_shared: int = 1) -> Dict[str, Any]:
    """
    Find shared entities in the graph.

    Two modes:
      1. Within a single graph: entities connected to multiple IPs.
      2. Across multiple graphs: pass a list of graphs.

    For this stage, we support mode 1 (single graph) and mode 2 is
    implemented in correlate() by merging graphs.
    """
    shared = {
        "shared_asns": [],
        "shared_prefixes": [],
        "shared_certificates": [],
        "shared_nameservers": [],
        "shared_mailservers": [],
        "shared_organizations": [],
        "shared_san_domains": [],
        "shared_passive_dns": []
    }

    # Build reverse index: entity_id -> set of ip_ids connected
    entity_to_ips: Dict[str, Set[str]] = defaultdict(set)
    entity_to_domains: Dict[str, Set[str]] = defaultdict(set)

    for edge in graph.get("edges", []) or []:
        src = edge["source"]
        dst = edge["target"]

        if src.startswith("ip:"):
            entity_to_ips[dst].add(src)
        elif dst.startswith("ip:"):
            entity_to_ips[src].add(dst)

        if src.startswith("domain:"):
            entity_to_domains[dst].add(src)
        elif dst.startswith("domain:"):
            entity_to_domains[src].add(dst)

    # Group by node type
    index = graph.get("index", {}) or {}
    for entity_id, ips in entity_to_ips.items():
        if len(ips) < min_shared + 1:  # must be shared by more than one IP
            continue
        node = index.get(entity_id, {})
        ntype = node.get("type")
        entry = {
            "entity": entity_id,
            "type": ntype,
            "shared_by": sorted(ips),
            "attributes": node.get("attributes", {})
        }
        if ntype == "asn":
            shared["shared_asns"].append(entry)
        elif ntype == "prefix":
            shared["shared_prefixes"].append(entry)
        elif ntype == "certificate":
            shared["shared_certificates"].append(entry)
        elif ntype == "nameserver":
            shared["shared_nameservers"].append(entry)
        elif ntype == "mailserver":
            shared["shared_mailservers"].append(entry)
        elif ntype == "organization":
            shared["shared_organizations"].append(entry)
        elif ntype == "san":
            shared["shared_san_domains"].append(entry)
        elif ntype == "passive_dns_domain":
            shared["shared_passive_dns"].append(entry)

    return shared


def _find_related_targets(graph: Dict[str, Any],
                          targets: List[str]) -> List[Dict[str, Any]]:
    """
    Identify target pairs that share at least one entity.
    """
    # Map ip_node_id -> target
    ip_to_target: Dict[str, str] = {}
    for t in targets:
        ip_to_target[f"ip:{t}"] = t

    # Build reverse index: entity -> set of target IPs
    entity_to_targets: Dict[str, Set[str]] = defaultdict(set)
    for edge in graph.get("edges", []) or []:
        src = edge["source"]
        dst = edge["target"]
        if src in ip_to_target:
            entity_to_targets[dst].add(ip_to_target[src])
        elif dst in ip_to_target:
            entity_to_targets[src].add(ip_to_target[dst])

    # Build target pairs
    pairs: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    for entity_id, tset in entity_to_targets.items():
        if len(tset) < 2:
            continue
        sorted_t = sorted(tset)
        for i in range(len(sorted_t)):
            for j in range(i + 1, len(sorted_t)):
                pair = (sorted_t[i], sorted_t[j])
                pairs[pair].add(entity_id)

    related = []
    for (a, b), shared_entities in pairs.items():
        related.append({
            "target_a": a,
            "target_b": b,
            "shared_entities": sorted(shared_entities),
            "shared_count": len(shared_entities)
        })

    related.sort(key=lambda x: x["shared_count"], reverse=True)
    return related


def correlate(reports: List[Dict[str, Any]],
              targets: List[str],
              config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlate one or more reports into a single graph.

    Input:
      reports: list of report dicts (one per target)
      targets: matching list of target strings

    Output:
    {
        "enabled": bool,
        "graph": {...},
        "shared": {...},
        "related_targets": [...],
        "notes": [...]
    }
    """
    corr_cfg = (config or {}).get("correlation", {}) if isinstance(config, dict) else {}
    if not corr_cfg.get("enabled", True):
        return {"enabled": False}

    min_shared = corr_cfg.get("min_shared", 1)
    try:
        min_shared = int(min_shared)
    except Exception:
        min_shared = 1
    max_shared = corr_cfg.get("max_shared_in_report", 100)
    try:
        max_shared = int(max_shared)
    except Exception:
        max_shared = 100
    max_related = corr_cfg.get("max_related_targets", 50)
    try:
        max_related = int(max_related)
    except Exception:
        max_related = 50
    notes = corr_cfg.get("notes", [
        "A shared relationship indicates shared infrastructure, not shared intent.",
        "Shared ASN, prefix, or nameserver may be normal for CDNs, hosting providers, or cloud platforms.",
        "Shared certificate is a stronger signal of shared ownership, but can also be a shared CDN certificate.",
        "Correlation is evidence, not a verdict. Always validate before drawing conclusions."
    ])

    # Merge graphs
    merged_nodes: Dict[str, Dict[str, Any]] = {}
    merged_edges: List[Dict[str, Any]] = []

    for report, target in zip(reports or [], targets or []):
        g = build_graph(report, target, config)
        for node in g["nodes"]:
            merged_nodes[node["id"]] = node
        merged_edges.extend(g["edges"])

    merged_graph = {
        "nodes": list(merged_nodes.values()),
        "edges": merged_edges,
        "index": merged_nodes,
        "stats": {
            "node_count": len(merged_nodes),
            "edge_count": len(merged_edges),
            "node_types": _count_by_key(list(merged_nodes.values()), "type"),
            "edge_types": _count_by_key(merged_edges, "type")
        }
    }

    # Find shared entities
    shared = find_shared(merged_graph, min_shared=min_shared)
    if max_shared and max_shared > 0:
        for k, v in list(shared.items()):
            if isinstance(v, list):
                shared[k] = v[:max_shared]

    # Identify related targets
    related_targets = _find_related_targets(merged_graph, targets or [])
    if max_related and max_related > 0:
        related_targets = related_targets[:max_related]

    return {
        "enabled": True,
        "graph": merged_graph,
        "shared": shared,
        "related_targets": related_targets,
        "notes": notes,
        "summary": {
            "targets_correlated": len(targets or []),
            "total_nodes": merged_graph["stats"]["node_count"],
            "total_edges": merged_graph["stats"]["edge_count"],
            "shared_asns": len(shared["shared_asns"]),
            "shared_prefixes": len(shared["shared_prefixes"]),
            "shared_certificates": len(shared["shared_certificates"]),
            "shared_nameservers": len(shared["shared_nameservers"]),
            "shared_organizations": len(shared["shared_organizations"])
        }
    }

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
def _export_stix_legacy(result):
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

def _export_misp_legacy(result):
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
#  FINAL INTELLIGENCE REPORT — v42 (Stage 17)
#  18-section professional report + multi-format exporters.
#  A report is not a verdict. Every claim traces to evidence.
# ============================================================
def _report_metadata(target: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build report-level metadata.
    """
    try:
        version = config.get("version", "v44") if isinstance(config, dict) else "v44"
    except Exception:
        version = "v44"
    try:
        classification = config.get("reports", {}).get("classification", "UNCLASSIFIED") if isinstance(config, dict) else "UNCLASSIFIED"
    except Exception:
        classification = "UNCLASSIFIED"
    try:
        safe = str(target).replace('.', '-').replace(':', '-')
    except Exception:
        safe = "unknown"
    try:
        ts = int(datetime.now(timezone.utc).timestamp())
    except Exception:
        ts = 0
    return {
        "tool": "ReconIP",
        "version": version,
        "target": target,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "report_id": f"reconip-{safe}-{ts}",
        "classification": classification,
        "profile": config.get("_applied_profile", {"name": None, "description": "base config"}) if isinstance(config, dict) else {"name": None, "description": "base config"},
        "disclaimer": (
            "This report is evidence-driven and intended for authorized security "
            "analysis only. It does not claim compromise, exploitation, or impact. "
            "All findings must be validated in context."
        )
    }


def _section_target_profile(target: str, report: Dict[str, Any]) -> Dict[str, Any]:
    infra = report.get("infrastructure_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(infra, dict):
        infra = {}
    asn = infra.get("asn", {}) if isinstance(infra, dict) else {}
    org = infra.get("organization", {}) if isinstance(infra, dict) else {}
    prefix = infra.get("prefix", {}) if isinstance(infra, dict) else {}
    if not isinstance(asn, dict):
        asn = {}
    if not isinstance(org, dict):
        org = {}
    if not isinstance(prefix, dict):
        prefix = {}
    return {
        "target": target,
        "ip": infra.get("ip"),
        "asn": asn.get("asn"),
        "asn_name": asn.get("asn_name"),
        "country": org.get("country"),
        "organization": org.get("name"),
        "prefix": prefix.get("cidr"),
        "rir": prefix.get("rir"),
        "anycast": report.get("anycast", False) if isinstance(report, dict) else False
    }


def _executive_headline(report: Dict[str, Any]) -> str:
    try:
        anomaly = report.get("anomaly_intelligence", {}) if isinstance(report, dict) else {}
        by_sev = anomaly.get("by_severity", {}) if isinstance(anomaly, dict) else {}
        threat = report.get("threat_intelligence", {}) if isinstance(report, dict) else {}
        observed = float(threat.get("observed_threat_score", 0.0) or 0.0) if isinstance(threat, dict) else 0.0
    except Exception:
        by_sev = {}
        observed = 0.0
    try:
        if int(by_sev.get("HIGH", 0) or 0) > 0:
            return "HIGH severity anomalies detected. Manual review recommended."
        if observed >= 50:
            return "Elevated threat indicators observed. Validate before concluding."
        if int(by_sev.get("MODERATE", 0) or 0) > 0:
            return "Moderate deviations detected. Review recommended."
        return "No significant deviations detected. Continue routine monitoring."
    except Exception:
        return "No significant deviations detected. Continue routine monitoring."


def _section_executive_summary(report: Dict[str, Any]) -> Dict[str, Any]:
    scoring = report.get("intelligence_scoring", {}) if isinstance(report, dict) else {}
    confidence = report.get("confidence_intelligence", {}) if isinstance(report, dict) else {}
    anomaly = report.get("anomaly_intelligence", {}) if isinstance(report, dict) else {}
    threat = report.get("threat_intelligence", {}) if isinstance(report, dict) else {}
    exposure = report.get("attack_surface_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(scoring, dict):
        scoring = {}
    if not isinstance(confidence, dict):
        confidence = {}
    if not isinstance(anomaly, dict):
        anomaly = {}
    if not isinstance(threat, dict):
        threat = {}
    if not isinstance(exposure, dict):
        exposure = {}
    summary = scoring.get("summary", {}) if isinstance(scoring, dict) else {}
    assessment = confidence.get("assessment_confidence", {}) if isinstance(confidence, dict) else {}
    if not isinstance(summary, dict):
        summary = {}
    if not isinstance(assessment, dict):
        assessment = {}
    return {
        "assessment_confidence": assessment.get("label", "UNKNOWN"),
        "assessment_score": assessment.get("score", 0.0),
        "scores": {
            "threat": summary.get("threat", 0.0),
            "infrastructure": summary.get("infrastructure", 0.0),
            "data_quality": summary.get("data_quality", 0.0),
            "exposure": summary.get("exposure", 0.0),
            "anomaly": summary.get("anomaly", 0.0),
            "coverage": summary.get("coverage", 0.0)
        },
        "threat_confidence": threat.get("threat_confidence", 0.0),
        "observed_threat_score": threat.get("observed_threat_score", 0.0),
        "anomaly_summary": anomaly.get("by_severity", {}),
        "exposed_services": exposure.get("service_count", 0),
        "sensitive_services": exposure.get("sensitive_count", 0),
        "headline": _executive_headline(report)
    }


def _section_data_quality(report: Dict[str, Any]) -> Dict[str, Any]:
    conf = report.get("confidence_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(conf, dict):
        conf = {}
    data_conf = conf.get("data_confidence", {}) if isinstance(conf, dict) else {}
    if not isinstance(data_conf, dict):
        data_conf = {}
    return {
        "score": data_conf.get("score", 0.0),
        "components": data_conf.get("components", {}),
        "explanation": data_conf.get("explanation", "")
    }


def _section_network(report: Dict[str, Any]) -> Dict[str, Any]:
    infra = report.get("infrastructure_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(infra, dict):
        infra = {}
    return {
        "asn": infra.get("asn", {}),
        "prefix": infra.get("prefix", {}),
        "organization": infra.get("organization", {}),
        "origin": infra.get("origin", {}),
        "related_infrastructure": infra.get("related_infrastructure", {}),
        "peering": infra.get("peering", {})
    }


def _section_dns(report: Dict[str, Any]) -> Dict[str, Any]:
    dns = report.get("dns_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(dns, dict):
        dns = {}
    return {
        "evidence": dns.get("evidence", []),
        "analysis": dns.get("analysis", {})
    }


def _section_certificate(report: Dict[str, Any]) -> Dict[str, Any]:
    cert = report.get("certificate_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(cert, dict):
        cert = {}
    return {
        "live_certificate": cert.get("live_certificate"),
        "ct_certificates": cert.get("ct_certificates", []),
        "correlation": cert.get("correlation", {}),
        "relationships": cert.get("relationships", {}),
        "summary": cert.get("summary", {})
    }


def _section_passive_dns(report: Dict[str, Any]) -> Dict[str, Any]:
    pdns = report.get("passive_dns_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(pdns, dict):
        pdns = {}
    return {
        "timeline": pdns.get("timeline", []),
        "stats": pdns.get("stats", {}),
        "related_domains": pdns.get("related_domains", [])
    }


def _section_history(report: Dict[str, Any]) -> Dict[str, Any]:
    hist = report.get("historical_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(hist, dict):
        hist = {}
    return {
        "status": hist.get("status"),
        "previous_timestamp": hist.get("previous_timestamp"),
        "current_timestamp": hist.get("current_timestamp"),
        "detection": hist.get("detection", {})
    }


def _section_threat(report: Dict[str, Any]) -> Dict[str, Any]:
    ti = report.get("threat_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(ti, dict):
        ti = {}
    return {
        "observed_threat_score": ti.get("observed_threat_score"),
        "evidence_coverage": ti.get("evidence_coverage"),
        "provider_agreement": ti.get("provider_agreement"),
        "data_freshness": ti.get("data_freshness"),
        "threat_confidence": ti.get("threat_confidence"),
        "provider_count": ti.get("provider_count"),
        "ok_count": ti.get("ok_count"),
        "failed_count": ti.get("failed_count"),
        "not_configured_count": ti.get("not_configured_count"),
        "failures": ti.get("failures", {}),
        "normalized": ti.get("normalized", [])
    }


def _section_correlation(report: Dict[str, Any]) -> Dict[str, Any]:
    corr = report.get("correlation_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(corr, dict):
        corr = {}
    graph = corr.get("graph", {}) if isinstance(corr, dict) else {}
    if not isinstance(graph, dict):
        graph = {}
    return {
        "graph_stats": graph.get("stats", {}),
        "shared": corr.get("shared", {}),
        "related_targets": corr.get("related_targets", []),
        "notes": corr.get("notes", [])
    }


def _section_attack_surface(report: Dict[str, Any]) -> Dict[str, Any]:
    as_intel = report.get("attack_surface_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(as_intel, dict):
        as_intel = {}
    return {
        "services": as_intel.get("services", []),
        "sensitive_services": as_intel.get("sensitive_services", []),
        "service_count": as_intel.get("service_count", 0),
        "sensitive_count": as_intel.get("sensitive_count", 0),
        "exposure": as_intel.get("exposure", {}),
        "notes": as_intel.get("notes", [])
    }


def _section_technology(report: Dict[str, Any]) -> Dict[str, Any]:
    tech = report.get("technology_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(tech, dict):
        tech = {}
    return {
        "results": tech.get("results", []),
        "by_class": tech.get("by_class", {}),
        "summary": tech.get("summary", {}),
        "notes": tech.get("notes", [])
    }


def _section_vulnerability(report: Dict[str, Any]) -> Dict[str, Any]:
    vuln = report.get("vulnerability_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(vuln, dict):
        vuln = {}
    return {
        "candidates": vuln.get("candidates", []),
        "cpes_built": vuln.get("cpes_built", []),
        "summary": vuln.get("summary", {}),
        "notes": vuln.get("notes", [])
    }


def _section_anomalies(report: Dict[str, Any]) -> Dict[str, Any]:
    anomaly = report.get("anomaly_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(anomaly, dict):
        anomaly = {}
    return {
        "checks_executed": anomaly.get("checks_executed", []),
        "checks_executed_count": anomaly.get("checks_executed_count", 0),
        "by_severity": anomaly.get("by_severity", {}),
        "by_category": anomaly.get("by_category", {}),
        "anomalies": anomaly.get("anomalies", []),
        "notes": anomaly.get("notes", [])
    }


def _section_evidence(report: Dict[str, Any],
                      config: Dict[str, Any],
                      include_raw: bool = False) -> Dict[str, Any]:
    """
    Aggregate all Evidence objects across sections.
    If include_raw is False, only summary metadata is included.
    """
    all_evidence: List[Dict[str, Any]] = []

    for section in (
        "dns_intelligence",
        "certificate_intelligence",
        "passive_dns_intelligence",
    ):
        try:
            sec = report.get(section, {}) if isinstance(report, dict) else {}
            if not isinstance(sec, dict):
                continue
            for ev in sec.get("evidence", []) or []:
                if not isinstance(ev, dict):
                    continue
                all_evidence.append({
                    "section": section,
                    "source": ev.get("source"),
                    "timestamp": ev.get("timestamp"),
                    "status": ev.get("status"),
                    "confidence": ev.get("confidence"),
                    "freshness": ev.get("freshness"),
                    "value": ev.get("value") if include_raw else None,
                    "normalized_value": ev.get("normalized_value") if include_raw else None,
                })
        except Exception:
            continue

    # Provider evidence
    try:
        ti = report.get("threat_intelligence", {}) if isinstance(report, dict) else {}
        if isinstance(ti, dict):
            for norm in ti.get("normalized", []) or []:
                if not isinstance(norm, dict):
                    continue
                all_evidence.append({
                    "section": "threat_intelligence",
                    "source": norm.get("source"),
                    "timestamp": None,
                    "status": norm.get("status"),
                    "confidence": norm.get("confidence"),
                    "freshness": norm.get("freshness"),
                    "value": norm.get("threat_score") if include_raw else None,
                    "normalized_value": None,
                })
    except Exception:
        pass

    # Stats
    by_status = defaultdict(int)
    by_source = defaultdict(int)
    for ev in all_evidence:
        try:
            by_status[ev.get("status", "UNKNOWN")] += 1
            by_source[ev.get("source", "unknown")] += 1
        except Exception:
            continue

    return {
        "total": len(all_evidence),
        "by_status": dict(by_status),
        "by_source": dict(by_source),
        "include_raw": include_raw,
        "items": all_evidence if include_raw else []
    }


def _section_confidence(report: Dict[str, Any]) -> Dict[str, Any]:
    conf = report.get("confidence_intelligence", {}) if isinstance(report, dict) else {}
    if not isinstance(conf, dict):
        conf = {}
    return {
        "data_confidence": conf.get("data_confidence", {}),
        "threat_confidence": conf.get("threat_confidence", {}),
        "geo_confidence": conf.get("geo_confidence", {}),
        "assessment_confidence": conf.get("assessment_confidence", {}),
        "summary": conf.get("summary", {}),
        "notes": conf.get("notes", [])
    }


def _section_limitations(report: Dict[str, Any],
                         config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Explicitly state what the report does NOT claim.
    """
    limitations = [
        "This report is evidence-driven. It does not claim compromise, exploitation, or impact.",
        "An open port is exposure, not a vulnerability.",
        "A detected service is a fingerprint, not a confirmed vulnerability.",
        "A CVE candidate is not a confirmed vulnerability.",
        "A shared relationship is not shared intent.",
        "A score is not a verdict.",
        "A confidence value is not accuracy.",
        "Historical changes are evidence, not conclusions.",
        "Geolocation is approximate, especially for anycast and CDN IPs.",
        "Passive DNS data depends on third-party sources and may be incomplete.",
        "Threat intelligence depends on provider coverage and freshness.",
        "Technology fingerprinting depends on available evidence; UNKNOWN is honest.",
    ]

    # Add configuration-specific limitations
    try:
        as_cfg = config.get("attack_surface", {}) if isinstance(config, dict) else {}
        if not as_cfg.get("port_scan", False):
            limitations.append("Active port scanning was disabled. Service list is passive-only.")
        fp_cfg = config.get("fingerprinting", {}) if isinstance(config, dict) else {}
        if not fp_cfg.get("active_banner_grab", False):
            limitations.append("Active banner grabbing was disabled. Technology versions may be UNKNOWN.")
        vuln_cfg = config.get("vulnerability", {}) if isinstance(config, dict) else {}
        if vuln_cfg.get("require_validation", True):
            limitations.append("Vulnerability validation is required. Candidates are not confirmations.")
        if not config.get("history", {}).get("enabled", True):
            limitations.append("Historical comparison was disabled. No change detection available.")
    except Exception:
        pass

    return {"limitations": limitations}


def _section_next_investigation(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Suggest actionable next steps based on findings.
    Never suggests exploitation.
    """
    steps: List[Dict[str, Any]] = []

    # Anomalies
    try:
        anomaly = report.get("anomaly_intelligence", {}) if isinstance(report, dict) else {}
        by_sev = anomaly.get("by_severity", {}) if isinstance(anomaly, dict) else {}
        if int(by_sev.get("HIGH", 0) or 0) > 0:
            steps.append({
                "priority": "high",
                "action": "Review HIGH severity anomalies in detail.",
                "reason": f"{by_sev['HIGH']} HIGH severity anomaly(ies) detected."
            })
        if int(by_sev.get("MODERATE", 0) or 0) > 0:
            steps.append({
                "priority": "moderate",
                "action": "Investigate MODERATE severity anomalies.",
                "reason": f"{by_sev['MODERATE']} MODERATE severity anomaly(ies) detected."
            })
    except Exception:
        pass

    # Threat
    try:
        ti = report.get("threat_intelligence", {}) if isinstance(report, dict) else {}
        if isinstance(ti, dict):
            if int(ti.get("failed_count", 0) or 0) > 0:
                steps.append({
                    "priority": "moderate",
                    "action": "Resolve failed threat intelligence providers.",
                    "reason": f"{ti['failed_count']} provider(s) failed. Absence of data is not absence of threat."
                })
            if float(ti.get("observed_threat_score", 0) or 0) >= 50:
                steps.append({
                    "priority": "high",
                    "action": "Validate threat indicators with additional sources.",
                    "reason": f"Observed threat score {ti['observed_threat_score']}/100."
                })
    except Exception:
        pass

    # Attack surface
    try:
        as_intel = report.get("attack_surface_intelligence", {}) if isinstance(report, dict) else {}
        if isinstance(as_intel, dict) and int(as_intel.get("sensitive_count", 0) or 0) > 0:
            steps.append({
                "priority": "high",
                "action": "Review sensitive exposed services.",
                "reason": f"{as_intel['sensitive_count']} sensitive service(s) exposed."
            })
    except Exception:
        pass

    # Vulnerability candidates
    try:
        vuln = report.get("vulnerability_intelligence", {}) if isinstance(report, dict) else {}
        if isinstance(vuln, dict) and vuln.get("candidates"):
            steps.append({
                "priority": "high",
                "action": "Validate vulnerability candidates in an authorized environment.",
                "reason": f"{len(vuln['candidates'])} candidate(s) require validation."
            })
    except Exception:
        pass

    # Historical changes
    try:
        hist = report.get("historical_intelligence", {}) if isinstance(report, dict) else {}
        detection = hist.get("detection", {}) if isinstance(hist, dict) else {}
        by_sev_h = detection.get("by_severity", {}) if isinstance(detection, dict) else {}
        if int(by_sev_h.get("critical", 0) or 0) > 0:
            steps.append({
                "priority": "high",
                "action": "Review critical historical changes.",
                "reason": f"{by_sev_h['critical']} critical change(s) detected."
            })
    except Exception:
        pass

    # Certificate
    try:
        cert = report.get("certificate_intelligence", {}) if isinstance(report, dict) else {}
        summary = cert.get("summary", {}) if isinstance(cert, dict) else {}
        if int(summary.get("expired_count", 0) or 0) > 0:
            steps.append({
                "priority": "moderate",
                "action": "Renew expired certificates.",
                "reason": f"{summary['expired_count']} expired certificate(s)."
            })
        if int(summary.get("weak_algo_count", 0) or 0) > 0:
            steps.append({
                "priority": "high",
                "action": "Replace weak certificate algorithms.",
                "reason": f"{summary['weak_algo_count']} certificate(s) with weak algorithms."
            })
    except Exception:
        pass

    # Coverage
    try:
        scoring = report.get("intelligence_scoring", {}) if isinstance(report, dict) else {}
        coverage = scoring.get("summary", {}).get("coverage", 0) if isinstance(scoring, dict) else 0
        if float(coverage or 0) < 60:
            steps.append({
                "priority": "moderate",
                "action": "Improve intelligence coverage.",
                "reason": f"Coverage is {coverage}/100."
            })
    except Exception:
        pass

    if not steps:
        steps.append({
            "priority": "informational",
            "action": "Continue routine monitoring.",
            "reason": "No actionable findings at this time."
        })

    # Sort by priority
    order = {"high": 0, "moderate": 1, "low": 2, "informational": 3}
    try:
        steps.sort(key=lambda s: order.get(s.get("priority", "informational"), 99))
    except Exception:
        pass

    return {"next_investigation": steps}


def generate_report(target: str,
                    report: Dict[str, Any],
                    config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Assemble the full 18-section professional intelligence report.
    """
    try:
        reports_cfg = config.get("reports", {}) if isinstance(config, dict) else {}
    except Exception:
        reports_cfg = {}
    include_raw = reports_cfg.get("include_raw", False) if isinstance(reports_cfg, dict) else False
    if report is None:
        report = {}
    if config is None:
        config = CFG if isinstance(CFG, dict) else {}

    return {
        "metadata": _report_metadata(target, config),
        "01_target_profile":       _section_target_profile(target, report),
        "02_executive_summary":    _section_executive_summary(report),
        "03_data_quality":         _section_data_quality(report),
        "04_network_intelligence": _section_network(report),
        "05_dns_intelligence":     _section_dns(report),
        "06_certificate_intelligence": _section_certificate(report),
        "07_passive_dns":          _section_passive_dns(report),
        "08_historical_intelligence": _section_history(report),
        "09_threat_intelligence":  _section_threat(report),
        "10_infrastructure_correlation": _section_correlation(report),
        "11_attack_surface":       _section_attack_surface(report),
        "12_technology":           _section_technology(report),
        "13_vulnerability_candidates": _section_vulnerability(report),
        "14_anomalies":            _section_anomalies(report),
        "15_evidence":             _section_evidence(report, config, include_raw=include_raw),
        "16_confidence":           _section_confidence(report),
        "17_limitations":          _section_limitations(report, config),
        "18_next_investigation":   _section_next_investigation(report),
    }


def _ensure_output_dir(config: Dict[str, Any]) -> str:
    try:
        out_dir = config.get("reports", {}).get("output_dir", "reports/") if isinstance(config, dict) else "reports/"
    except Exception:
        out_dir = "reports/"
    if not out_dir:
        out_dir = "reports/"
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


def _report_filename(target: str, ext: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_target = re.sub(r"[^a-zA-Z0-9._-]", "_", str(target or "unknown"))
    return f"{safe_target}_{ts}.{ext}"


def export_json(final_report: Dict[str, Any],
                config: Dict[str, Any]) -> str:
    """
    Export the final report as JSON.
    The output is SIEM-compatible: flat keys, ISO timestamps, no NaN.
    """
    out_dir = _ensure_output_dir(config)
    target = final_report.get("metadata", {}).get("target", "unknown") if isinstance(final_report, dict) else "unknown"
    path = os.path.join(out_dir, _report_filename(target, "json"))

    with open(path, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=2, default=str, ensure_ascii=False)

    return path


def export_csv(final_report: Dict[str, Any],
               config: Dict[str, Any]) -> str:
    """
    Export a flat CSV suitable for spreadsheets.

    Each row represents one finding:
      section, category, severity, value, evidence, source
    """
    out_dir = _ensure_output_dir(config)
    target = final_report.get("metadata", {}).get("target", "unknown") if isinstance(final_report, dict) else "unknown"
    path = os.path.join(out_dir, _report_filename(target, "csv"))

    rows: List[Dict[str, Any]] = []

    # Anomalies
    try:
        for a in final_report.get("14_anomalies", {}).get("anomalies", []) or []:
            if not isinstance(a, dict):
                continue
            rows.append({
                "section": "anomaly",
                "category": a.get("category"),
                "severity": a.get("severity"),
                "value": a.get("subtype"),
                "evidence": json.dumps(a.get("evidence", []), default=str),
                "source": ",".join(a.get("source_sections", []) or [])
            })
    except Exception:
        pass

    # Vulnerability candidates
    try:
        for c in final_report.get("13_vulnerability_candidates", {}).get("candidates", []) or []:
            if not isinstance(c, dict):
                continue
            rows.append({
                "section": "vulnerability",
                "category": "candidate",
                "severity": str(c.get("severity")),
                "value": c.get("cve"),
                "evidence": json.dumps(c.get("evidence", []), default=str),
                "source": "vulnerability_intelligence"
            })
    except Exception:
        pass

    # Services
    try:
        for s in final_report.get("11_attack_surface", {}).get("services", []) or []:
            if not isinstance(s, dict):
                continue
            rows.append({
                "section": "attack_surface",
                "category": s.get("service"),
                "severity": s.get("risk_class"),
                "value": f"{s.get('port')}/{s.get('protocol')}",
                "evidence": s.get("evidence", ""),
                "source": s.get("source", "")
            })
    except Exception:
        pass

    # History changes
    try:
        for ch in final_report.get("08_historical_intelligence", {}).get("detection", {}).get("changes", []) or []:
            if not isinstance(ch, dict):
                continue
            rows.append({
                "section": "history",
                "category": ch.get("change_type"),
                "severity": ch.get("severity"),
                "value": ch.get("key"),
                "evidence": json.dumps({"old": ch.get("old"), "new": ch.get("new")}, default=str),
                "source": "historical_intelligence"
            })
    except Exception:
        pass

    # Write CSV
    fieldnames = ["section", "category", "severity", "value", "evidence", "source"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            try:
                writer.writerow(row)
            except Exception:
                continue

    return path


def export_html(final_report: Dict[str, Any],
                config: Dict[str, Any]) -> str:
    """
    Export a readable HTML report.
    """
    out_dir = _ensure_output_dir(config)
    target = final_report.get("metadata", {}).get("target", "unknown") if isinstance(final_report, dict) else "unknown"
    path = os.path.join(out_dir, _report_filename(target, "html"))

    def esc(v):
        try:
            return _html.escape(str(v)) if v is not None else ""
        except Exception:
            return str(v) if v is not None else ""

    md = final_report.get("metadata", {}) if isinstance(final_report, dict) else {}
    ex = final_report.get("02_executive_summary", {}) if isinstance(final_report, dict) else {}
    an = final_report.get("14_anomalies", {}) if isinstance(final_report, dict) else {}
    conf = final_report.get("16_confidence", {}) if isinstance(final_report, dict) else {}
    if not isinstance(md, dict):
        md = {}
    if not isinstance(ex, dict):
        ex = {}
    if not isinstance(an, dict):
        an = {}
    if not isinstance(conf, dict):
        conf = {}

    parts = []
    parts.append("<!DOCTYPE html>")
    parts.append("<html lang='en'><head><meta charset='utf-8'>")
    parts.append(f"<title>ReconIP Report \u2014 {esc(target)}</title>")
    parts.append("<style>")
    parts.append("body{font-family:Arial,sans-serif;margin:2em;color:#222}")
    parts.append("h1,h2,h3{color:#003366}")
    parts.append("table{border-collapse:collapse;width:100%;margin:1em 0}")
    parts.append("th,td{border:1px solid #ccc;padding:6px;text-align:left}")
    parts.append("th{background:#f0f0f0}")
    parts.append(".HIGH{color:#b30000;font-weight:bold}")
    parts.append(".MODERATE{color:#cc6600;font-weight:bold}")
    parts.append(".LOW{color:#806600}")
    parts.append(".INFORMATIONAL{color:#555}")
    parts.append("</style></head><body>")

    parts.append(f"<h1>ReconIP Intelligence Report</h1>")
    parts.append(f"<p><b>Target:</b> {esc(md.get('target'))}<br>")
    parts.append(f"<b>Generated:</b> {esc(md.get('generated_at'))}<br>")
    parts.append(f"<b>Version:</b> {esc(md.get('version'))}<br>")
    parts.append(f"<b>Classification:</b> {esc(md.get('classification'))}</p>")
    parts.append(f"<p><i>{esc(md.get('disclaimer'))}</i></p>")

    # Executive Summary
    parts.append("<h2>Executive Summary</h2>")
    parts.append(f"<p><b>Assessment Confidence:</b> {esc(ex.get('assessment_confidence'))} "
                 f"({esc(ex.get('assessment_score'))})</p>")
    parts.append(f"<p>{esc(ex.get('headline'))}</p>")

    scores = ex.get("scores", {}) if isinstance(ex.get("scores", {}), dict) else {}
    parts.append("<table><tr><th>Score</th><th>Value</th></tr>")
    for k, v in scores.items():
        parts.append(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>")
    parts.append("</table>")

    # Anomalies
    parts.append("<h2>Anomalies</h2>")
    by_sev = an.get("by_severity", {}) if isinstance(an.get("by_severity", {}), dict) else {}
    parts.append("<table><tr><th>Severity</th><th>Count</th></tr>")
    for sev in ("HIGH", "MODERATE", "LOW", "INFORMATIONAL"):
        parts.append(f"<tr><td class='{sev}'>{sev}</td><td>{esc(by_sev.get(sev, 0))}</td></tr>")
    parts.append("</table>")

    if an.get("anomalies"):
        try:
            parts.append("<table><tr><th>Category</th><th>Severity</th><th>Message</th></tr>")
            for a in (an.get("anomalies", []) or [])[:100]:
                if not isinstance(a, dict):
                    continue
                parts.append(
                    f"<tr><td>{esc(a.get('category'))}</td>"
                    f"<td class='{esc(a.get('severity'))}'>{esc(a.get('severity'))}</td>"
                    f"<td>{esc(a.get('message'))}</td></tr>"
                )
            parts.append("</table>")
        except Exception:
            pass

    # Confidence
    parts.append("<h2>Confidence</h2>")
    parts.append("<table><tr><th>Metric</th><th>Score</th></tr>")
    for k in ("data_confidence", "threat_confidence", "geo_confidence", "assessment_confidence"):
        sec = conf.get(k, {}) if isinstance(conf.get(k, {}), dict) else {}
        parts.append(f"<tr><td>{esc(k)}</td><td>{esc(sec.get('score'))}</td></tr>")
    parts.append("</table>")

    # Limitations
    parts.append("<h2>Limitations</h2><ul>")
    try:
        for lim in final_report.get("17_limitations", {}).get("limitations", []) or []:
            parts.append(f"<li>{esc(lim)}</li>")
    except Exception:
        pass
    parts.append("</ul>")

    # Next investigation
    parts.append("<h2>Next Investigation</h2><ul>")
    try:
        for step in final_report.get("18_next_investigation", {}).get("next_investigation", []) or []:
            if not isinstance(step, dict):
                continue
            parts.append(
                f"<li><b>[{esc(step.get('priority'))}]</b> "
                f"{esc(step.get('action'))} \u2014 <i>{esc(step.get('reason'))}</i></li>"
            )
    except Exception:
        pass
    parts.append("</ul>")
    parts.append("<hr><p style='color:#888;font-size:12px;text-align:center'>X7 &bull; X7&Lambda;&dagger;&Xi;X</p>")

    parts.append("</body></html>")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))

    return path


def export_markdown(final_report: Dict[str, Any],
                    config: Dict[str, Any]) -> str:
    """
    Export a Markdown report suitable for wikis and documentation.
    """
    out_dir = _ensure_output_dir(config)
    target = final_report.get("metadata", {}).get("target", "unknown") if isinstance(final_report, dict) else "unknown"
    path = os.path.join(out_dir, _report_filename(target, "md"))

    md = final_report.get("metadata", {}) if isinstance(final_report, dict) else {}
    ex = final_report.get("02_executive_summary", {}) if isinstance(final_report, dict) else {}
    an = final_report.get("14_anomalies", {}) if isinstance(final_report, dict) else {}
    conf = final_report.get("16_confidence", {}) if isinstance(final_report, dict) else {}
    if not isinstance(md, dict):
        md = {}
    if not isinstance(ex, dict):
        ex = {}
    if not isinstance(an, dict):
        an = {}
    if not isinstance(conf, dict):
        conf = {}

    lines = []
    lines.append(f"# ReconIP Intelligence Report \u2014 `{target}`")
    lines.append("")
    lines.append(f"- **Generated:** {md.get('generated_at')}")
    lines.append(f"- **Version:** {md.get('version')}")
    lines.append(f"- **Classification:** {md.get('classification')}")
    lines.append(f"- **Report ID:** {md.get('report_id')}")
    lines.append("")
    lines.append(f"> {md.get('disclaimer')}")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Assessment Confidence:** {ex.get('assessment_confidence')} ({ex.get('assessment_score')})")
    lines.append(f"- **Headline:** {ex.get('headline')}")
    lines.append("")
    lines.append("| Score | Value |")
    lines.append("|-------|-------|")
    try:
        for k, v in (ex.get("scores", {}) or {}).items():
            lines.append(f"| {k} | {v} |")
    except Exception:
        pass
    lines.append("")

    lines.append("## Anomalies")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    try:
        for sev in ("HIGH", "MODERATE", "LOW", "INFORMATIONAL"):
            lines.append(f"| {sev} | {(an.get('by_severity', {}) or {}).get(sev, 0)} |")
    except Exception:
        pass
    lines.append("")

    if an.get("anomalies"):
        lines.append("### Anomaly Details")
        lines.append("")
        lines.append("| Category | Severity | Message |")
        lines.append("|----------|----------|---------|")
        try:
            for a in (an.get("anomalies", []) or [])[:100]:
                if not isinstance(a, dict):
                    continue
                lines.append(f"| {a.get('category')} | {a.get('severity')} | {a.get('message')} |")
        except Exception:
            pass
        lines.append("")

    lines.append("## Confidence")
    lines.append("")
    lines.append("| Metric | Score |")
    lines.append("|--------|-------|")
    for k in ("data_confidence", "threat_confidence", "geo_confidence", "assessment_confidence"):
        try:
            sec = conf.get(k, {}) if isinstance(conf, dict) else {}
            lines.append(f"| {k} | {(sec or {}).get('score')} |")
        except Exception:
            continue
    lines.append("")

    lines.append("## Limitations")
    lines.append("")
    try:
        for lim in final_report.get("17_limitations", {}).get("limitations", []) or []:
            lines.append(f"- {lim}")
    except Exception:
        pass
    lines.append("")

    lines.append("## Next Investigation")
    lines.append("")
    try:
        for step in final_report.get("18_next_investigation", {}).get("next_investigation", []) or []:
            if not isinstance(step, dict):
                continue
            lines.append(f"- **[{step.get('priority')}]** {step.get('action')} \u2014 _{step.get('reason')}_")
    except Exception:
        pass
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("<sub>X7 \u2022 X7\u039b\u2020\u039eX</sub>")
    lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return path


def _stix_uuid() -> str:
    import uuid
    return str(uuid.uuid4())


def export_stix(final_report: Optional[Any] = None,
                config: Optional[Any] = None) -> Any:
    """
    Export a minimal STIX 2.1 bundle (Stage 17) or legacy dict (Stage 14 compat).

    New: export_stix(final_report, config) -> path str (writes file).
    Legacy: export_stix(result) -> dict (returns bundle).
    """
    # Legacy path: single arg, raw recon result with 'ip' and no 'metadata'
    if config is None:
        try:
            if isinstance(final_report, dict) and "metadata" not in final_report:
                return _export_stix_legacy(final_report)
        except Exception:
            pass
        # Fallback: if it looks like final_report but no config, return bundle dict without writing
        try:
            if isinstance(final_report, dict) and "metadata" in final_report:
                target = final_report.get("metadata", {}).get("target", "unknown")
                now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                target_type = "ipv4-addr" if re.match(r"^\d+\.\d+\.\d+\.\d+$", str(target)) else "domain-name"
                return {
                    "type": "bundle",
                    "id": f"bundle--{_stix_uuid()}",
                    "spec_version": "2.1",
                    "objects": [
                        {"type": "identity", "id": f"identity--{_stix_uuid()}", "spec_version": "2.1", "created": now, "modified": now, "name": "ReconIP", "identity_class": "system", "description": "Evidence-driven OSINT platform"},
                        {"type": "indicator", "id": f"indicator--{_stix_uuid()}", "spec_version": "2.1", "created": now, "modified": now, "name": f"Target: {target}", "pattern": f"[{target_type}:value = '{target}']", "pattern_type": "stix", "valid_from": now, "description": final_report.get("02_executive_summary", {}).get("headline", ""), "confidence": 0, "labels": ["reconip", "osint", "assessment"]}
                    ]
                }
        except Exception:
            pass
        return _export_stix_legacy(final_report if isinstance(final_report, dict) else {})
    # New path: (final_report, config) -> write file, return path
    try:
        out_dir = _ensure_output_dir(config if isinstance(config, dict) else {})
        target = final_report.get("metadata", {}).get("target", "unknown") if isinstance(final_report, dict) else "unknown"
        path = os.path.join(out_dir, _report_filename(target, "stix.json"))
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        target_type = "ipv4-addr" if re.match(r"^\d+\.\d+\.\d+\.\d+$", str(target)) else "domain-name"
        try:
            conf_score = float(final_report.get("16_confidence", {}).get("summary", {}).get("assessment", 0) or 0) if isinstance(final_report, dict) else 0.0
        except Exception:
            conf_score = 0.0
        bundle = {
            "type": "bundle",
            "id": f"bundle--{_stix_uuid()}",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "identity",
                    "id": f"identity--{_stix_uuid()}",
                    "spec_version": "2.1",
                    "created": now,
                    "modified": now,
                    "name": "ReconIP",
                    "identity_class": "system",
                    "description": "Evidence-driven OSINT platform"
                },
                {
                    "type": "indicator",
                    "id": f"indicator--{_stix_uuid()}",
                    "spec_version": "2.1",
                    "created": now,
                    "modified": now,
                    "name": f"Target: {target}",
                    "pattern": f"[{target_type}:value = '{target}']",
                    "pattern_type": "stix",
                    "valid_from": now,
                    "description": final_report.get("02_executive_summary", {}).get("headline", "") if isinstance(final_report, dict) else "",
                    "confidence": int(conf_score * 100),
                    "labels": ["reconip", "osint", "assessment"]
                }
            ]
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, default=str, ensure_ascii=False)
        return path
    except Exception as e:
        raise e


def export_misp(final_report: Optional[Any] = None,
                config: Optional[Any] = None) -> Any:
    """
    Export a minimal MISP event JSON (Stage 17) or legacy dict (Stage 14 compat).

    New: export_misp(final_report, config) -> path str (writes file).
    Legacy: export_misp(result) -> dict (returns Event).
    """
    if config is None:
        try:
            if isinstance(final_report, dict) and "metadata" not in final_report:
                return _export_misp_legacy(final_report)
        except Exception:
            pass
        try:
            if isinstance(final_report, dict) and "metadata" in final_report:
                target = final_report.get("metadata", {}).get("target", "unknown")
                now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                target_type = "ip-src" if re.match(r"^\d+\.\d+\.\d+\.\d+$", str(target)) else "domain"
                return {"Event": {"info": f"ReconIP assessment for {target}", "date": now.split("T")[0], "timestamp": now, "published": False, "analysis": "1", "threat_level_id": "4", "distribution": "0", "Attribute": [{"type": target_type, "value": target, "category": "Network activity", "to_ids": False, "comment": "ReconIP target"}], "Tag": [{"name": "reconip:assessment"}, {"name": "reconip:evidence-driven"}]}}
        except Exception:
            pass
        return _export_misp_legacy(final_report if isinstance(final_report, dict) else {})
    try:
        out_dir = _ensure_output_dir(config if isinstance(config, dict) else {})
        target = final_report.get("metadata", {}).get("target", "unknown") if isinstance(final_report, dict) else "unknown"
        path = os.path.join(out_dir, _report_filename(target, "misp.json"))
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        attributes: List[Dict[str, Any]] = []
        target_type = "ip-src" if re.match(r"^\d+\.\d+\.\d+\.\d+$", str(target)) else "domain"
        attributes.append({
            "type": target_type,
            "value": target,
            "category": "Network activity",
            "to_ids": False,
            "comment": "ReconIP target"
        })
        try:
            for c in final_report.get("13_vulnerability_candidates", {}).get("candidates", []) or []:
                if not isinstance(c, dict):
                    continue
                attributes.append({
                    "type": "vulnerability",
                    "value": c.get("cve"),
                    "category": "External analysis",
                    "to_ids": False,
                    "comment": f"CANDIDATE \u2014 {c.get('cpe')} \u2014 requires validation"
                })
        except Exception:
            pass
        event = {
            "Event": {
                "info": f"ReconIP assessment for {target}",
                "date": now.split("T")[0],
                "timestamp": now,
                "published": False,
                "analysis": "1",
                "threat_level_id": "4",
                "distribution": "0",
                "Attribute": attributes,
                "Tag": [
                    {"name": "reconip:assessment"},
                    {"name": "reconip:evidence-driven"}
                ]
            }
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(event, f, indent=2, default=str, ensure_ascii=False)
        return path
    except Exception as e:
        raise e


def export_all(final_report: Dict[str, Any],
               config: Dict[str, Any]) -> Dict[str, str]:
    """
    Export the final report in all configured formats.
    Returns a dict of {format: path}.
    """
    try:
        reports_cfg = config.get("reports", {}) if isinstance(config, dict) else {}
    except Exception:
        reports_cfg = {}
    formats = reports_cfg.get("formats", ["json", "html", "markdown", "csv", "stix", "misp"]) if isinstance(reports_cfg, dict) else ["json", "html", "markdown", "csv", "stix", "misp"]

    exporters = {
        "json":     export_json,
        "csv":      export_csv,
        "html":     export_html,
        "markdown": export_markdown,
        "stix":     export_stix,
        "misp":     export_misp,
    }

    paths: Dict[str, str] = {}
    for fmt in formats:
        fn = exporters.get(fmt)
        if not fn:
            continue
        try:
            paths[fmt] = fn(final_report, config)
        except Exception as e:
            paths[fmt] = f"ERROR: {e}"
    return paths


# ============================================================
#  BATCH INTELLIGENCE — v42.1 (Stage 18)
#  Multi-target orchestration with isolation + correlation.
#  Each target processed in isolation. Failure never propagates.
# ============================================================
_SQLITE_LOCK: Optional[threading.Lock] = None


def _install_sqlite_lock(lock: threading.Lock) -> None:
    """
    Install a global lock used by snapshot writes.
    """
    global _SQLITE_LOCK
    _SQLITE_LOCK = lock


def _get_sqlite_lock() -> threading.Lock:
    global _SQLITE_LOCK
    if _SQLITE_LOCK is None:
        _SQLITE_LOCK = threading.Lock()
    return _SQLITE_LOCK


def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    """
    Load config from file merged over DEFAULTS.
    Returns a fresh dict (safe to mutate per-target).
    """
    try:
        file_cfg = load_cfg(path) if callable(globals().get("load_cfg")) else {}
    except Exception:
        file_cfg = {}
    try:
        base = json.loads(json.dumps(DEFAULTS))
    except Exception:
        base = {}
    try:
        return deep_merge(base, file_cfg or {})
    except Exception:
        return base


# ============================================================
#  SECURITY RESEARCH MODE — v44 (Stage 21)
#  Named execution profiles: quick / standard / deep / forensic.
#  A profile is an override, not a rewrite. Base config is never mutated.
# ============================================================
# Canonical profile names. Do not add new names without updating docs.
KNOWN_PROFILES = ["quick", "standard", "deep", "forensic"]

# Mapping from profile keys to config paths.
# Each entry: profile_key -> (config_section, config_key, transform)
PROFILE_KEY_MAP = {
    "dns":               ("dns", "enabled", bool),
    "whois":             ("infrastructure", "enabled", bool),
    "ct":                ("certificate", "enabled", bool),
    "passive_dns":       ("passive_dns", "enabled", bool),
    "history":           ("history", "enabled", bool),
    "anomaly":           ("anomaly", "enabled", bool),
    "attack_surface":    ("attack_surface", "enabled", bool),
    "technology":        ("fingerprinting", "enabled", bool),
    "vulnerability":     ("vulnerability", "enabled", bool),
    "correlation":       ("correlation", "enabled", bool),
    "confidence":        ("confidence", "enabled", bool),
    "scoring":           ("scoring", "enabled", bool),
    "timeline":          ("passive_dns", "timeline", bool),
    "provider_comparison": ("threat_intelligence", "include_normalized", bool),
}


def load_profile(name: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Load a profile definition by name.

    Rules:
      - Name must be a known profile.
      - Unknown profile raises ValueError (fail loudly).
      - Returns the profile dict (empty dict if profile has no overrides).
    """
    if not name:
        raise ValueError("Profile name is empty.")

    profiles = config.get("profiles", {}) if isinstance(config, dict) else {}
    if not isinstance(profiles, dict):
        profiles = {}
    if name not in profiles:
        raise ValueError(
            f"Unknown profile '{name}'. "
            f"Available: {sorted(profiles.keys())}"
        )

    profile = profiles[name] or {}
    if not isinstance(profile, dict):
        raise ValueError(f"Profile '{name}' must be a mapping.")

    # Attach the name for reporting
    profile = dict(profile)
    profile["_name"] = name
    return profile


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> None:
    """
    Recursive merge of override into base (mutates base).
    """
    for k, v in (override or {}).items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


def apply_profile(profile: Dict[str, Any],
                  base_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply a profile as an override on top of the base config.

    Returns a NEW config dict (deep copy). The base config is never mutated.
    """
    # Deep copy so nothing leaks back
    try:
        new_config: Dict[str, Any] = json.loads(json.dumps(base_config))
    except Exception:
        new_config = dict(base_config) if isinstance(base_config, dict) else {}
    if not isinstance(profile, dict):
        profile = {}

    # 1. Providers
    providers_spec = profile.get("providers")
    if providers_spec is not None:
        all_providers = new_config.setdefault("providers", {})
        if not isinstance(all_providers, dict):
            all_providers = {}
            new_config["providers"] = all_providers
        if providers_spec == "all":
            for pname in all_providers:
                try:
                    all_providers[pname]["enabled"] = True
                except Exception:
                    all_providers[pname] = {"enabled": True}
        elif isinstance(providers_spec, list):
            for pname in all_providers:
                try:
                    all_providers[pname]["enabled"] = pname in providers_spec
                except Exception:
                    continue
        else:
            raise ValueError(
                f"Profile '{profile.get('_name')}' has invalid 'providers' value: "
                f"{providers_spec!r}. Must be 'all' or a list."
            )

    # 2. Section toggles
    for pkey, (section, key, transform) in PROFILE_KEY_MAP.items():
        if pkey in profile:
            value = profile[pkey]
            try:
                value = transform(value)
            except Exception as e:
                raise ValueError(
                    f"Profile '{profile.get('_name')}' has invalid value "
                    f"for '{pkey}': {value!r} ({e})"
                )
            try:
                sec = new_config.setdefault(section, {})
                if not isinstance(sec, dict):
                    sec = {}
                    new_config[section] = sec
                sec[key] = value
            except Exception as e:
                raise ValueError(
                    f"Profile '{profile.get('_name')}' cannot set "
                    f"'{section}.{key}': {e}"
                )

    # 3. Nested sections (deep merge)
    for section in (
        "performance",
        "cache",
        "reports",
        "evidence",
        "anomaly",
        "history",
        "attack_surface",
        "fingerprinting",
        "vulnerability",
        "dns",
        "certificate",
        "passive_dns",
        "threat_intelligence",
        "confidence",
        "scoring",
        "correlation",
        "infrastructure",
    ):
        if section in profile and isinstance(profile[section], dict):
            try:
                sec = new_config.setdefault(section, {})
                if not isinstance(sec, dict):
                    sec = {}
                    new_config[section] = sec
                _deep_merge(sec, profile[section])
            except Exception:
                continue

    # 4. Record the applied profile for reporting
    new_config["_applied_profile"] = {
        "name": profile.get("_name", "custom"),
        "description": profile.get("description", ""),
    }

    return new_config


def resolve_effective_config(config: Dict[str, Any],
                             cli_profile: Optional[str]) -> Dict[str, Any]:
    """
    Determine which profile to use and return the effective config.

    Precedence:
      1. CLI --profile
      2. config.default_profile
      3. No profile (base config)
    """
    try:
        profile_name = cli_profile or (config.get("default_profile") if isinstance(config, dict) else None)
    except Exception:
        profile_name = cli_profile

    if not profile_name:
        # No profile requested; return base config untouched (as a fresh copy)
        try:
            new_config = json.loads(json.dumps(config))
        except Exception:
            new_config = dict(config) if isinstance(config, dict) else {}
        new_config["_applied_profile"] = {"name": None, "description": "base config"}
        return new_config

    profile = load_profile(profile_name, config)
    return apply_profile(profile, config)


def _sync_global_config(effective: Dict[str, Any]) -> None:
    """
    Sync an effective (profile-resolved) config into the module-global
    CFG and its derived section globals, so the recon() pipeline — which
    reads globals — executes under the profile. The base config object
    passed to apply_profile() is never mutated (apply works on a copy).
    """
    global CFG, PB, PC, PD, PE, PF, PG, PH, PI, PJ, PK, PM, PN, CACHE
    if not isinstance(effective, dict):
        return
    try:
        CFG.clear()
        CFG.update(effective)
    except Exception:
        return
    try:
        PB, PC, PD, PE, PF, PG, PH, PI, PJ, PK = (CFG[k] for k in
            ("phase_b", "phase_c", "phase_d", "phase_e", "phase_f",
             "phase_g", "phase_h", "phase_i", "phase_j", "phase_k"))
        PM, PN = CFG["phase_m"], CFG["phase_n"]
    except Exception:
        pass
    # Honor cache.enabled for the shared HTTP cache (forensic queries live).
    try:
        cache_cfg = CFG.get("cache", {}) if isinstance(CFG, dict) else {}
        if isinstance(cache_cfg, dict) and not cache_cfg.get("enabled", True):
            CACHE = None
        else:
            try:
                pd_cfg = CFG.get("phase_d", {}) if isinstance(CFG, dict) else {}
                cache_cfg_pd = pd_cfg.get("cache", {}) if isinstance(pd_cfg, dict) else {}
                if cache_cfg_pd.get("enabled", True):
                    CACHE = Cache(cache_cfg_pd.get("db_path", "./reconip_cache.db"))
                else:
                    CACHE = None
            except Exception:
                pass
    except Exception:
        pass


def _is_valid_target(target: str) -> bool:
    """
    Validate that a target is a valid IP address or domain.
    """
    if not target or not isinstance(target, str):
        return False
    t = target.strip()
    if not t:
        return False
    # IP
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        pass
    # CIDR (rejected for now — batch operates on single hosts)
    if "/" in t:
        return False
    # Domain
    if len(t) > 253:
        return False
    if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$", t):
        return False
    return True


def _read_targets_file(path: str, config: Dict[str, Any]) -> List[str]:
    """
    Read targets from a file, one per line.
    """
    try:
        batch_cfg = config.get("batch", {}) if isinstance(config, dict) else {}
    except Exception:
        batch_cfg = {}
    max_lines = batch_cfg.get("max_targets", 1000) if isinstance(batch_cfg, dict) else 1000
    try:
        max_lines = int(max_lines)
    except Exception:
        max_lines = 1000

    if not os.path.isfile(path):
        logging.error(f"Input file not found: {path}")
        return []

    lines: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    logging.warning(
                        f"Input file exceeds max_targets={max_lines}. Truncating."
                    )
                    break
                lines.append(line.rstrip("\n"))
    except Exception as e:
        logging.error(f"Failed to read input file {path}: {e}")
        return []

    return lines


def load_targets(cli_targets: Optional[List[str]],
                 input_file: Optional[str],
                 config: Dict[str, Any]) -> List[str]:
    """
    Load, validate, and deduplicate targets from CLI args and/or a file.

    Rules:
      - Comments (#) and blank lines are ignored.
      - Trailing/leading whitespace is stripped.
      - Duplicates are removed, preserving first-seen order.
      - Invalid targets are skipped with a warning.
    """
    raw: List[str] = []

    # CLI targets
    if cli_targets:
        try:
            raw.extend(list(cli_targets))
        except Exception:
            pass

    # File targets
    if input_file:
        try:
            raw.extend(_read_targets_file(input_file, config))
        except Exception as e:
            logging.error(f"Failed to load file targets: {e}")

    # Normalize + deduplicate
    seen = set()
    unique: List[str] = []
    for t in raw:
        try:
            t = (t or "").strip()
        except Exception:
            continue
        if not t:
            continue
        if t.startswith("#"):
            continue
        # Strip inline comments
        if " #" in t:
            t = t.split(" #", 1)[0].strip()
        if not t:
            continue
        if t in seen:
            continue
        seen.add(t)
        unique.append(t)

    # Validate
    valid: List[str] = []
    for t in unique:
        try:
            if _is_valid_target(t):
                valid.append(t)
            else:
                logging.warning(f"Skipping invalid target: {t}")
        except Exception:
            logging.warning(f"Skipping invalid target: {t}")

    return valid


def build_parser() -> argparse.ArgumentParser:
    """
    Build the CLI argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="reconip",
        description="ReconIP \u2014 evidence-driven OSINT platform",
        epilog="Example: python3 reconip.py 8.8.8.8 1.1.1.1"
    )

    # Targets
    parser.add_argument(
        "targets",
        nargs="*",
        help="One or more IP addresses or domains."
    )
    parser.add_argument(
        "--input", "-i",
        metavar="FILE",
        default=None,
        help="File containing targets, one per line."
    )

    # Batch control
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=None,
        help="Max parallel workers for batch mode. Default: from config."
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Force batch mode even for a single target."
    )
    parser.add_argument(
        "--no-correlate",
        action="store_true",
        help="Skip cross-target correlation in batch mode."
    )

    # Output
    parser.add_argument(
        "--format",
        choices=["json", "html", "markdown", "csv", "stix", "misp", "all"],
        default=None,
        help="Output format. Default: from config."
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Override report output directory."
    )

    # Verbosity
    parser.add_argument("--quiet", "-q", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--debug", action="store_true")

    # Behavior
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--provider", default=None, help="Comma-separated provider list.")
    parser.add_argument("--profile", choices=KNOWN_PROFILES, default=None,
                        help="Execution profile: quick, standard, deep, forensic.")
    parser.add_argument(
        "--test-providers",
        action="store_true",
        help="Test all enabled providers against a target without running a full scan."
    )
    parser.add_argument(
        "--show-auth",
        action="store_true",
        help="Print the authentication state of every provider and exit."
    )
    parser.add_argument(
        "--list-providers",
        action="store_true",
        help="List all providers with their enabled state and remediation path."
    )
    parser.add_argument(
        "--no-display",
        action="store_true",
        help="Generate reports without rendering to the terminal."
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable the progress indicator."
    )

    # Legacy single-target / system flags (preserved for backward compat)
    parser.add_argument("-o", "--output", choices=["text", "json"], default="text")
    parser.add_argument("--parallel", action="store_true",
                        help="Parallel collection (faster)")
    parser.add_argument("--report", choices=["txt", "json", "html"], default=None)
    parser.add_argument("--report-file", metavar="PATH", default=None)
    parser.add_argument("--export", choices=["stix", "misp"], default=None)
    parser.add_argument("--api", action="store_true")
    parser.add_argument("--api-host", default=None)
    parser.add_argument("--api-port", type=int, default=None)
    parser.add_argument("--metrics", action="store_true")
    parser.add_argument("--health", action="store_true")
    parser.add_argument("--allow-private", action="store_true")
    parser.add_argument("--no-db", action="store_true")
    parser.add_argument("--timeout", type=int, default=None)

    # Version
    parser.add_argument("--version", action="version", version="ReconIP v42.1")

    return parser


def _deep_copy_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep copy config to prevent cross-target state leakage.
    Uses JSON round-trip (config must be JSON-serializable).
    """
    try:
        return json.loads(json.dumps(config))
    except Exception:
        # Fallback shallow-ish copy
        try:
            import copy as _copy
            return _copy.deepcopy(config)
        except Exception:
            return dict(config) if isinstance(config, dict) else {}


def _apply_cli_overrides(config: Dict[str, Any],
                         args: argparse.Namespace) -> None:
    """
    Apply CLI overrides to the local config copy.
    """
    try:
        if getattr(args, "output_dir", None):
            config.setdefault("reports", {})["output_dir"] = args.output_dir
        fmt = getattr(args, "format", None)
        if fmt and fmt != "all":
            config.setdefault("reports", {})["formats"] = [fmt]
        if fmt == "all":
            config.setdefault("reports", {})["formats"] = ["json", "html", "markdown", "csv", "stix", "misp"]
        provider = getattr(args, "provider", None)
        if provider:
            enabled = [p.strip() for p in provider.split(",") if p.strip()]
            provs = config.get("providers", {})
            if isinstance(provs, dict):
                for name in provs:
                    try:
                        provs[name]["enabled"] = name in enabled
                    except Exception:
                        continue
        if getattr(args, "no_cache", False):
            config.setdefault("cache", {})["enabled"] = False
    except Exception:
        pass


def _process_single_target(target: str,
                           config: Dict[str, Any],
                           args: argparse.Namespace,
                           progress=None) -> Dict[str, Any]:
    """
    Process a single target end-to-end.

    This function:
      - Does NOT mutate shared state.
      - Does NOT depend on other targets.
      - Returns a full report dict, or an error dict.
    Delegates to the existing single-target pipeline (recon) to avoid
    duplication and guarantee parity with single-target workflow.

    progress: optional _NoopProgress/_RichProgress handle (Stage C1).
      Defaults to a silent no-op; never affects results.
    """
    try:
        try:
            progress = progress or _NoopProgress()
        except Exception:
            progress = _NoopProgress()
        # Per-target config copy (avoid cross-target leakage)
        try:
            local_config = _deep_copy_config(config)
        except Exception:
            local_config = config
        try:
            _apply_cli_overrides(local_config, args)
        except Exception:
            pass

        # Run the existing pipeline stages in order via recon().
        # recon() internally runs DNS, infra, cert, pdns, threat,
        # attack surface, technology, vuln, correlation, history,
        # anomaly, confidence, scoring, final report + export.
        # Use local output_dir/formats if overridden by re-exporting.
        report = recon(target, enable_db=not bool(getattr(args, "no_db", False)),
                       progress=progress)

        if not isinstance(report, dict):
            return {"target": target, "error": "empty report", "status": "FAILED"}
        if report.get("error") and not report.get("ip"):
            # recon returns {"input":..,"error":..} on validation/resolve failure
            return {"target": target, "error": report.get("error"), "status": "FAILED"}
        # Ensure target key present
        report.setdefault("target", target)
        # If CLI overrides changed export config, re-export with local config
        try:
            global_cfg_reports = (config.get("reports", {}) if isinstance(config, dict) else {})
            local_reports = (local_config.get("reports", {}) if isinstance(local_config, dict) else {})
            if local_reports != global_cfg_reports and report.get("final_report"):
                try:
                    re_paths = export_all(report["final_report"], local_config)
                    # Merge: keep original paths, add/override with re-exported
                    existing = report.get("export_paths", {})
                    if isinstance(existing, dict):
                        existing.update(re_paths)
                        report["export_paths"] = existing
                    else:
                        report["export_paths"] = re_paths
                except Exception:
                    pass
        except Exception:
            pass
        return report

    except Exception as e:
        logging.exception(f"Target {target} failed: {e}")
        return {
            "target": target,
            "error": str(e),
            "status": "FAILED"
        }


def _log_batch_progress(current: int, total: int,
                        target: str, config: Dict[str, Any]) -> None:
    try:
        batch_cfg = config.get("batch", {}) if isinstance(config, dict) else {}
    except Exception:
        batch_cfg = {}
    if isinstance(batch_cfg, dict) and batch_cfg.get("quiet", False):
        return
    try:
        from rich.console import Console
        console = Console()
        console.log(f"[{current}/{total}] Processing {target}")
    except Exception:
        logging.info(f"[{current}/{total}] Processing {target}")


def batch_process(targets: List[str],
                  config: Dict[str, Any],
                  args: argparse.Namespace,
                  workers: int = 1,
                  progress=None) -> Dict[str, Any]:
    """
    Process multiple targets.

    progress: optional progress handle forwarded to each target (Stage C1).
      Defaults to a silent no-op; never affects results.

    Returns:
    {
        "targets": [...],
        "results": {target: report_or_error},
        "stats": {...}
    }
    """
    try:
        progress = progress or _NoopProgress()
    except Exception:
        progress = _NoopProgress()
    results: Dict[str, Any] = {}
    started = datetime.now(timezone.utc)

    # SQLite snapshot writes must be serialized
    try:
        db_lock = threading.Lock()
        _install_sqlite_lock(db_lock)
    except Exception:
        pass

    try:
        workers = int(workers)
    except Exception:
        workers = 1
    if workers < 1:
        workers = 1

    if workers <= 1 or len(targets) <= 1:
        # Sequential
        for i, target in enumerate(targets, 1):
            try:
                _log_batch_progress(i, len(targets), target, config)
            except Exception:
                pass
            try:
                progress.update(f"[{i}/{len(targets)}] {target}")
            except Exception:
                pass
            try:
                results[target] = _process_single_target(target, config, args,
                                                         progress=progress)
            except Exception as e:
                logging.exception(f"Target {target} raised: {e}")
                results[target] = {"target": target, "error": str(e), "status": "FAILED"}
    else:
        # Parallel
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_target = {
                executor.submit(_process_single_target, t, config, args, progress): t
                for t in targets
            }
            completed = 0
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                completed += 1
                try:
                    _log_batch_progress(completed, len(targets), target, config)
                except Exception:
                    pass
                try:
                    results[target] = future.result()
                except Exception as e:
                    logging.exception(f"Target {target} raised: {e}")
                    results[target] = {
                        "target": target,
                        "error": str(e),
                        "status": "FAILED"
                    }

    # Finalize
    ended = datetime.now(timezone.utc)
    try:
        duration = (ended - started).total_seconds()
    except Exception:
        duration = 0.0

    ok = sum(1 for r in results.values() if isinstance(r, dict) and r.get("status") != "FAILED")
    failed = len(results) - ok

    return {
        "targets": list(targets),
        "results": results,
        "stats": {
            "total": len(targets),
            "ok": ok,
            "failed": failed,
            "duration_seconds": round(duration, 2),
            "workers": workers,
            "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ended_at": ended.strftime("%Y-%m-%dT%H:%M:%SZ")
        }
    }


def batch_correlate(batch_result: Dict[str, Any],
                    config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run cross-target correlation across all successful targets.
    """
    try:
        batch_cfg = config.get("batch", {}) if isinstance(config, dict) else {}
    except Exception:
        batch_cfg = {}
    if isinstance(batch_cfg, dict) and not batch_cfg.get("correlate", True):
        return {"enabled": False}

    targets = []
    reports = []
    try:
        for target, report in (batch_result.get("results", {}) or {}).items():
            if not isinstance(report, dict):
                continue
            if report.get("status") == "FAILED":
                continue
            targets.append(target)
            reports.append(report)
    except Exception:
        return {"enabled": False, "error": "invalid batch result"}

    if len(targets) < 2:
        return {
            "enabled": True,
            "status": "INSUFFICIENT_TARGETS",
            "message": "At least 2 successful targets are required for cross-target correlation.",
            "related_targets": []
        }

    try:
        correlation = correlate(reports, targets, config)
        if not isinstance(correlation, dict):
            correlation = {"enabled": True}
        correlation["status"] = "OK"
        return correlation
    except Exception as e:
        logging.exception(f"batch correlate failed: {e}")
        return {"enabled": True, "status": "ERROR", "error": str(e), "related_targets": []}


def batch_summary_report(batch_result: Dict[str, Any],
                         batch_corr: Dict[str, Any],
                         config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a batch summary report.
    """
    stats = batch_result.get("stats", {}) if isinstance(batch_result, dict) else {}
    results = batch_result.get("results", {}) if isinstance(batch_result, dict) else {}
    if not isinstance(batch_corr, dict):
        batch_corr = {}

    # Aggregate scores
    scores_agg = {
        "threat": [],
        "infrastructure": [],
        "data_quality": [],
        "exposure": [],
        "anomaly": [],
        "coverage": []
    }
    top_anomalies: List[Dict[str, Any]] = []
    failed_targets: List[str] = []
    ok_targets: List[str] = []

    for target, report in results.items():
        try:
            if not isinstance(report, dict) or report.get("status") == "FAILED":
                failed_targets.append(target)
                continue
            ok_targets.append(target)

            scoring = report.get("intelligence_scoring", {}).get("summary", {}) if isinstance(report.get("intelligence_scoring", {}), dict) else {}
            if not isinstance(scoring, dict):
                scoring = {}
            for k in scores_agg:
                v = scoring.get(k)
                if isinstance(v, (int, float)):
                    scores_agg[k].append(float(v))

            anomaly = report.get("anomaly_intelligence", {}) if isinstance(report.get("anomaly_intelligence", {}), dict) else {}
            for a in anomaly.get("anomalies", []) or []:
                if not isinstance(a, dict):
                    continue
                if a.get("severity") in ("HIGH", "MODERATE"):
                    top_anomalies.append({
                        "target": target,
                        "category": a.get("category"),
                        "subtype": a.get("subtype"),
                        "severity": a.get("severity"),
                        "message": a.get("message")
                    })
        except Exception:
            continue

    def _avg(lst):
        try:
            return round(sum(lst) / len(lst), 2) if lst else 0.0
        except Exception:
            return 0.0

    try:
        version = config.get("version", "v42.1") if isinstance(config, dict) else "v42.1"
    except Exception:
        version = "v42.1"

    try:
        shared = batch_corr.get("shared", {}) if isinstance(batch_corr.get("shared", {}), dict) else {}
    except Exception:
        shared = {}

    def _slen(key):
        try:
            return len(shared.get(key, []) or [])
        except Exception:
            return 0

    return {
        "metadata": {
            "tool": "ReconIP",
            "version": version,
            "type": "batch_summary",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        },
        "stats": stats,
        "targets_ok": ok_targets,
        "targets_failed": failed_targets,
        "aggregate_scores": {
            "threat": _avg(scores_agg["threat"]),
            "infrastructure": _avg(scores_agg["infrastructure"]),
            "data_quality": _avg(scores_agg["data_quality"]),
            "exposure": _avg(scores_agg["exposure"]),
            "anomaly": _avg(scores_agg["anomaly"]),
            "coverage": _avg(scores_agg["coverage"])
        },
        "top_anomalies": sorted(top_anomalies,
                                key=lambda x: {"HIGH": 0, "MODERATE": 1}.get(x.get("severity"), 2))[:50],
        "cross_target_correlation": {
            "status": batch_corr.get("status"),
            "shared_asns": _slen("shared_asns"),
            "shared_prefixes": _slen("shared_prefixes"),
            "shared_certificates": _slen("shared_certificates"),
            "shared_nameservers": _slen("shared_nameservers"),
            "related_targets": batch_corr.get("related_targets", [])
        },
        "notes": [
            "A shared relationship across targets is not shared intent.",
            "Batch summaries aggregate scores \u2014 always read per-target reports for detail.",
            "Failed targets are listed explicitly. Their absence is not absence of findings."
        ]
    }


def export_batch_summary(summary: Dict[str, Any],
                         config: Dict[str, Any]) -> str:
    out_dir = _ensure_output_dir(config)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(out_dir, f"batch_summary_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str, ensure_ascii=False)
    return path


# ============================================================
#  RECON (MAIN FLOW) — v21.3 with Phase 2
# ============================================================
def recon(target, enable_db=True, parallel=None, progress=None):
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

    # Live progress (Stage C1): additive markers only, never logic.
    try:
        progress = progress or _NoopProgress()
    except Exception:
        progress = _NoopProgress()
    progress.start("01/13 DNS Intelligence")

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

    # Stage 5: DNS Intelligence Engine — v33
    try:
        # Use dns_collect (new) and merge with existing dns_evs for comprehensive analysis
        dns_evidences_v5 = dns_collect(target, CFG)
        # Merge with existing dns_evs (deduplicate by record_type+normalized_value)
        combined_dns_evs = list(dns_evs)
        existing_keys = {(getattr(e, 'metadata', {}).get("record_type"), getattr(e, 'normalized_value', None)) for e in dns_evs if hasattr(e, 'metadata')}
        for ev in dns_evidences_v5:
            key = (ev.metadata.get("record_type"), ev.normalized_value)
            if key not in existing_keys:
                combined_dns_evs.append(ev)
                existing_keys.add(key)
        # Deterministic ordering (v48.1): upstream DNS answers may arrive
        # in varying order (round-robin). Sort so consecutive runs are
        # structurally identical. Score-neutral: analysis uses multisets.
        try:
            combined_dns_evs.sort(key=lambda e: (
                str((getattr(e, "metadata", {}) or {}).get("record_type", "")),
                str(getattr(e, "normalized_value", "") or ""),
                str(getattr(e, "source", "") or ""),
                str(getattr(e, "provider", "") or ""),
                str(getattr(e, "value", "") or ""),
            ))
        except Exception:
            pass
        dns_intel = dns_analyze(combined_dns_evs, CFG)
        out["dns_intelligence"] = {
            "evidence": [ev.to_dict() for ev in combined_dns_evs],
            "analysis": dns_intel
        }
        out["dns_collect_evidence"] = [ev.to_dict() for ev in dns_evidences_v5]
        # Also extend evs with any new DNS evidences for downstream scoring
        for ev in dns_evidences_v5:
            if ev not in evs:
                evs.append(ev)
    except Exception as e:
        log.debug(f"dns intelligence: {e}")
        out["dns_intelligence"] = {"evidence": [], "analysis": {}}
        out["dns_collect_evidence"] = []

    cert_evs, cert_st, cert_ci = cert_res if len(cert_res) == 3 \
        else ([], MS.SKIPPED.value, {"records": {}})
    evs += cert_evs
    out["module_statuses"]["cert"] = cert_st

    threat_obs, threat_st = threat_res if len(threat_res) == 2 \
        else ([], MS.SKIPPED.value)
    progress.next("02/13 Threat Intelligence")
    threat_agg = agg_threat(threat_obs)
    evs += threat_evs(ip, threat_obs)
    out["module_statuses"]["threat"] = threat_st
    out["phase_i"] = threat_agg

    # Stage 3: Source Reliability Engine — run new providers (v32) with reliability/weight
    stage3_threat_evs: List[Evidence] = []
    try:
        cfg_providers = load_providers(CFG)
        try:
            _set_providers_registry(cfg_providers)
        except Exception:
            pass
        auth_info = load_api_keys(cfg_providers, CFG)
        # NOTE (C3.6): no _log_auth_summary() here. main() emits it once,
        # inside the progress context (or via plain logging when inactive).
        stage3_threat_evs = run_providers(ip, cfg_providers)
        # Keep for evidence_engine; also optionally extend evs for legacy scoring (as Ev)
        # Convert to Ev for downstream if needed, but keep separate to avoid double count
        out["stage3_threat_evidences"] = [e.to_dict() for e in stage3_threat_evs]
    except Exception as e:
        log.debug(f"stage3 providers: {e}")
        stage3_threat_evs = []
        out["stage3_threat_evidences"] = []

    # Stage 4: Threat Intelligence Engine 2.0 — normalize, detect failures, compute confidence (v32.1)
    try:
        # Deduplicate by source — prefer OK over FAILED/NOT_CONFIGURED (Stage 4)
        raw_map: Dict[str, Dict[str, Any]] = {}
        for o in threat_obs:
            src = getattr(o, 'provider', 'unknown')
            st = getattr(o, 'status', 'FAILED')
            # Stage 4: map Obs freshness — OK with recent success = FRESH
            fresh = "FRESH" if st in (TS2.POSITIVE, TS.NO_THREAT.value, TS.NO_DATA.value) else "UNKNOWN"
            raw_map[src] = {
                "source": src,
                "threat_score": getattr(o, 'score', None),
                "tags": getattr(o, 'categories', []),
                "first_seen": getattr(o, 'first_seen', None),
                "last_seen": getattr(o, 'last_seen', None),
                "evidence": str(getattr(o, 'error', '') or ''),
                "status": st,
                "confidence": (getattr(o, 'confidence', 50) / 100.0) if getattr(o, 'confidence', None) else 0.5,
                "reliability": getattr(o, 'reliability', 0.5),
                "weight": getattr(o, 'weight', 1.0),
                "latency": None,
                "freshness": fresh
            }
        for ev in stage3_threat_evs:
            d = ev.to_dict()
            meta = d.get("metadata", {}) or {}
            src = d.get("source", "unknown")
            new_entry = {
                "source": src,
                "threat_score": d.get("value"),
                "tags": meta.get("tags", []),
                "first_seen": meta.get("first_seen"),
                "last_seen": meta.get("last_seen"),
                "evidence": meta.get("evidence", ""),
                "status": d.get("status", "FAILED"),
                "confidence": d.get("confidence", 0.5),
                "reliability": meta.get("reliability", 0.5),
                "weight": meta.get("weight", 1.0),
                "latency": meta.get("latency"),
                "freshness": d.get("freshness", "UNKNOWN")
            }
            # Prefer OK over non-OK; if both same status, keep higher confidence
            existing = raw_map.get(src)
            if existing is None:
                raw_map[src] = new_entry
            else:
                # Prefer OK
                if existing.get("status") != "OK" and new_entry.get("status") == "OK":
                    raw_map[src] = new_entry
                elif existing.get("status") == "OK" and new_entry.get("status") != "OK":
                    pass  # keep existing OK
                else:
                    # Both same status, keep higher confidence
                    if new_entry.get("confidence", 0) > existing.get("confidence", 0):
                        raw_map[src] = new_entry
        raw_results = list(raw_map.values())
        threat_aggregate = aggregate(raw_results, CFG)
        out["threat_intelligence"] = {
            "observed_threat_score": threat_aggregate["metrics"]["observed_threat_score"],
            "evidence_coverage": threat_aggregate["metrics"]["evidence_coverage"],
            "provider_agreement": threat_aggregate["metrics"]["provider_agreement"],
            "data_freshness": threat_aggregate["metrics"]["data_freshness"],
            "threat_confidence": threat_aggregate["metrics"]["threat_confidence"],
            "provider_count": threat_aggregate["metrics"]["provider_count"],
            "ok_count": threat_aggregate["metrics"]["ok_count"],
            "failed_count": threat_aggregate["metrics"]["failed_count"],
            "not_configured_count": threat_aggregate["metrics"]["not_configured_count"],
            "failures": threat_aggregate["failures"],
            "normalized": threat_aggregate["normalized"],
            "summary": threat_aggregate["summary"]
        }
        # Data confidence separate (from Evidence) — Stage 4
        try:
            all_evidences: List[Evidence] = []
            for e in evs:
                if isinstance(e, Evidence):
                    all_evidences.append(e)
                elif isinstance(e, Ev):
                    all_evidences.append(ev_to_evidence(e))
            all_evidences.extend(stage3_threat_evs)
            out["data_confidence"] = data_confidence_evidence(all_evidences)
        except Exception:
            out["data_confidence"] = 0.0
    except Exception as e:
        log.debug(f"stage4 aggregate: {e}")
        out["threat_intelligence"] = {}
        out["data_confidence"] = 0.0

    out["scan_status"] = agg_scan_status(out["module_statuses"])
    anycast = ip in CFG["geo_validation"]["anycast_ips"]
    cs = conflict_report(evs, anycast=anycast)
    trusted = build_trusted(evs, cs, anycast)

    threat_dim = threat_score([e for e in evs if e.data_type == "threat"],
                              phase_i=threat_agg)
    infra_dim = infra_risk(ip, trusted, evs)
    dc = _data_confidence_legacy(evs, trusted, cs, None)
    cov = coverage({}, phase_i=threat_agg)
    eq = evidence_quality(evs, cs)
    ac = assess_confidence(threat_dim, infra_dim, dc, cov, eq, cs)
    fa = final_assess(threat_dim, infra_dim, dc, cov, ac, cs, anycast)

    ents = build_entities(evs, ip)
    rels = build_rels(ents, evs, ip)
    ni = network_intel(ip, domain, evs, trusted, cert_ci)

    # Stage 7: Certificate Intelligence 2.0 — v34 (single source of truth)
    progress.next("03/13 Certificate")
    try:
        cert_intel = certificate_intelligence(target, CFG)
    except Exception as e:
        log.debug(f"certificate intelligence: {e}")
        cert_intel = {"live_certificate": None, "ct_certificates": [],
                      "correlation": {}, "metadata": [], "relationships": {},
                      "anomalies": [], "summary": {}}
    try:
        _legacy_cert = cert_summary(cert_ci) if cert_ci is not None else {}
    except Exception:
        _legacy_cert = {}
    if not isinstance(_legacy_cert, dict):
        _legacy_cert = {}
    if not isinstance(cert_intel, dict):
        cert_intel = {"live_certificate": None, "ct_certificates": [],
                      "correlation": {}, "metadata": [], "relationships": {},
                      "anomalies": [], "summary": {}}
    # Merge legacy summary keys (total, by_status, ...) for display compat.
    # New Stage 7 keys take precedence; legacy keys fill display path.
    _merged_cert_intel = dict(_legacy_cert)
    _merged_cert_intel.update(cert_intel)

    # Stage 8: Passive DNS Intelligence — v34.1 (single source of truth)
    progress.next("04/13 Passive DNS")
    try:
        pdns_intel = passive_dns_intelligence(target, CFG)
    except Exception as e:
        log.debug(f"passive dns intelligence: {e}")
        pdns_intel = {"evidence": [], "timeline": [],
                      "stats": {"total_domains": 0, "active_count": 0,
                                "historical_count": 0, "unknown_count": 0,
                                "churn_count": 0, "churn_domains": [],
                                "avg_lifespan_days": None,
                                "earliest_first_seen": None,
                                "latest_last_seen": None,
                                "churn_threshold": 5, "short_lived_days": 7},
                      "related_domains": [], "anomalies": [],
                      "summary": {"total_domains": 0, "active": 0,
                                  "historical": 0, "churn": 0,
                                  "avg_lifespan_days": None}}
    if not isinstance(pdns_intel, dict):
        pdns_intel = {"evidence": [], "timeline": [], "stats": {},
                      "related_domains": [], "anomalies": [], "summary": {}}

    # Stage 6: Infrastructure Intelligence — v33.1
    progress.next("05/13 Infrastructure")
    try:
        infra = infra_profile(target, CFG)
        out["infrastructure_intelligence"] = infra
    except Exception as e:
        log.debug(f"infra profile: {e}")
        out["infrastructure_intelligence"] = {"status": "FAILED", "reason": str(e), "ip": ip}

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
        "certificate_intelligence": _merged_cert_intel,
        "passive_dns_intelligence": pdns_intel,
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

    # Stage 9: Historical Intelligence — v35 (single source of truth)
    progress.next("06/13 History")
    # Snapshot must be taken after all sections are built.
    try:
        history_intel = historical_intelligence(target, out, CFG)
    except Exception as e:
        log.debug(f"historical intelligence: {e}")
        history_intel = {"enabled": True, "status": "ERROR",
                         "message": str(e), "changes": [], "total_changes": 0}
    if not isinstance(history_intel, dict):
        history_intel = {"enabled": True, "status": "ERROR",
                         "message": "invalid result", "changes": [], "total_changes": 0}
    out["historical_intelligence"] = history_intel

    # Stage 10: Correlation Engine — v36 (single source of truth)
    progress.next("07/13 Correlation")
    # Called after all other sections; reads only, modifies none.
    try:
        correlation = correlate([out], [target], CFG)
    except Exception as e:
        log.debug(f"correlation engine: {e}")
        correlation = {"enabled": True, "graph": {"nodes": [], "edges": [], "index": {}, "stats": {}},
                       "shared": {}, "related_targets": [], "notes": [], "summary": {}}
    if not isinstance(correlation, dict):
        correlation = {"enabled": True, "graph": {"nodes": [], "edges": [], "index": {}, "stats": {}},
                       "shared": {}, "related_targets": [], "notes": [], "summary": {}}
    out["correlation_intelligence"] = correlation

    # Stage 11: Attack Surface Intelligence — v37 (passive by default)
    progress.next("08/13 Attack Surface")
    # Reads infrastructure/certificate sections; OPEN != VULNERABLE.
    try:
        as_intel = attack_surface(target, out, CFG)
    except Exception as e:
        log.debug(f"attack surface: {e}")
        as_intel = {"enabled": True, "services": [], "service_count": 0,
                    "sensitive_services": [], "sensitive_count": 0,
                    "by_protocol": {}, "by_service": {}, "ports": [],
                    "exposure": {}, "anomalies": [], "notes": [],
                    "summary": {"total_services": 0, "sensitive_services": 0,
                                "anomalies": 0, "scan_mode": "passive"}}
    if not isinstance(as_intel, dict):
        as_intel = {"enabled": True, "services": [], "service_count": 0,
                    "sensitive_services": [], "sensitive_count": 0,
                    "by_protocol": {}, "by_service": {}, "ports": [],
                    "exposure": {}, "anomalies": [], "notes": [],
                    "summary": {"total_services": 0, "sensitive_services": 0,
                                "anomalies": 0, "scan_mode": "passive"}}
    out["attack_surface_intelligence"] = as_intel

    # Stage 12: Technology Fingerprinting — v38 (passive by default)
    progress.next("09/13 Technology")
    # Reads attack surface services; never guesses a version.
    try:
        tech_intel = technology_intelligence(out, CFG)
    except Exception as e:
        log.debug(f"technology intelligence: {e}")
        tech_intel = {"enabled": True, "results": [], "by_class": {},
                      "summary": {"services_analyzed": 0, "technologies_identified": 0,
                                  "ok": 0, "insufficient_evidence": 0, "unknown": 0,
                                  "min_confidence": 0.7}, "notes": []}
    if not isinstance(tech_intel, dict):
        tech_intel = {"enabled": True, "results": [], "by_class": {},
                      "summary": {"services_analyzed": 0, "technologies_identified": 0,
                                  "ok": 0, "insufficient_evidence": 0, "unknown": 0,
                                  "min_confidence": 0.7}, "notes": []}
    out["technology_intelligence"] = tech_intel

    # Stage 13: Vulnerability Intelligence — v39 (candidates only)
    progress.next("10/13 Vulnerability")
    # Reads technology fingerprints; candidate != confirmed.
    try:
        vuln_intel = vulnerability_candidates(out, CFG)
    except Exception as e:
        log.debug(f"vulnerability intelligence: {e}")
        vuln_intel = {"enabled": True, "candidates": [], "cpes_built": [],
                      "summary": {"technologies_analyzed": 0, "cpes_built": 0,
                                  "candidates": 0,
                                  "by_severity": {"critical": 0, "high": 0, "medium": 0,
                                                  "low": 0, "unknown": 0},
                                  "require_validation": True,
                                  "min_technology_confidence": 0.7},
                      "notes": []}
    if not isinstance(vuln_intel, dict):
        vuln_intel = {"enabled": True, "candidates": [], "cpes_built": [],
                      "summary": {"technologies_analyzed": 0, "cpes_built": 0,
                                  "candidates": 0,
                                  "by_severity": {"critical": 0, "high": 0, "medium": 0,
                                                  "low": 0, "unknown": 0},
                                  "require_validation": True,
                                  "min_technology_confidence": 0.7},
                      "notes": []}
    out["vulnerability_intelligence"] = vuln_intel

    # Stage 14: Anomaly Detection Engine — v40 (deviation, not verdict)
    progress.next("11/13 Anomaly")
    # Reads all prior sections; must run last before persistence.
    try:
        anomaly_intel = anomaly_report(out, CFG)
    except Exception as e:
        log.debug(f"anomaly engine: {e}")
        anomaly_intel = {"enabled": True, "checks_executed": [],
                         "checks_executed_count": 0, "total_anomalies": 0,
                         "by_severity": {}, "by_category": {}, "anomalies": [],
                         "notes": [], "summary": {}}
    if not isinstance(anomaly_intel, dict):
        anomaly_intel = {"enabled": True, "checks_executed": [],
                         "checks_executed_count": 0, "total_anomalies": 0,
                         "by_severity": {}, "by_category": {}, "anomalies": [],
                         "notes": [], "summary": {}}
    out["anomaly_intelligence"] = anomaly_intel

    # Stage 15: Confidence Engine — v41 (four separate metrics)
    progress.next("12/13 Confidence")
    # Must be computed last, after all other sections are populated.
    try:
        confidence = confidence_engine(out, CFG)
    except Exception as e:
        log.debug(f"confidence engine: {e}")
        confidence = {"enabled": False, "error": str(e)}
    if not isinstance(confidence, dict):
        confidence = {"enabled": False, "error": "invalid result"}
    out["confidence_intelligence"] = confidence
    # Backward-compatible aliases (canonical source is confidence_intelligence)
    try:
        if isinstance(confidence, dict) and confidence.get("enabled"):
            out["data_confidence"] = confidence.get("data_confidence", {}).get("score", out.get("data_confidence", 0.0))
            out["threat_confidence"] = confidence.get("threat_confidence", {}).get("score", 0.0)
    except Exception:
        pass

    # Stage 16: Intelligence Scoring — v41.1 (six explainable scores)
    progress.next("13/13 Scoring")
    # Must be computed last, after all other sections and confidence are populated.
    try:
        scoring = compute_scores(out, CFG)
    except Exception as e:
        log.debug(f"scoring engine: {e}")
        scoring = {"enabled": False, "error": str(e)}
    if not isinstance(scoring, dict):
        scoring = {"enabled": False, "error": "invalid result"}
    out["intelligence_scoring"] = scoring

    # Stage 20: Cache Intelligence — attach cache health (memory, not truth)
    try:
        out["cache_intelligence"] = _section_cache(out, CFG)
    except Exception as e:
        log.debug(f"cache intelligence: {e}")
        out["cache_intelligence"] = {"enabled": False, "error": str(e)}

    # Stage 17: Final Intelligence Report — v42 (18 sections + exports)
    progress.done()
    # Must be computed last, after all intelligence and scoring.
    try:
        final_report = generate_report(target, out, CFG)
    except Exception as e:
        log.debug(f"report generation: {e}")
        final_report = {"metadata": _report_metadata(target, CFG), "error": str(e)}
    try:
        export_paths = export_all(final_report, CFG)
    except Exception as e:
        log.debug(f"report export: {e}")
        export_paths = {}
    out["final_report"] = final_report
    out["export_paths"] = export_paths

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

    # [03b] THREAT INTELLIGENCE ENGINE 2.0 (Stage 4) — separate Threat vs Data Confidence
    ti = d.get("threat_intelligence") or {}
    if ti:
        out.append(_section_header("03b", "Threat Intelligence Engine 2.0"))
        out.append(f"   {_c('OBSERVED THREAT', C.KEY).ljust(28)} {_c(str(ti.get('observed_threat_score', 0)) + '/100', C.VAL)}")
        cov = ti.get('evidence_coverage', 0) * 100
        agr = ti.get('provider_agreement', 0) * 100
        fresh = ti.get('data_freshness', 0) * 100
        tconf = ti.get('threat_confidence', 0) * 100
        out.append(f"   {_c('EVIDENCE COVERAGE', C.KEY).ljust(28)} {_c(f'{cov:.1f}%', C.VAL)}")
        out.append(f"   {_c('PROVIDER AGREEMENT', C.KEY).ljust(28)} {_c(f'{agr:.1f}%', C.VAL)}")
        out.append(f"   {_c('DATA FRESHNESS', C.KEY).ljust(28)} {_c(f'{fresh:.1f}%', C.VAL)}")
        out.append(f"   {_c('THREAT CONFIDENCE', C.KEY).ljust(28)} {_c(f'{tconf:.1f}%', C.VAL)}")
        out.append(f"   {_c('DATA CONFIDENCE', C.KEY).ljust(28)} {_c(str(d.get('data_confidence', 0)), C.VAL)}")
        fails = ti.get("failures", {}) or {}
        if fails.get("failed") or fails.get("not_configured"):
            out.append(f"   {_c('FAILURES', C.WARN).ljust(28)} {_c('failed=' + str(fails.get('failed', [])), C.WARN)}")
            out.append(f"   {_c('', C.WARN).ljust(28)} {_c('not_configured=' + str(fails.get('not_configured', [])), C.GRY)}")
            if fails.get("warning"):
                out.append(f"   {_c('⚠', C.WARN)} {_c(fails.get('warning'), C.WARN)}")
        # Show summary
        if ti.get("summary"):
            out.append(f"   {_c('SUMMARY', C.DIM).ljust(28)} {_c(ti.get('summary', '')[:80], C.GRY)}")
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

    # [05a] DNS INTELLIGENCE ENGINE — v33 (Stage 5)
    dns_intel = d.get("dns_intelligence") or {}
    if dns_intel:
        analysis = dns_intel.get("analysis") or {}
        evidences = dns_intel.get("evidence") or []
        if analysis or evidences:
            out.append(_section_header("05a", "DNS Intelligence Engine"))
            # Records
            rt_present = analysis.get("record_types_present", [])
            rc = analysis.get("record_counts", {})
            if rt_present:
                out.append(f"   {_c('RECORDS', C.KEY).ljust(14)} {_c(', '.join(rt_present), C.VAL)}")
                for rt in rt_present:
                    cnt = rc.get(rt, 0)
                    vals = [e.get("normalized_value") or e.get("value") for e in evidences if e.get("metadata", {}).get("record_type") == rt and e.get("status") == "OK"]
                    vals = [v for v in vals if v][:3]
                    if vals:
                        out.append(f"     {_c(rt.ljust(6), C.DIM)} → {_c(', '.join(str(v) for v in vals[:3]), C.GRY)} {C.DIM}({cnt}){C.RST}")
            # Relationships
            rel = analysis.get("relationships", {}) or {}
            if rel.get("nameservers") or rel.get("mail_servers") or rel.get("cname_chains"):
                out.append(f"   {_c('RELATIONSHIPS', C.KEY).ljust(14)}")
                if rel.get("nameservers"):
                    out.append(f"     {_c('NS', C.DIM)} → {_c(', '.join(rel['nameservers'][:3]), C.VAL)}")
                if rel.get("mail_servers"):
                    out.append(f"     {_c('MX', C.DIM)} → {_c(', '.join(rel['mail_servers'][:3]), C.VAL)}")
                if rel.get("cname_chains"):
                    for ch in rel["cname_chains"][:2]:
                        out.append(f"     {_c('CNAME', C.DIM)} → {_c(' → '.join(ch), C.VAL)}")
                if rel.get("cname_loops"):
                    out.append(f"     {_c('LOOP', C.FAIL)} {_c(str(rel['cname_loops'][:1]), C.WARN)}")
            # Consistency
            cons = analysis.get("consistency", {}) or {}
            if cons.get("a_vs_ptr") or cons.get("ns_vs_soa") or cons.get("duplicate_records"):
                out.append(f"   {_c('CONSISTENCY', C.KEY).ljust(14)}")
                if cons.get("a_vs_ptr"):
                    avp = cons["a_vs_ptr"]
                    out.append(f"     {_c('A vs PTR', C.DIM)} a={avp.get('a_count')} ptr={avp.get('ptr_count')} consistent={avp.get('consistent')}")
                if cons.get("ns_vs_soa"):
                    nss = cons["ns_vs_soa"]
                    out.append(f"     {_c('NS vs SOA', C.DIM)} ns={nss.get('ns_count')} soa={nss.get('soa_primary')} consistent={nss.get('consistent')}")
                for dup in cons.get("duplicate_records", [])[:2]:
                    out.append(f"     {_c('DUP', C.WARN)} {dup.get('record_type')}: {', '.join(dup.get('duplicates', [])[:2])}")
            # TTL
            ttl = analysis.get("ttl", {}) or {}
            if ttl.get("per_type"):
                out.append(f"   {_c('TTL', C.KEY).ljust(14)} min={ttl.get('overall_min')} max={ttl.get('overall_max')} avg={ttl.get('overall_avg')}")
                for rt, v in list(ttl.get("per_type", {}).items())[:3]:
                    out.append(f"     {_c(rt, C.DIM)} min={v.get('min')} max={v.get('max')} avg={v.get('avg')}")
                if ttl.get("low_ttl_warning"):
                    out.append(f"     {_c('LOW TTL', C.WARN)} {ttl.get('low_ttl_count')} <60s")
                if ttl.get("high_ttl_warning"):
                    out.append(f"     {_c('HIGH TTL', C.WARN)} {ttl.get('high_ttl_count')} >86400s")
            # Mail
            mail = analysis.get("mail", {}) or {}
            if mail.get("mx_records") or mail.get("spf") or mail.get("dmarc"):
                out.append(f"   {_c('MAIL', C.KEY).ljust(14)}")
                if mail.get("mx_records"):
                    for mx in mail["mx_records"][:2]:
                        out.append(f"     {_c('MX', C.DIM)} {mx.get('priority')} {mx.get('host')} ({_identify_mail_provider(mx.get('host',''))})")
                if mail.get("spf"):
                    out.append(f"     {_c('SPF', C.DIM)} {_c(mail['spf'][:60], C.VAL)}")
                if mail.get("dmarc"):
                    out.append(f"     {_c('DMARC', C.DIM)} {_c(mail['dmarc'][:60], C.VAL)}")
                if mail.get("mx_providers"):
                    out.append(f"     {_c('PROVIDERS', C.DIM)} {_c(', '.join(mail['mx_providers']), C.VAL)}")
            # Security
            sec = analysis.get("security", {}) or {}
            if sec:
                out.append(f"   {_c('SECURITY', C.KEY).ljust(14)} SPF={'✓' if sec.get('spf_present') else '✗'} DMARC={'✓' if sec.get('dmarc_present') else '✗'} CAA={'✓' if sec.get('caa_present') else '✗'}")
                if sec.get("caa_records"):
                    out.append(f"     {_c('CAA', C.DIM)} {_c(', '.join(sec['caa_records'][:2]), C.VAL)}")
            # Anomalies
            anomalies = analysis.get("anomalies", []) or []
            if anomalies:
                out.append(f"   {_c('ANOMALIES', C.WARN).ljust(14)} {len(anomalies)}")
                for an in anomalies[:3]:
                    out.append(f"     {_c('['+an.get('severity','')+']', _severity_color(an.get('severity','')))} {an.get('type')} - {an.get('message')[:60]}")
            out.append(_section_footer())

    # [05a1] INFRASTRUCTURE INTELLIGENCE — v33.1 (Stage 6)
    infra = d.get("infrastructure_intelligence") or {}
    if infra:
        if infra.get("status") == "OK":
            out.append(_section_header("05a1", "Infrastructure Intelligence"))
            asn = infra.get("asn") or {}
            out.append(f"   {_c('ASN', C.KEY).ljust(14)} {_c(str(asn.get('asn', 'n/a')), C.VAL)} {_c(str(asn.get('asn_name',''))[:50], C.GRY)}")
            out.append(f"   {_c('TYPE', C.KEY).ljust(14)} {_c(str(asn.get('type','')), C.VAL)}")
            prefix = infra.get("prefix") or {}
            out.append(f"   {_c('PREFIX', C.KEY).ljust(14)} {_c(str(prefix.get('prefix','n/a')), C.VAL)}")
            out.append(f"   {_c('RIR', C.KEY).ljust(14)} {_c(str(prefix.get('rir','n/a')), C.VAL)}")
            org = infra.get("organization") or {}
            out.append(f"   {_c('ORG', C.KEY).ljust(14)} {_c(str(org.get('name','n/a')), C.VAL)}")
            if org.get("abuse_email"):
                out.append(f"   {_c('ABUSE', C.KEY).ljust(14)} {_c(str(org.get('abuse_email')), C.CYN)}")
            origin = infra.get("origin") or {}
            out.append(f"   {_c('ORIGIN', C.KEY).ljust(14)} {_c(str(origin.get('origin_asn','n/a')), C.VAL)}")
            related = infra.get("related_infrastructure") or {}
            if related.get("sibling_prefixes"):
                out.append(f"   {_c('SIBLINGS', C.KEY).ljust(14)} {_c(', '.join(related['sibling_prefixes'][:3]), C.VAL)}")
            hist = infra.get("history") or {}
            if hist.get("allocated"):
                out.append(f"   {_c('ALLOCATED', C.KEY).ljust(14)} {_c(str(hist.get('allocated')), C.VAL)}")
            peering = infra.get("peering") or {}
            if peering.get("note"):
                out.append(f"   {_c('PEERING', C.KEY).ljust(14)} {_c(str(peering.get('note')), C.GRY)}")
            out.append(_section_footer())
        elif infra.get("status") == "FAILED":
            out.append(_section_header("05a1", "Infrastructure Intelligence"))
            out.append(f"   {_c('STATUS', C.FAIL)} {infra.get('reason','')}")
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

    # [06] CERTIFICATES (Stage 7: Certificate Intelligence 2.0 — v34)
    ci = d.get("certificate_intelligence") or {}
    _live = ci.get("live_certificate") if isinstance(ci, dict) else None
    _ct_certs = ci.get("ct_certificates") if isinstance(ci, dict) else None
    _corr = ci.get("correlation") if isinstance(ci, dict) else None
    _rels = ci.get("relationships") if isinstance(ci, dict) else None
    _csum = ci.get("summary") if isinstance(ci, dict) else None
    _has_v34 = bool((_live and isinstance(_live, dict) and _live.get("fingerprint_sha256")) or _ct_certs or _corr or _rels or _csum)
    if ci.get("total") or _has_v34:
        out.append(_section_header("06", "Certificate Intelligence"))
        if ci.get("total"):
            out.append(f"   {_c('TOTAL', C.KEY).ljust(14)} "
                       f"{_c(ci.get('total', 0), C.BLD, C.VAL)}")
        elif _csum and _csum.get("total_certificates") is not None:
            out.append(f"   {_c('TOTAL', C.KEY).ljust(14)} "
                       f"{_c(_csum.get('total_certificates', 0), C.BLD, C.VAL)}")
        bs = ci.get("by_status", {})
        if bs:
            cur_n = bs.get("CURRENT", 0)
            hist_n = bs.get("HISTORICAL", 0)
            unreach_n = bs.get("UNREACHABLE", 0)
            status_str = f"CURRENT={cur_n}  HISTORICAL={hist_n}  UNREACHABLE={unreach_n}"
            out.append(f"   {_c('STATUS', C.KEY).ljust(14)} "
                       f"{_c(status_str, C.VAL)}")
        exp = ci.get("expired", 0)
        near = ci.get("near_expiry", 0)
        weak = ci.get("weak", 0)
        if _csum:
            try:
                exp = _csum.get("expired_count", exp)
                weak = _csum.get("weak_algo_count", weak)
            except Exception:
                pass
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
        if not wc and _rels and _rels.get("wildcard_certs"):
            wc = [str(f)[:16] for f in (_rels.get("wildcard_certs") or [])]
        if wc:
            out.append(f"   {_c('WILDCARDS', C.KEY).ljust(14)} "
                       f"{_c(', '.join([str(x) for x in wc[:5]]), C.MAG)}")
        # Stage 7 live certificate details
        if isinstance(_live, dict) and _live.get("fingerprint_sha256"):
            out.append(f"   {_c('LIVE CERT', C.KEY).ljust(14)} "
                       f"{_c(str(_live.get('subject_cn') or 'n/a'), C.VAL)}")
            if _live.get("issuer_cn") or _live.get("issuer_o"):
                out.append(f"   {_c('ISSUER', C.KEY).ljust(14)} "
                           f"{_c(str(_live.get('issuer_cn') or _live.get('issuer_o') or 'unknown')[:50], C.CYN)}")
            sans = _live.get("san_domains") or []
            if sans:
                out.append(f"   {_c('SANs', C.KEY).ljust(14)} "
                           f"{_c(', '.join([str(s) for s in sans[:4]]) + (f' +{len(sans)-4} more' if len(sans) > 4 else ''), C.VAL)}")
            out.append(f"   {_c('FINGERPRINT', C.KEY).ljust(14)} "
                       f"{_c(str(_live.get('fingerprint_sha256',''))[:32], C.GRY)}")
            if _corr:
                out.append(f"   {_c('LIVE IN CT', C.KEY).ljust(14)} "
                           f"{_c(str(_corr.get('live_in_ct')), C.VAL)}")
        if _ct_certs is not None:
            try:
                out.append(f"   {_c('CT CERTS', C.KEY).ljust(14)} "
                           f"{_c(str(len(_ct_certs or [])), C.VAL)}")
            except Exception:
                pass
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

# ============================================================
#  PROVIDER TEST HARNESS — v44.6 (Stage R5)
#  Read-only diagnostics: no db, no reports, no cache.
# ============================================================
def _auth_label(provider: Any) -> str:
    """
    Return a short label describing the provider's auth mode.

    Examples:
      "none"
      "header:Key"
      "param:key"
      "bearer"
      "basic"
      "header:Key (no key)"
    """
    try:
        at = (getattr(provider, "auth_type", None) or "api_key_header").lower()
    except Exception:
        at = "api_key_header"
    try:
        has_key = bool(getattr(provider, "api_key", None))
    except Exception:
        has_key = False

    if at == "none":
        return "none"
    if at == "api_key_header":
        try:
            h = getattr(provider, "auth_header", None) or "Authorization"
        except Exception:
            h = "Authorization"
        return f"header:{h}" + ("" if has_key else " (no key)")
    if at == "api_key_param":
        try:
            p = getattr(provider, "auth_param", None) or "key"
        except Exception:
            p = "key"
        return f"param:{p}" + ("" if has_key else " (no key)")
    if at == "bearer_token":
        return "bearer" + ("" if has_key else " (no key)")
    if at == "basic_auth":
        return "basic" + ("" if has_key else " (no key)")
    return at


def _summarize_result(result: Dict[str, Any]) -> str:
    """
    Build a short, safe summary of a provider result for the diagnostic table.
    Never includes secrets. Never truncates mid-word where possible.
    """
    if not isinstance(result, dict):
        return "(empty result)"
    parts: List[str] = []

    score = result.get("threat_score")
    if score is not None:
        parts.append(f"score={score}")

    tags = result.get("tags") or []
    if tags:
        try:
            tag_preview = ",".join(str(t) for t in tags[:2])
            if len(tags) > 2:
                tag_preview += f",+{len(tags) - 2}"
            parts.append(f"tags=[{tag_preview}]")
        except Exception:
            pass

    evidence = result.get("evidence")
    if evidence:
        ev = _scrub(str(evidence))
        if len(ev) > 60:
            ev = ev[:57] + "..."
        parts.append(ev)

    if not parts:
        return "(empty result)"

    return " | ".join(parts)


def _render_rich_table(console, table, rows: List[Dict[str, Any]]) -> None:
    """
    Populate and print a rich table.
    """
    status_style = {
        "OK": "green",
        "FAILED": "red",
        "ERROR": "red",
        "NOT_CONFIGURED": "yellow",
        "DISABLED": "dim",
    }

    for row in rows:
        style = status_style.get(row["status"], "white")
        table.add_row(
            row["name"],
            row["auth"],
            f"[{style}]{row['status']}[/{style}]",
            row["latency"],
            row["detail"],
        )

    console.print(table)


def _render_plain_table(rows: List[Dict[str, Any]]) -> None:
    """
    Plain-text fallback renderer.
    """
    headers = ["Provider", "Auth", "Status", "Latency", "Evidence / Error"]
    widths = [20, 20, 16, 10, 60]

    def fmt_row(cells: List[str]) -> str:
        return "  ".join(
            str(c)[:w].ljust(w) for c, w in zip(cells, widths)
        )

    print(fmt_row(headers))
    print("-" * (sum(widths) + 2 * (len(widths) - 1)))
    for row in rows:
        print(fmt_row([
            row["name"],
            row["auth"],
            row["status"],
            row["latency"],
            row["detail"],
        ]))


def _render_auth_table(auth_info: Dict[str, Any],
                       providers: Dict[str, Any],
                       config: Optional[Dict[str, Any]] = None) -> None:
    """
    Render the full provider auth state, including disabled (Stage A2).

    Read-only: performs no network I/O and writes no files.
    """
    try:
        declared = (config.get("providers", {}) or {}) if isinstance(config, dict) else {}
    except Exception:
        declared = {}
    if not isinstance(declared, dict):
        declared = {}
    try:
        provided = dict(providers or {})
    except Exception:
        provided = {}
    try:
        missing = set(auth_info.get("missing", []) or [])
        misconfigured = set(auth_info.get("misconfigured", []) or [])
        present = set(auth_info.get("present", []) or [])
        disabled_info = set(auth_info.get("disabled", []) or [])
    except Exception:
        missing = set()
        misconfigured = set()
        present = set()
        disabled_info = set()

    rows: List[Dict[str, str]] = []
    for name in sorted(set(declared.keys()) | set(provided.keys())):
        p = provided.get(name)
        pc = declared.get(name) if isinstance(declared.get(name), dict) else {}
        try:
            enabled = bool(getattr(p, "enabled", True)) if p is not None else bool(pc.get("enabled", True))
        except Exception:
            enabled = bool(pc.get("enabled", True))
        try:
            auth_type = str(getattr(p, "auth_type", None) or pc.get("auth_type") or "api_key_header")
        except Exception:
            auth_type = str(pc.get("auth_type", "api_key_header"))
        try:
            env = str(getattr(p, "auth_env", None) or pc.get("api_key_env") or "-")
        except Exception:
            env = str(pc.get("api_key_env", "-") or "-")
        if not enabled or name in disabled_info and p is None:
            state = "DISABLED"
        elif auth_type.lower() == "none":
            state = "NO_AUTH"
        elif name in misconfigured:
            state = "MISCONFIGURED"
        elif name in missing:
            state = "MISSING"
        elif name in present:
            state = "PRESENT"
        elif env not in ("-", "", "None"):
            state = "PRESENT" if bool(os.getenv(env)) else "MISSING"
        else:
            state = "MISCONFIGURED"
        # Remediation hint for actionable states (Stage A3).
        hint = ""
        if state in ("MISSING", "MISCONFIGURED"):
            try:
                remediation = pc.get("remediation", {}) if isinstance(pc.get("remediation", {}), dict) else {}
                hint_env = str(remediation.get("env_var", "") or env)
                hint_url = str(remediation.get("signup_url", "") or "")
                if state == "MISCONFIGURED" and hint_env in ("-", "", "None"):
                    hint = "\n[dim]no env var declared[/dim]"
                elif hint_env not in ("-", "", "None"):
                    hint = f"\n[dim]set {hint_env}[/dim]"
                if hint_url:
                    hint += f"\n[dim]{hint_url}[/dim]"
            except Exception:
                hint = ""
        rows.append({
            "name": name,
            "enabled": "yes" if enabled else "no",
            "auth_type": auth_type,
            "env": env,
            "state": state,
            "hint": hint,
        })

    try:
        n_present = len(present)
        n_missing = len(missing) + len(misconfigured)
        n_disabled = sum(1 for r in rows if r["state"] == "DISABLED")
        n_noauth = sum(1 for r in rows if r["state"] == "NO_AUTH")
    except Exception:
        n_present = n_missing = n_disabled = n_noauth = 0

    try:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        table = Table(title="ReconIP Auth State", show_lines=False)
        table.add_column("Provider", style="cyan", no_wrap=True)
        table.add_column("Enabled", justify="center", no_wrap=True)
        table.add_column("Auth Type", style="magenta", no_wrap=True)
        table.add_column("Env Var", style="dim", no_wrap=True)
        table.add_column("State", style="bold", no_wrap=True)
        style_map = {
            "DISABLED": "dim",
            "NO_AUTH": "green",
            "MISCONFIGURED": "yellow",
            "MISSING": "yellow",
            "PRESENT": "green",
        }
        for r in rows:
            style = style_map.get(r["state"], "white")
            table.add_row(r["name"], r["enabled"], r["auth_type"], r["env"], f"[{style}]{r['state']}[/{style}]{r.get('hint', '')}")
        console.print(table)
        console.print(
            f"\nSummary: {n_present} present, {n_missing} missing, "
            f"{n_disabled} disabled, {n_noauth} no-auth."
        )
    except ImportError:
        headers = ["Provider", "Enabled", "Auth Type", "Env Var", "State"]
        widths = [20, 10, 18, 24, 14]
        print("  ".join(h[:w].ljust(w) for h, w in zip(headers, widths)))
        print("-" * (sum(widths) + 2 * (len(widths) - 1)))
        for r in rows:
            cell = r["state"] + r.get("hint", "").replace("\n", " ").replace("[dim]", "").replace("[/dim]", "")
            print("  ".join(str(c)[:w].ljust(w) for c, w in zip(
                [r["name"], r["enabled"], r["auth_type"], r["env"], cell], widths)))
        print(f"\nSummary: {n_present} present, {n_missing} missing, "
              f"{n_disabled} disabled, {n_noauth} no-auth.")


def _render_providers_table(providers: Dict[str, Any],
                             config: Optional[Dict[str, Any]] = None) -> None:
    """
    Render every provider with its state and remediation path (Stage A3).

    Metadata comes from config.yaml `remediation` blocks; no URL is
    hardcoded here. Read-only: no network I/O, no disk writes.
    """
    try:
        declared = (config.get("providers", {}) or {}) if isinstance(config, dict) else {}
    except Exception:
        declared = {}
    if not isinstance(declared, dict):
        declared = {}
    try:
        provided = dict(providers or {})
    except Exception:
        provided = {}

    rows: List[Dict[str, str]] = []
    for name in sorted(set(declared.keys()) | set(provided.keys())):
        p = provided.get(name)
        pc = declared.get(name) if isinstance(declared.get(name), dict) else {}
        remediation = pc.get("remediation", {}) if isinstance(pc.get("remediation", {}), dict) else {}
        try:
            enabled = bool(getattr(p, "enabled", True)) if p is not None else bool(pc.get("enabled", True))
        except Exception:
            enabled = bool(pc.get("enabled", True))
        try:
            auth_type = str(getattr(p, "auth_type", None) or pc.get("auth_type") or "api_key_header")
        except Exception:
            auth_type = str(pc.get("auth_type", "api_key_header"))
        try:
            env = str(getattr(p, "auth_env", None) or pc.get("api_key_env")
                      or remediation.get("env_var") or "-")
        except Exception:
            env = "-"
        why = str(remediation.get("why", "") or "-")
        url = str(remediation.get("signup_url", "") or "")
        free = str(remediation.get("free_tier", "") or "")
        rows.append({
            "name": name,
            "state": "ENABLED" if enabled else "DISABLED",
            "auth_type": auth_type,
            "env": env,
            "why": why,
            "url": url,
            "free": free,
        })

    try:
        n_enabled = sum(1 for r in rows if r["state"] == "ENABLED")
        n_disabled = len(rows) - n_enabled
    except Exception:
        n_enabled = n_disabled = 0

    try:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        table = Table(title="ReconIP Providers", show_lines=False, expand=False)
        table.add_column("Provider", style="cyan", no_wrap=True)
        table.add_column("State", justify="center", no_wrap=True)
        table.add_column("Auth", style="magenta", no_wrap=True)
        table.add_column("Env Var", style="dim", no_wrap=True)
        table.add_column("Remediation", overflow="fold")
        for r in rows:
            state = "[green]ENABLED[/green]" if r["state"] == "ENABLED" else "[yellow]DISABLED[/yellow]"
            detail = r["why"]
            if r["url"]:
                detail += f"\n{r['url']}"
            if r["free"]:
                detail += f"\n[dim]{r['free']}[/dim]"
            table.add_row(r["name"], state, r["auth_type"], r["env"], detail)
        console.print(table)
        console.print(f"\nSummary: {n_enabled} enabled, {n_disabled} disabled.")
        console.print(
            "[dim]To enable a disabled provider: "
            "set its env var, then change enabled: false → true.[/dim]"
        )
    except ImportError:
        headers = ["Provider", "State", "Auth", "Env Var", "Remediation"]
        widths = [20, 10, 18, 24, 60]
        print("  ".join(h[:w].ljust(w) for h, w in zip(headers, widths)))
        print("-" * (sum(widths) + 2 * (len(widths) - 1)))
        for r in rows:
            detail = r["why"]
            if r["url"]:
                detail += f" {r['url']}"
            print("  ".join(str(c)[:w].ljust(w) for c, w in zip(
                [r["name"], r["state"], r["auth_type"], r["env"], detail], widths)))
        print(f"\nSummary: {n_enabled} enabled, {n_disabled} disabled.")


# ============================================================
#  TERMINAL DISPLAY INFRASTRUCTURE — Stage B1 (v46.1)
#  Console singleton, palette, box style, panel/section wrappers,
#  section registry with placeholders, and the render_all dispatcher.
#  Stages B2–B5 fill in banner/header/sections. Display never blocks
#  report generation, never writes to disk, and never raises.
# ============================================================
_CONSOLE: Optional["Console"] = None


def _console(config: Optional[Dict[str, Any]] = None) -> Optional["Console"]:
    """
    Return the shared rich Console instance (Stage B1).

    Rules:
      - Created once.
      - Width is derived from config (display.width) if provided.
      - Returns None when rich is unavailable.
    """
    global _CONSOLE
    if not _RICH_AVAILABLE:
        return None
    if _CONSOLE is None:
        width = None
        try:
            if isinstance(config, dict):
                width = (config.get("display", {}) or {}).get("width")
        except Exception:
            width = None
        _CONSOLE = Console(width=width, force_terminal=None, soft_wrap=False)
    return _CONSOLE


class _NoteDedupFilter(logging.Filter):
    """
    Drop records already shown via progress.note() (Stage C3.6).

    _log_auth_summary() emits through progress.note() for live display
    AND through logging so the file handler captures it. This filter,
    attached to console handlers only, suppresses the duplicate on the
    terminal while the file handler (no filter) still records it.
    """

    def filter(self, record: Any) -> bool:
        try:
            return not bool(getattr(record, "via_note", False))
        except Exception:
            return True


def _setup_logging(config: Dict[str, Any]) -> None:
    """
    Configure the root logger (Stage C3.6).

    Behavior:
      - Display enabled AND rich.logging available: RichHandler on the
        SHARED _console() so log lines coordinate with the live progress
        region (drawn above the bar) instead of jamming into it.
      - Otherwise: plain stderr StreamHandler (scripts, off mode, pipes).
      - logging.file (when set): plain-text FileHandler, best-effort.
      - logging.level (default INFO); unknown levels fall back to INFO.
      - Existing root handlers are removed to prevent double-logging.
      - Never raises.
    """
    try:
        log_cfg = (config.get("logging", {}) or {}) if isinstance(config, dict) else {}
        if not isinstance(log_cfg, dict):
            log_cfg = {}
        level_name = str(log_cfg.get("level", "INFO")).upper()
        level = getattr(logging, level_name, logging.INFO)
        try:
            level = int(level)
        except Exception:
            level = logging.INFO

        log_file = log_cfg.get("file")
        log_format = log_cfg.get(
            "format",
            "%(asctime)s [%(levelname)s] %(message)s",
        )

        # ---- Reset existing handlers (avoid double-logging) ----
        root = logging.getLogger()
        for h in list(root.handlers):
            try:
                root.removeHandler(h)
            except Exception:
                pass

        handlers: List[logging.Handler] = []

        # ---- Console handler ----
        try:
            dcfg = (config.get("display", {}) or {}) if isinstance(config, dict) else {}
        except Exception:
            dcfg = {}
        if not isinstance(dcfg, dict):
            dcfg = {}
        display_enabled = bool(dcfg.get("enabled", True))

        # RF redacts secrets (API keys, tokens) from every record.
        try:
            _redacting_formatter = RF(log_format)
        except Exception:
            _redacting_formatter = logging.Formatter(log_format)

        if _RICH_AVAILABLE and _RICH_LOG_AVAILABLE and display_enabled:
            # RichHandler with its own (stderr) console: logs stay off
            # stdout, which is reserved for machine-readable output.
            # show_path MUST stay False: internal file paths are not
            # operator information. No custom formatter: RichHandler
            # renders [LEVEL] + message; file handler keeps the full
            # timestamped format with secret redaction.
            console_handler = RichHandler(
                show_time=False,
                show_level=True,
                show_path=False,
                markup=False,
                rich_tracebacks=False,
            )
        else:
            # Plain fallback: stderr, one line per record.
            console_handler = logging.StreamHandler()  # stderr by default
            console_handler.setFormatter(_redacting_formatter)
        try:
            console_handler.addFilter(_NoteDedupFilter())
        except Exception:
            pass
        handlers.append(console_handler)

        # ---- Optional file handler (always plain text) ----
        if log_file:
            try:
                file_handler = logging.FileHandler(log_file, encoding="utf-8")
                try:
                    file_handler.setFormatter(RF(log_format))
                except Exception:
                    file_handler.setFormatter(logging.Formatter(log_format))
                handlers.append(file_handler)
            except Exception:
                # File logging is best-effort; never fail the tool.
                pass

        # ---- Apply ----
        for h in handlers:
            try:
                h.setLevel(level)
            except Exception:
                pass

        try:
            root.setLevel(level)
        except Exception:
            pass
        for h in handlers:
            try:
                root.addHandler(h)
            except Exception:
                pass

    except Exception:
        # Never let logging configuration break the pipeline.
        # (Explicit handler, not basicConfig: handlers were removed above,
        # but basicConfig is a no-op if any handler was re-added.)
        try:
            _fallback = logging.StreamHandler()
            logging.getLogger().addHandler(_fallback)
            logging.getLogger().setLevel(logging.INFO)
        except Exception:
            pass


class Palette:
    """
    Resolve colors from config into rich style strings (Stage B1).

    Config shape:
      display:
        colors:
          primary: "cyan"
          ...
    """

    DEFAULTS = {
        "primary": "cyan",
        "accent": "magenta",
        "success": "green",
        "warning": "yellow",
        "danger": "red",
        "muted": "dim",
        "highlight": "bold white",
        "border": "cyan",
        "label": "bold",
        "value": "",
    }

    def __init__(self, config: Dict[str, Any]):
        try:
            colors = (config.get("display", {}) or {}).get("colors", {}) or {}
        except Exception:
            colors = {}
        if not isinstance(colors, dict):
            colors = {}
        self._map: Dict[str, str] = dict(self.DEFAULTS)
        try:
            self._map.update({k: str(v) for k, v in colors.items() if v})
        except Exception:
            pass

    def get(self, name: str) -> str:
        try:
            return self._map.get(name, "")
        except Exception:
            return ""

    def style(self, *names: str) -> str:
        """Return a composed style string, e.g. palette.style('accent', 'bold')."""
        try:
            parts = [self.get(n) for n in names if self.get(n)]
        except Exception:
            return ""
        return " ".join(parts) if parts else ""


class _NoopProgress:
    """
    A silent no-op progress handle (Stage C1).

    Used when progress is disabled, when stdout is not a TTY,
    or when rich is unavailable. Pipeline code calls it uniformly.
    """
    def start(self, name: str) -> None:
        pass

    def next(self, name: str) -> None:
        pass

    def update(self, name: str) -> None:
        pass

    def done(self) -> None:
        pass

    def note(self, message: str) -> None:
        pass


class _RichProgress:
    """
    A progress handle that owns its own completed counter (Stage C3.4).

    Design:
      - `completed` is tracked locally, not by rich.
      - Every `next()` passes an absolute `completed` value to rich.
      - `total` is passed on every update so the bar never loses it.
      - `done()` forces the counter to `total` and marks the description.
      - `start()` resets the counter so handle reuse across batch
        targets restarts the bar instead of resuming a stale count.

    This removes the dependency on rich's internal `advance` behavior,
    which was responsible for the stalled counter in v47.5.
    """

    def __init__(self, progress: "Progress", task_id: Any, total: int = 13):
        self._progress = progress
        self._task_id = task_id
        try:
            self._total = max(1, int(total))
        except Exception:
            self._total = 13
        self._completed = 0

    def start(self, name: str) -> None:
        """Reset to 0 and set the first stage description."""
        self._completed = 0
        self._progress.update(
            self._task_id,
            description=name,
            completed=0,
            total=self._total,
        )

    def next(self, name: str) -> None:
        """Advance by 1 and set the next stage description."""
        self._completed = min(self._completed + 1, self._total)
        self._progress.update(
            self._task_id,
            description=name,
            completed=self._completed,
            total=self._total,
        )

    def update(self, name: str) -> None:
        """Update only the description, preserving the counter."""
        self._progress.update(
            self._task_id,
            description=name,
            completed=self._completed,
            total=self._total,
        )

    def done(self) -> None:
        """Force the counter to total and mark as done."""
        self._completed = self._total
        self._progress.update(
            self._task_id,
            description="Done",
            completed=self._completed,
            total=self._total,
        )

    def note(self, message: str) -> None:
        """Emit a log line through rich's console."""
        try:
            self._progress.console.log(message)
        except Exception:
            pass


def _progress_wanted(config: Optional[Dict[str, Any]] = None) -> bool:
    """
    True when a live progress bar should be shown (Stage C1).

    Suppressed by: display.enabled=false, display.show_progress=false,
    display.mode=quiet, batch quiet mode. Requires a TTY unless
    display.force_progress is true. Never raises.
    """
    try:
        dcfg = (config.get("display", {}) or {}) if isinstance(config, dict) else {}
        if not isinstance(dcfg, dict):
            return False
        if not dcfg.get("enabled", True):
            return False
        if not dcfg.get("show_progress", True):
            return False
        if str(dcfg.get("mode", "terminal")) == "quiet":
            return False
        try:
            if isinstance(config, dict) and bool((config.get("batch", {}) or {}).get("quiet", False)):
                return False
        except Exception:
            pass
        if bool(dcfg.get("force_progress", False)):
            return True
        return bool(sys.stdout.isatty())
    except Exception:
        return False


@contextmanager
def _progress_context(config: Dict[str, Any],
                      total_stages: int,
                      stage_name: str = "Scan"):
    """
    Yield a progress handle suitable for the current environment (Stage C1).

    Yields _RichProgress on an interactive TTY, else _NoopProgress.
    The rich bar is transient: it clears itself when the context exits.
    Never raises; never writes reports; never touches the pipeline.
    """
    if not _progress_wanted(config):
        yield _NoopProgress()
        return
    if not _RICH_AVAILABLE or not _RICH_PROGRESS_AVAILABLE:
        yield _NoopProgress()
        return

    try:
        palette = Palette(config)
    except Exception:
        yield _NoopProgress()
        return
    try:
        dcfg = (config.get("display", {}) or {}) if isinstance(config, dict) else {}
        refresh = int(dcfg.get("progress_refresh_per_second", 10))
    except Exception:
        refresh = 10
    if refresh < 1:
        refresh = 1
    if refresh > 60:
        refresh = 60

    try:
        progress = Progress(
            SpinnerColumn(style=palette.get("accent")),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(
                bar_width=None,
                style=palette.get("muted"),
                complete_style=palette.get("success"),
            ),
            MofNCompleteColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            transient=True,
            refresh_per_second=refresh,
            console=_console(config),
        )
        task_id = progress.add_task(stage_name, total=total_stages)
        handle = _RichProgress(progress, task_id, total=total_stages)
    except Exception:
        yield _NoopProgress()
        return

    try:
        with progress:
            yield handle
    finally:
        # progress.__exit__ clears the transient display
        pass


_MISSING = "—"  # em-dash for missing values (Stage B3)


def _safe(d: Any, *keys: str, default: Any = _MISSING) -> Any:
    """
    Safely walk a nested dict and return the value at the path (Stage B3).

    Returns `default` when any key is missing or an intermediate
    value is not a dict.

    Example:
      _safe(report, "01_target_profile", "asn") → 15169
    """
    if not isinstance(d, dict):
        return default
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        try:
            cur = cur.get(k, default)
        except Exception:
            return default
        if cur is _MISSING:
            return default
    return cur if cur is not None else default


def _present(value: Any) -> str:
    """
    Normalize a value for display (Stage B3).
    - None → "—"; empty list/dict/str → "—"
    - True/False → "yes"/"no"; otherwise str(value).
    """
    if value is None:
        return _MISSING
    if value is True:
        return "yes"
    if value is False:
        return "no"
    if isinstance(value, (list, dict)) and not value:
        return _MISSING
    if isinstance(value, str) and not value.strip():
        return _MISSING
    try:
        return str(value)
    except Exception:
        return _MISSING


def _shorten(value: Any, max_len: int = 30) -> str:
    """
    Shorten a value for display (Stage C3.7).

    Behavior:
      - None or empty → "—"
      - Length ≤ max_len → unchanged
      - Length > max_len → first (max_len - 1) chars + "…"

    Note: display-only transformation. The full value remains
    in the JSON report.
    """
    if value is None:
        return _MISSING
    try:
        s = str(value).strip()
    except Exception:
        return _MISSING
    if not s:
        return _MISSING
    try:
        limit = int(max_len)
    except Exception:
        limit = 30
    if len(s) <= limit:
        return s
    if limit <= 1:
        return "…"
    return s[: limit - 1] + "…"


def _trunc_limit(config: Dict[str, Any], key: str, default: int) -> int:
    """
    Read an operator-tunable truncation limit (Stage C3.7).

    display.truncation.<key> overrides the hardcoded default.
    Missing/invalid config falls back to the default.
    """
    try:
        trunc = ((config.get("display", {}) or {}).get("truncation", {}) or {})
        if isinstance(trunc, dict) and key in trunc:
            return max(1, int(trunc[key]))
    except Exception:
        pass
    return default


def _kv_grid(pairs: List[Tuple[str, Any]],
             config: Dict[str, Any],
             columns: int = 2) -> "Table":
    """
    Build a rich.Table.grid with N label/value column groups (Stage B3).
    """
    palette = Palette(config)
    grid = Table.grid(padding=(0, 2))
    for _ in range(max(1, columns)):
        grid.add_column(style=palette.get("muted"), no_wrap=True)
        grid.add_column(style=palette.get("value") or palette.get("highlight"),
                        no_wrap=False, overflow="fold")

    # Fill row by row
    row: List[str] = []
    for label, value in pairs:
        row.append(str(label))
        row.append(_present(value))
        if len(row) == max(1, columns) * 2:
            grid.add_row(*row)
            row = []
    if row:
        # Pad the last row
        while len(row) < max(1, columns) * 2:
            row.append("")
        grid.add_row(*row)
    return grid


def _truncate_list(items: List[Any], limit: int,
                   joiner: str = ", ") -> str:
    """
    Join a list into a string, truncating with a (+N more) suffix (Stage B4).
    """
    if not items:
        return _MISSING
    try:
        shown = [str(x) for x in items[:limit]]
        tail = f"  (+{len(items) - limit} more)" if len(items) > limit else ""
        return joiner.join(shown) + tail
    except Exception:
        return _MISSING


def _resolve_box(config: Dict[str, Any]):
    """
    Return the rich box constant matching display.box_style (Stage B1).
    Falls back to ROUNDED.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        name = ((config.get("display", {}) or {}).get("box_style") or "rounded").lower()
    except Exception:
        name = "rounded"
    mapping = {
        "rounded": ROUNDED,
        "heavy": HEAVY,
        "double": DOUBLE,
        "simple": SIMPLE,
        "minimal": MINIMAL,
        "square": SQUARE,
        "ascii": ASCII,
    }
    return mapping.get(name, ROUNDED)


def panel(content, config: Dict[str, Any],
          title: Optional[str] = None,
          border: str = "border",
          padding: Tuple[int, int] = (0, 1)) -> Optional["Panel"]:
    """
    Build a Panel with consistent styling (Stage B1).

    Returns None when rich is unavailable.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        box = _resolve_box(config)
        return Panel(
            content,
            title=title,
            border_style=palette.get(border),
            box=box,
            padding=padding,
            expand=True,
        )
    except Exception as e:
        logging.debug(f"panel build failed: {e}")
        return None


def section(number: int, title: str,
            body, config: Dict[str, Any],
            border: str = "border") -> Optional["Panel"]:
    """
    Render a numbered section header + body inside a panel (Stage B1).

    Example:
      section(1, "TARGET PROFILE", table, config)
      → ╭─ 01 │ TARGET PROFILE ─────────╮
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        header = Text.assemble(
            (f" {number:02d} ", palette.get("accent")),
            ("│ ", palette.get("muted")),
            (title, palette.get("highlight")),
            (" ", ""),
        )
        return Panel(
            body,
            title=header,
            title_align="left",
            border_style=palette.get(border),
            box=_resolve_box(config),
            padding=(0, 1),
            expand=True,
        )
    except Exception as e:
        logging.debug(f"section build failed: {e}")
        return None


SECTION_REGISTRY: List[Tuple[int, str, str]] = [
    (1,  "TARGET PROFILE",           "_render_01_target_profile"),
    (2,  "EXECUTIVE SUMMARY",        "_render_02_executive_summary"),
    (3,  "DATA QUALITY",             "_render_03_data_quality"),
    (4,  "NETWORK INTELLIGENCE",     "_render_04_network"),
    (5,  "DNS INTELLIGENCE",         "_render_05_dns"),
    (6,  "CERTIFICATE INTELLIGENCE", "_render_06_certificate"),
    (7,  "PASSIVE DNS",              "_render_07_passive_dns"),
    (8,  "HISTORICAL INTELLIGENCE",  "_render_08_history"),
    (9,  "THREAT INTELLIGENCE",      "_render_09_threat"),
    (10, "INFRASTRUCTURE CORRELATION", "_render_10_correlation"),
    (11, "ATTACK SURFACE",           "_render_11_attack_surface"),
    (12, "TECHNOLOGY",               "_render_12_technology"),
    (13, "VULNERABILITY CANDIDATES", "_render_13_vulnerability"),
    (14, "ANOMALIES",                "_render_14_anomalies"),
    (15, "EVIDENCE",                 "_render_15_evidence"),
    (16, "CONFIDENCE",               "_render_16_confidence"),
    (17, "LIMITATIONS",              "_render_17_limitations"),
    (18, "NEXT INVESTIGATION",       "_render_18_next_investigation"),
]


def _render_placeholder(number: int, title: str,
                        config: Dict[str, Any]) -> Optional["Panel"]:
    """
    Fallback renderer for sections that are not yet implemented (Stage B1).

    Should not be reached after Stage B5, but is kept as a safety net
    so render_all() never crashes on a missing renderer.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        body = Text(
            f"[section {number:02d}] {title} — renderer not yet implemented",
            style=palette.get("muted") or "",
        )
        return section(number, title, body, config)
    except Exception as e:
        logging.debug(f"placeholder render failed: {e}")
        return None


# ---- Placeholder section renderers (replaced in B3–B5) ----

def _render_01_target_profile(report, config):
    """
    Render Section 01 — TARGET PROFILE (Stage B3).
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        tp = (report.get("01_target_profile", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(tp, dict):
            tp = {}

        rows: List[Tuple[str, Any]] = [
            ("Target",       tp.get("target")),
            ("IP",           tp.get("ip")),
            ("ASN",          tp.get("asn")),
            ("ASN Name",     tp.get("asn_name")),
            ("Country",      tp.get("country")),
            ("Organization", tp.get("organization")),
            ("Prefix",       tp.get("prefix")),
            ("RIR",          tp.get("rir")),
            ("Anycast",      tp.get("anycast")),
        ]

        body = _kv_grid(rows, config, columns=2)
        return section(1, "TARGET PROFILE", body, config)
    except Exception as e:
        logging.debug(f"section 01 render failed: {e}")
        return _render_placeholder(1, "TARGET PROFILE", config)


def _score_bar(value: float, config: Dict[str, Any],
                width: int = 10) -> "Text":
    """Build a mini bar for a 0–100 score (Stage B3)."""
    palette = Palette(config)
    try:
        v = max(0.0, min(100.0, float(value)))
    except (TypeError, ValueError):
        v = 0.0
    filled = int(round(v / 100.0 * width))
    filled = max(0, min(width, filled))
    bar_color = _score_style(v, config)
    return Text.assemble(
        ("█" * filled, bar_color),
        ("░" * (width - filled), palette.get("muted")),
    )


def _score_style(value: float, config: Dict[str, Any]) -> str:
    """Severity color for a 0–100 score (Stage B3)."""
    palette = Palette(config)
    try:
        v = float(value)
    except (TypeError, ValueError):
        return palette.get("muted")
    if v >= 80:
        return palette.get("danger")
    if v >= 60:
        return palette.get("warning")
    if v >= 40:
        return palette.get("primary")
    return palette.get("muted")


def _score_label_from_value(value: float, config: Dict[str, Any]) -> "Text":
    """Severity label for a 0–100 score (Stage B3)."""
    palette = Palette(config)
    try:
        v = float(value)
    except (TypeError, ValueError):
        return Text(_MISSING, style=palette.get("muted"))
    if v >= 80:
        label, color = "VERY_HIGH", palette.get("danger")
    elif v >= 60:
        label, color = "HIGH", palette.get("warning")
    elif v >= 40:
        label, color = "MODERATE", palette.get("primary")
    elif v >= 20:
        label, color = "LOW", palette.get("muted")
    else:
        label, color = "VERY_LOW", palette.get("muted")
    return Text(label, style=color)


def _assessment_style(label: Any, config: Dict[str, Any]) -> str:
    """Style for an assessment confidence label (Stage B3)."""
    palette = Palette(config)
    if not isinstance(label, str):
        return palette.get("muted")
    ll = label.upper()
    if ll == "HIGH":
        return palette.get("success")
    if ll == "MODERATE":
        return palette.get("warning")
    if ll == "LOW":
        return palette.get("muted")
    if ll == "VERY_LOW":
        return palette.get("danger")
    return palette.get("muted")


def _render_02_executive_summary(report, config):
    """
    Render Section 02 — EXECUTIVE SUMMARY (Stage B3).

    Shows assessment confidence + score, six scores with mini bars,
    and the one-line headline. Read-only: no values are computed.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        ex = (report.get("02_executive_summary", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(ex, dict):
            ex = {}
        scores = ex.get("scores", {}) or {}
        if not isinstance(scores, dict):
            scores = {}
        assessment = ex.get("assessment_confidence", _MISSING)
        assessment_score = ex.get("assessment_score", _MISSING)
        headline = ex.get("headline", _MISSING)

        # ---- Assessment line ----
        assessment_line = Text.assemble(
            ("Assessment Confidence  ", palette.get("muted")),
            (f"{assessment}", _assessment_style(assessment, config)),
            ("  ", ""),
            (f"({assessment_score})" if assessment_score != _MISSING and assessment_score is not None else "",
             palette.get("muted")),
        )

        # ---- Scores table with bar ----
        score_table = Table(
            show_header=True,
            header_style=palette.get("muted"),
            box=None,
            padding=(0, 1),
            expand=False,
        )
        score_table.add_column("Score", style=palette.get("muted"), no_wrap=True)
        score_table.add_column("Value", justify="right", no_wrap=True)
        score_table.add_column("Bar", no_wrap=True)
        score_table.add_column("Label", no_wrap=True)

        for key, label in (
            ("threat",         "Threat"),
            ("infrastructure", "Infrastructure"),
            ("data_quality",   "Data Quality"),
            ("exposure",       "Exposure"),
            ("anomaly",        "Anomaly"),
            ("coverage",       "Coverage"),
        ):
            value = scores.get(key)
            if value is None:
                score_table.add_row(label, _MISSING, _MISSING, _MISSING)
                continue
            try:
                v = float(value)
            except (TypeError, ValueError):
                score_table.add_row(label, str(value), _MISSING, _MISSING)
                continue
            bar = _score_bar(v, config)
            lbl = _score_label_from_value(v, config)
            score_table.add_row(label, f"{v:.1f}", bar, lbl)

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(assessment_line)
        body.add_row(Text(""))
        body.add_row(score_table)
        body.add_row(Text(""))
        body.add_row(Text.assemble(
            ("▸ ", palette.get("accent")),
            (str(headline), palette.get("highlight")),
        ))

        return section(2, "EXECUTIVE SUMMARY", body, config)
    except Exception as e:
        logging.debug(f"section 02 render failed: {e}")
        return _render_placeholder(2, "EXECUTIVE SUMMARY", config)


def _to_float(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _component_badges(components: Dict[str, Any],
                      config: Dict[str, Any]) -> List[str]:
    """Compact badges for the Data Quality header line (Stage B3)."""
    badges: List[str] = []
    try:
        if "ok_count" in components and "total_evidence" in components:
            badges.append(f"{components['ok_count']}/{components['total_evidence']} OK")
        if "freshness_avg" in components:
            badges.append(f"fresh {_to_float(components['freshness_avg']):.2f}")
        if "coverage" in components:
            badges.append(f"cov {_to_float(components['coverage']):.2f}")
    except Exception:
        pass
    return badges


def _render_03_data_quality(report, config):
    """
    Render Section 03 — DATA QUALITY (Stage B3).
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        dq = (report.get("03_data_quality", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(dq, dict):
            dq = {}
        score = dq.get("score", _MISSING)
        components = dq.get("components", {}) or {}
        if not isinstance(components, dict):
            components = {}
        explanation = dq.get("explanation", _MISSING)

        # Score header line
        score_text = Text.assemble(
            ("Score  ", palette.get("muted")),
            (f"{score}", _score_style(_to_float(score), config)),
            ("  ", ""),
            ("  ".join(_component_badges(components, config)), ""),
        )

        # Components breakdown
        comp_table = Table.grid(padding=(0, 2))
        comp_table.add_column(style=palette.get("muted"), no_wrap=True)
        comp_table.add_column(style=palette.get("value") or palette.get("highlight"))
        for key, label in (
            ("total_evidence",   "Evidence items"),
            ("ok_count",         "OK evidence"),
            ("freshness_avg",    "Freshness avg"),
            ("status_avg",       "Status avg"),
            ("coverage",         "Coverage"),
        ):
            comp_table.add_row(label, _present(components.get(key)))

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(score_text)
        body.add_row(Text(""))
        body.add_row(comp_table)
        body.add_row(Text(""))
        body.add_row(Text.assemble(
            ("▸ ", palette.get("accent")),
            (str(explanation), palette.get("muted")),
        ))

        return section(3, "DATA QUALITY", body, config)
    except Exception as e:
        logging.debug(f"section 03 render failed: {e}")
        return _render_placeholder(3, "DATA QUALITY", config)


def _render_04_network(report, config):
    """
    Render Section 04 — NETWORK INTELLIGENCE (Stage B3).
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        net = (report.get("04_network_intelligence", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(net, dict):
            net = {}
        asn = net.get("asn", {}) or {}
        prefix = net.get("prefix", {}) or {}
        org = net.get("organization", {}) or {}
        origin = net.get("origin", {}) or {}
        related = net.get("related_infrastructure", {}) or {}
        if not isinstance(asn, dict):
            asn = {}
        if not isinstance(prefix, dict):
            prefix = {}
        if not isinstance(org, dict):
            org = {}
        if not isinstance(origin, dict):
            origin = {}
        if not isinstance(related, dict):
            related = {}

        rows: List[Tuple[str, Any]] = [
            ("ASN",          asn.get("asn")),
            ("ASN Name",     _shorten(asn.get("asn_name"), _trunc_limit(config, "asn_name", 18))),
            ("ASN Type",     asn.get("type")),
            ("Country",      asn.get("country")),
            ("Prefix",       prefix.get("cidr")),
            ("Prefix Len",   prefix.get("prefix_length")),
            ("RIR",          prefix.get("rir")),
            ("Allocated",    prefix.get("allocated")),
            ("Organization", _shorten(org.get("name"), _trunc_limit(config, "organization_name", 18))),
            ("Abuse Email",  org.get("abuse_email")),
            ("Origin ASN",   origin.get("origin_asn")),
            ("Routing",      origin.get("routing_status")),
        ]

        grid = _kv_grid(rows, config, columns=2)

        # Related infrastructure (optional line)
        try:
            siblings = related.get("sibling_prefixes") or []
        except Exception:
            siblings = []
        if siblings:
            sibs = ", ".join(str(s) for s in siblings[:3])
            if len(siblings) > 3:
                sibs += f"  (+{len(siblings) - 3} more)"
            outer = Table.grid(padding=(0, 0))
            outer.add_column()
            outer.add_row(grid)
            outer.add_row(Text.assemble(
                ("Related: ", palette.get("muted")),
                (sibs, palette.get("value") or palette.get("highlight")),
            ))
            body = outer
        else:
            body = grid

        return section(4, "NETWORK INTELLIGENCE", body, config)
    except Exception as e:
        logging.debug(f"section 04 render failed: {e}")
        return _render_placeholder(4, "NETWORK INTELLIGENCE", config)


def _security_flags_line(flags: List[Tuple[str, str, str]],
                         config: Dict[str, Any]) -> "Text":
    """Compact SPF/DMARC/CAA flag line (Stage B3)."""
    palette = Palette(config)
    parts: List[Tuple[str, str]] = [("Security  ", palette.get("muted"))]
    first = True
    for label, value, style in flags:
        if not first:
            parts.append(("  ", ""))
        first = False
        parts.append((f"{label}:", palette.get("muted")))
        parts.append((" ", ""))
        parts.append((str(value), style))
    return Text.assemble(*parts)


def _anomaly_count_style(n: int, config: Dict[str, Any]) -> str:
    """Severity color for an anomaly count (Stage B3)."""
    palette = Palette(config)
    try:
        count = int(n)
    except (TypeError, ValueError):
        return palette.get("muted")
    if count == 0:
        return palette.get("success")
    if count <= 2:
        return palette.get("warning")
    return palette.get("danger")


def _render_05_dns(report, config):
    """
    Render Section 05 — DNS INTELLIGENCE (Stage B3).

    Shows record-type counts, SPF/DMARC/CAA flags, first values per
    type, and the anomaly count. Read-only.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        dns = (report.get("05_dns_intelligence", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(dns, dict):
            dns = {}
        analysis = dns.get("analysis", {}) or {}
        if not isinstance(analysis, dict):
            analysis = {}
        evidence = dns.get("evidence", []) or []
        if not isinstance(evidence, list):
            evidence = []

        # ---- Records summary by type ----
        counts = analysis.get("record_counts", {}) or {}
        if not isinstance(counts, dict) or not counts:
            # Fallback: count from evidence
            counts = {}
            for ev in evidence:
                if not isinstance(ev, dict) or ev.get("status") != "OK":
                    continue
                try:
                    rt = (ev.get("metadata", {}) or {}).get("record_type", "UNKNOWN")
                except Exception:
                    rt = "UNKNOWN"
                counts[rt] = counts.get(rt, 0) + 1

        records_line = "  ".join(
            f"{rt}={counts[rt]}" for rt in sorted(counts)
        ) or _MISSING

        # ---- Security flags ----
        security = analysis.get("security", {}) or {}
        if not isinstance(security, dict):
            security = {}
        flags: List[Tuple[str, str, str]] = []  # (label, value, style)
        for key, label in (
            ("spf_present",   "SPF"),
            ("dmarc_present", "DMARC"),
            ("caa_present",   "CAA"),
        ):
            val = security.get(key)
            if val is True:
                flags.append((label, "present", palette.get("success")))
            elif val is False:
                flags.append((label, "missing", palette.get("warning")))
            else:
                flags.append((label, _MISSING, palette.get("muted")))

        # ---- Records of interest ----
        def _first_value(rtype: str) -> str:
            for ev in evidence:
                if not isinstance(ev, dict) or ev.get("status") != "OK":
                    continue
                try:
                    if (ev.get("metadata", {}) or {}).get("record_type") == rtype:
                        return _present(ev.get("normalized_value"))
                except Exception:
                    continue
            return _MISSING

        rows: List[Tuple[str, Any]] = [
            ("A",     _first_value("A")),
            ("AAAA",  _first_value("AAAA")),
            ("PTR",   _first_value("PTR")),
            ("NS",    _shorten(_first_value("NS"), _trunc_limit(config, "ns_preview", 40))),
            ("MX",    _first_value("MX")),
            ("CNAME", _first_value("CNAME")),
            ("TXT",   _first_value("TXT")),
            ("CAA",   _first_value("CAA")),
            ("SOA",   _first_value("SOA")),
        ]

        records_grid = _kv_grid(rows, config, columns=2)

        # ---- Anomaly line ----
        anomalies = analysis.get("anomalies", []) or []
        if not isinstance(anomalies, list):
            anomalies = []
        anomalies_line = Text.assemble(
            ("Anomalies  ", palette.get("muted")),
            (str(len(anomalies)), _anomaly_count_style(len(anomalies), config)),
        )

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(Text(f"Records  {records_line}", style=palette.get("muted")))
        body.add_row(_security_flags_line(flags, config))
        body.add_row(Text(""))
        body.add_row(records_grid)
        body.add_row(anomalies_line)

        return section(5, "DNS INTELLIGENCE", body, config)
    except Exception as e:
        logging.debug(f"section 05 render failed: {e}")
        return _render_placeholder(5, "DNS INTELLIGENCE", config)


def _short_date(iso: Optional[str]) -> str:
    """Trim an ISO8601 timestamp to YYYY-MM-DD (Stage B3)."""
    if not iso:
        return _MISSING
    try:
        s = str(iso).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return str(iso)


def _short_fp(fp: Optional[str]) -> str:
    """Truncate a fingerprint to first8…last8 (Stage B3)."""
    if not fp:
        return _MISSING
    s = str(fp)
    if len(s) <= 16:
        return s
    return s[:8] + "…" + s[-8:]


def _key_summary(live: Dict[str, Any]) -> str:
    """Summarize key type + size (Stage B3)."""
    try:
        kt = live.get("key_type")
        ks = live.get("key_size")
    except Exception:
        return _MISSING
    if kt and ks:
        return f"{kt} {ks}"
    if kt:
        return str(kt)
    return _MISSING


def _count_style(n: int, config: Dict[str, Any]) -> str:
    """Severity color for a counter (Stage B3)."""
    palette = Palette(config)
    try:
        count = int(n)
    except (TypeError, ValueError):
        return palette.get("muted")
    if count == 0:
        return palette.get("success")
    if count <= 1:
        return palette.get("warning")
    return palette.get("danger")


def _render_06_certificate(report, config):
    """
    Render Section 06 — CERTIFICATE INTELLIGENCE (Stage B3).

    Shows live certificate summary, SAN preview, and CT counters.
    Read-only.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        ci = (report.get("06_certificate_intelligence", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(ci, dict):
            ci = {}
        live = ci.get("live_certificate") or {}
        if not isinstance(live, dict):
            live = {}
        ct_certs = ci.get("ct_certificates", []) or []
        if not isinstance(ct_certs, list):
            ct_certs = []
        summary = ci.get("summary", {}) or {}
        if not isinstance(summary, dict):
            summary = {}

        if not live and not ct_certs:
            empty = Text("No certificate data available.", style=palette.get("muted"))
            return section(6, "CERTIFICATE INTELLIGENCE", empty, config)

        # ---- Live certificate rows ----
        rows: List[Tuple[str, Any]] = []
        if live:
            rows.extend([
                ("Subject CN",  _shorten(live.get("subject_cn"), _trunc_limit(config, "subject_cn", 30))),
                ("Issuer CN",   _shorten(live.get("issuer_cn"), _trunc_limit(config, "issuer_cn", 14))),
                ("Issuer O",    _shorten(live.get("issuer_o"), _trunc_limit(config, "issuer_o", 18))),
                ("Valid From",  _short_date(live.get("not_before"))),
                ("Valid To",    _short_date(live.get("not_after"))),
                ("Key",         _key_summary(live)),
                ("Sig Algo",    live.get("signature_algorithm")),
                ("Wildcard",    live.get("wildcard")),
                ("Fingerprint", _short_fp(live.get("fingerprint_sha256"))),
            ])
        else:
            rows.append(("Live cert", _MISSING))

        live_grid = _kv_grid(rows, config, columns=2)

        # ---- SAN preview ----
        try:
            sans = (live.get("san_domains") or []) if live else []
        except Exception:
            sans = []
        if sans:
            preview = ", ".join(str(s) for s in sans[:4])
            if len(sans) > 4:
                preview += f"  (+{len(sans) - 4} more)"
            san_line = Text.assemble(
                ("SANs  ", palette.get("muted")),
                (preview, palette.get("value") or palette.get("highlight")),
            )
        else:
            san_line = Text.assemble(
                ("SANs  ", palette.get("muted")),
                (_MISSING, palette.get("muted")),
            )

        # ---- Counters ----
        total_ct = summary.get("total_certificates", len(ct_certs))
        expired = summary.get("expired_count", 0)
        weak = summary.get("weak_algo_count", 0)
        wildcard = summary.get("wildcard_count", 0)

        counters = Text.assemble(
            ("CT certs  ", palette.get("muted")),
            (str(total_ct), palette.get("highlight")),
            ("   Expired  ", palette.get("muted")),
            (str(expired), _count_style(expired, config)),
            ("   Weak algo  ", palette.get("muted")),
            (str(weak), _count_style(weak, config)),
            ("   Wildcard  ", palette.get("muted")),
            (str(wildcard), palette.get("highlight")),
        )

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(live_grid)
        body.add_row(san_line)
        body.add_row(counters)

        return section(6, "CERTIFICATE INTELLIGENCE", body, config)
    except Exception as e:
        logging.debug(f"section 06 render failed: {e}")
        return _render_placeholder(6, "CERTIFICATE INTELLIGENCE", config)


def _lifecycle_style(lifecycle: Any, config: Dict[str, Any]) -> str:
    """Severity color for a passive-DNS lifecycle state (Stage B4)."""
    palette = Palette(config)
    if not isinstance(lifecycle, str):
        return palette.get("muted")
    ll = lifecycle.upper()
    if ll == "ACTIVE":
        return palette.get("success")
    if ll == "HISTORICAL":
        return palette.get("muted")
    return palette.get("warning")


def _render_07_passive_dns(report, config):
    """
    Render Section 07 — PASSIVE DNS (Stage B4). Read-only.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        pdns = (report.get("07_passive_dns", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(pdns, dict):
            pdns = {}
        timeline = pdns.get("timeline", []) or []
        stats = pdns.get("stats", {}) or {}
        related = pdns.get("related_domains", []) or []
        anomalies = pdns.get("anomalies", []) or []
        if not isinstance(timeline, list):
            timeline = []
        if not isinstance(stats, dict):
            stats = {}
        if not isinstance(related, list):
            related = []
        if not isinstance(anomalies, list):
            anomalies = []

        if not timeline and not stats:
            body = Text("No passive DNS data available.",
                        style=palette.get("muted"))
            return section(7, "PASSIVE DNS", body, config)

        # ---- Stat line ----
        stat_line = Text.assemble(
            ("Domains  ", palette.get("muted")),
            (str(stats.get("total_domains", len(timeline))), palette.get("highlight")),
            ("   Active  ", palette.get("muted")),
            (str(stats.get("active_count", 0)), palette.get("success")),
            ("   Historical  ", palette.get("muted")),
            (str(stats.get("historical_count", 0)), palette.get("muted")),
            ("   Churn  ", palette.get("muted")),
            (str(stats.get("churn_count", 0)),
             _count_style(stats.get("churn_count", 0), config)),
        )

        # ---- Timeline table (top 8 entries) ----
        timeline_table = Table(
            show_header=True,
            header_style=palette.get("muted"),
            box=None,
            padding=(0, 1),
            expand=False,
        )
        timeline_table.add_column("Domain", style=palette.get("value") or palette.get("highlight"))
        timeline_table.add_column("First Seen", style=palette.get("muted"), no_wrap=True)
        timeline_table.add_column("Last Seen", style=palette.get("muted"), no_wrap=True)
        timeline_table.add_column("Lifecycle", no_wrap=True)

        _tl_limit = _trunc_limit(config, "passive_dns_timeline", 5)
        for entry in timeline[:_tl_limit]:
            if not isinstance(entry, dict):
                continue
            domain = entry.get("domain", _MISSING)
            first = _short_date(entry.get("first_seen"))
            last = _short_date(entry.get("last_seen"))
            lifecycle = entry.get("lifecycle", _MISSING)
            style = _lifecycle_style(lifecycle, config)
            timeline_table.add_row(
                str(domain), first, last,
                Text(str(lifecycle), style=style),
            )

        if len(timeline) > _tl_limit:
            timeline_table.add_row(
                f"[dim]+{len(timeline) - _tl_limit} more[/dim]", "", "", ""
            )

        # ---- Anomalies line ----
        anomalies_line = Text.assemble(
            ("Anomalies  ", palette.get("muted")),
            (str(len(anomalies)), _count_style(len(anomalies), config)),
        )

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(stat_line)
        body.add_row(Text(""))
        body.add_row(timeline_table)
        body.add_row(anomalies_line)

        # Related domains (optional)
        if related:
            try:
                preview = _truncate_list(
                    [f"{r.get('domain_a')} ↔ {r.get('domain_b')}" for r in related
                     if isinstance(r, dict)],
                    limit=3,
                )
            except Exception:
                preview = _MISSING
            body.add_row(Text.assemble(
                ("Related  ", palette.get("muted")),
                (preview, palette.get("value") or palette.get("highlight")),
            ))

        return section(7, "PASSIVE DNS", body, config)
    except Exception as e:
        logging.debug(f"section 07 render failed: {e}")
        return _render_placeholder(7, "PASSIVE DNS", config)


def _sev_style(sev: Any, config: Dict[str, Any]) -> str:
    """Severity color for a change severity (Stage B4)."""
    palette = Palette(config)
    s = str(sev).lower()
    if s == "critical":
        return palette.get("danger")
    if s == "high":
        return palette.get("danger")
    if s == "moderate":
        return palette.get("warning")
    if s == "low":
        return palette.get("muted")
    return palette.get("muted")


def _short_val(v: Any, max_len: int = 24) -> str:
    """Truncate a value for table cells (Stage B4)."""
    s = _present(v)
    if len(s) > max_len:
        return s[:max_len - 1] + "…"
    return s


def _render_08_history(report, config):
    """
    Render Section 08 — HISTORICAL INTELLIGENCE (Stage B4). Read-only.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        hist = (report.get("08_historical_intelligence", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(hist, dict):
            hist = {}
        status = hist.get("status", "UNKNOWN")
        prev_ts = hist.get("previous_timestamp")
        curr_ts = hist.get("current_timestamp")
        detection = hist.get("detection", {}) or {}
        if not isinstance(detection, dict):
            detection = {}

        if status == "FIRST_OBSERVATION":
            body = Text.assemble(
                ("No previous snapshot found. Baseline established.", palette.get("muted")),
                "\n",
                ("Current timestamp: ", palette.get("muted")),
                (str(curr_ts or _MISSING), palette.get("highlight")),
            )
            return section(8, "HISTORICAL INTELLIGENCE", body, config)

        if status != "COMPARED":
            body = Text(f"Historical status: {status}",
                        style=palette.get("muted"))
            return section(8, "HISTORICAL INTELLIGENCE", body, config)

        # ---- Comparison window ----
        window_line = Text.assemble(
            ("Previous  ", palette.get("muted")),
            (str(prev_ts or _MISSING), palette.get("value") or palette.get("highlight")),
            ("   Current  ", palette.get("muted")),
            (str(curr_ts or _MISSING), palette.get("value") or palette.get("highlight")),
        )

        # ---- Severity summary ----
        by_sev = detection.get("by_severity", {}) or {}
        if not isinstance(by_sev, dict):
            by_sev = {}
        severity_line = Text.assemble(
            ("Changes  ", palette.get("muted")),
            (str(detection.get("total_changes", 0)), palette.get("highlight")),
            ("   ", ""),
            ("critical=", palette.get("muted")),
            (str(by_sev.get("critical", 0)), _sev_style("critical", config)),
            ("  ", ""),
            ("high=", palette.get("muted")),
            (str(by_sev.get("high", 0)), _sev_style("high", config)),
            ("  ", ""),
            ("moderate=", palette.get("muted")),
            (str(by_sev.get("moderate", 0)), _sev_style("moderate", config)),
            ("  ", ""),
            ("low=", palette.get("muted")),
            (str(by_sev.get("low", 0)), _sev_style("low", config)),
        )

        # ---- Changes table (top 8) ----
        changes = detection.get("changes", []) or []
        if not isinstance(changes, list):
            changes = []
        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(window_line)
        body.add_row(severity_line)
        body.add_row(Text(""))
        if changes:
            change_table = Table(
                show_header=True,
                header_style=palette.get("muted"),
                box=None,
                padding=(0, 1),
                expand=False,
            )
            change_table.add_column("Severity", no_wrap=True)
            change_table.add_column("Key", style=palette.get("value") or palette.get("highlight"))
            change_table.add_column("Old → New", style=palette.get("muted"))

            for ch in changes[:8]:
                if not isinstance(ch, dict):
                    continue
                sev = ch.get("severity", "informational")
                key = ch.get("key", _MISSING)
                old = _short_val(ch.get("old"))
                new = _short_val(ch.get("new"))
                change_table.add_row(
                    Text(str(sev).upper(), style=_sev_style(sev, config)),
                    str(key),
                    f"{old} → {new}",
                )

            if len(changes) > 8:
                change_table.add_row(
                    f"[dim]+{len(changes) - 8} more[/dim]", "", ""
                )
            body.add_row(change_table)
        else:
            body.add_row(Text("No changes detected since previous snapshot.",
                              style=palette.get("success")))

        return section(8, "HISTORICAL INTELLIGENCE", body, config)
    except Exception as e:
        logging.debug(f"section 08 render failed: {e}")
        return _render_placeholder(8, "HISTORICAL INTELLIGENCE", config)


def _provider_status_style(status: Any, config: Dict[str, Any]) -> str:
    """Status color for a threat provider row (Stage B4)."""
    palette = Palette(config)
    s = str(status).upper()
    if s == "OK":
        return palette.get("success")
    if s == "FAILED":
        return palette.get("danger")
    if s == "NOT_CONFIGURED":
        return palette.get("warning")
    if s == "DISABLED":
        return palette.get("muted")
    return palette.get("muted")


def _render_09_threat(report, config):
    """
    Render Section 09 — THREAT INTELLIGENCE (Stage B4). Read-only.

    Never hides provider failures: FAILED and NOT_CONFIGURED rows
    are always shown, and the failure line is always present.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        ti = (report.get("09_threat_intelligence", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(ti, dict):
            ti = {}
        normalized = ti.get("normalized", []) or []
        failures = ti.get("failures", {}) or {}
        if not isinstance(normalized, list):
            normalized = []
        if not isinstance(failures, dict):
            failures = {}

        # ---- Metric line ----
        try:
            observed = float(ti.get("observed_threat_score", 0.0))
        except (TypeError, ValueError):
            observed = 0.0
        try:
            coverage = float(ti.get("evidence_coverage", 0.0))
            agreement = float(ti.get("provider_agreement", 0.0))
            freshness = float(ti.get("data_freshness", 0.0))
            threat_conf = float(ti.get("threat_confidence", 0.0))
        except (TypeError, ValueError):
            coverage = agreement = freshness = threat_conf = 0.0

        metrics_line = Text.assemble(
            ("Observed  ", palette.get("muted")),
            (f"{observed:.1f}", _score_style(observed, config)),
            ("   Coverage  ", palette.get("muted")),
            (f"{coverage * 100:.1f}%", palette.get("highlight")),
            ("   Agreement  ", palette.get("muted")),
            (f"{agreement * 100:.1f}%", palette.get("highlight")),
            ("   Freshness  ", palette.get("muted")),
            (f"{freshness * 100:.1f}%", palette.get("highlight")),
            ("   Confidence  ", palette.get("muted")),
            (f"{threat_conf * 100:.1f}%",
             _score_style(threat_conf * 100, config)),
        )

        # ---- Provider table ----
        provider_table = Table(
            show_header=True,
            header_style=palette.get("muted"),
            box=None,
            padding=(0, 1),
            expand=False,
        )
        provider_table.add_column("Provider", style=palette.get("value") or palette.get("highlight"))
        provider_table.add_column("Status", no_wrap=True)
        provider_table.add_column("Score", justify="right")
        provider_table.add_column("Conf", justify="right")
        provider_table.add_column("Cache", justify="center")

        for entry in normalized:
            if not isinstance(entry, dict):
                continue
            name = entry.get("source", _MISSING)
            status = entry.get("status", "UNKNOWN")
            score = entry.get("threat_score")
            conf = entry.get("confidence", 0.0)
            try:
                meta = entry.get("metadata", {}) or {}
            except Exception:
                meta = {}
            if not isinstance(meta, dict):
                meta = {}
            cache_status = meta.get("cache_status", "-")

            status_style = _provider_status_style(status, config)
            provider_table.add_row(
                str(name),
                Text(str(status), style=status_style),
                f"{score:.2f}" if isinstance(score, (int, float)) else _MISSING,
                f"{conf:.2f}" if isinstance(conf, (int, float)) else _MISSING,
                str(cache_status),
            )

        # ---- Failure line (always shown) ----
        failed = failures.get("failed", []) or []
        not_config = failures.get("not_configured", []) or []
        if not isinstance(failed, list):
            failed = []
        if not isinstance(not_config, list):
            not_config = []

        if failed or not_config:
            failure_line = Text.assemble(
                ("Failures  ", palette.get("muted")),
                (f"{len(failed)} failed", palette.get("danger") if failed else palette.get("muted")),
                ("   ", ""),
                (f"{len(not_config)} not configured",
                 palette.get("warning") if not_config else palette.get("muted")),
                ("   ", ""),
                ("(absence of data ≠ absence of threat)",
                 palette.get("muted")),
            )
        else:
            failure_line = Text.assemble(
                ("Failures  ", palette.get("muted")),
                ("none", palette.get("success")),
            )

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(metrics_line)
        body.add_row(Text(""))
        body.add_row(provider_table)
        body.add_row(failure_line)

        return section(9, "THREAT INTELLIGENCE", body, config)
    except Exception as e:
        logging.debug(f"section 09 render failed: {e}")
        return _render_placeholder(9, "THREAT INTELLIGENCE", config)


def _render_10_correlation(report, config):
    """
    Render Section 10 — INFRASTRUCTURE CORRELATION (Stage B4). Read-only.

    Correlation is evidence, not a verdict: the closing note is always
    shown.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        corr = (report.get("10_infrastructure_correlation", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(corr, dict):
            corr = {}
        graph_stats = corr.get("graph_stats", {}) or {}
        shared = corr.get("shared", {}) or {}
        related_targets = corr.get("related_targets", []) or []
        if not isinstance(graph_stats, dict):
            graph_stats = {}
        if not isinstance(shared, dict):
            shared = {}
        if not isinstance(related_targets, list):
            related_targets = []

        # ---- Graph summary ----
        try:
            node_count = int(graph_stats.get("node_count", 0))
        except (TypeError, ValueError):
            node_count = 0
        try:
            edge_count = int(graph_stats.get("edge_count", 0))
        except (TypeError, ValueError):
            edge_count = 0
        graph_line = Text.assemble(
            ("Nodes  ", palette.get("muted")),
            (str(node_count), palette.get("highlight")),
            ("   Edges  ", palette.get("muted")),
            (str(edge_count), palette.get("highlight")),
        )

        node_types = graph_stats.get("node_types", {}) or {}
        if isinstance(node_types, dict) and node_types:
            types_line = Text.assemble(
                ("Node types  ", palette.get("muted")),
                (_truncate_list(
                    [f"{k}={v}" for k, v in sorted(node_types.items())],
                    limit=_trunc_limit(config, "node_types_preview", 4)
                ), palette.get("value") or palette.get("highlight")),
            )
        else:
            types_line = Text("")

        # ---- Shared entities table ----
        def _shared_len(key: str) -> int:
            try:
                val = shared.get(key, []) or []
                return len(val) if isinstance(val, list) else 0
            except Exception:
                return 0

        shared_rows: List[Tuple[str, int]] = [
            ("ASNs",          _shared_len("shared_asns")),
            ("Prefixes",      _shared_len("shared_prefixes")),
            ("Certificates",  _shared_len("shared_certificates")),
            ("Nameservers",   _shared_len("shared_nameservers")),
            ("Mailservers",   _shared_len("shared_mailservers")),
            ("Organizations", _shared_len("shared_organizations")),
        ]

        shared_table = Table(
            show_header=True,
            header_style=palette.get("muted"),
            box=None,
            padding=(0, 1),
            expand=False,
        )
        shared_table.add_column("Shared Entity", style=palette.get("muted"))
        shared_table.add_column("Count", justify="right")

        for label, count in shared_rows:
            style = palette.get("warning") if count > 0 else palette.get("muted")
            shared_table.add_row(label, Text(str(count), style=style))

        # ---- Related targets ----
        if related_targets:
            try:
                pairs_preview = ", ".join(
                    f"{r.get('target_a')} ↔ {r.get('target_b')} ({r.get('shared_count')})"
                    for r in related_targets[:3] if isinstance(r, dict)
                ) or _MISSING
            except Exception:
                pairs_preview = _MISSING
            related_line = Text.assemble(
                ("Related targets  ", palette.get("muted")),
                (pairs_preview, palette.get("value") or palette.get("highlight")),
            )
        else:
            related_line = Text.assemble(
                ("Related targets  ", palette.get("muted")),
                ("none", palette.get("muted")),
            )

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(graph_line)
        body.add_row(types_line)
        body.add_row(Text(""))
        body.add_row(shared_table)
        body.add_row(related_line)
        body.add_row(Text(""))
        body.add_row(Text("Relationship ≠ Maliciousness.", style=palette.get("muted")))

        return section(10, "INFRASTRUCTURE CORRELATION", body, config)
    except Exception as e:
        logging.debug(f"section 10 render failed: {e}")
        return _render_placeholder(10, "INFRASTRUCTURE CORRELATION", config)


def _risk_style(risk: Any, config: Dict[str, Any]) -> str:
    """Severity color for a service risk class (Stage B4)."""
    palette = Palette(config)
    r = str(risk).lower()
    if r in ("critical", "high"):
        return palette.get("danger")
    if r == "moderate":
        return palette.get("warning")
    if r == "low":
        return palette.get("muted")
    return palette.get("muted")


def _render_11_attack_surface(report, config):
    """
    Render Section 11 — ATTACK SURFACE (Stage B4). Read-only.

    OPEN ≠ VULNERABLE: the closing note is always shown.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        asx = (report.get("11_attack_surface", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(asx, dict):
            asx = {}
        services = asx.get("services", []) or []
        exposure = asx.get("exposure", {}) or {}
        if not isinstance(services, list):
            services = []
        if not isinstance(exposure, dict):
            exposure = {}

        if not services:
            body = Text("No exposed services identified.",
                        style=palette.get("muted"))
            return section(11, "ATTACK SURFACE", body, config)

        # ---- Exposure summary ----
        try:
            service_count = int(asx.get("service_count", len(services)))
        except (TypeError, ValueError):
            service_count = len(services)
        try:
            sensitive_count = int(asx.get("sensitive_count", 0))
        except (TypeError, ValueError):
            sensitive_count = 0
        try:
            external_count = int(exposure.get("external_count", 0))
        except (TypeError, ValueError):
            external_count = 0
        try:
            internal_count = int(exposure.get("internal_count", 0))
        except (TypeError, ValueError):
            internal_count = 0
        exposure_line = Text.assemble(
            ("Services  ", palette.get("muted")),
            (str(service_count), palette.get("highlight")),
            ("   Sensitive  ", palette.get("muted")),
            (str(sensitive_count),
             _count_style(sensitive_count, config)),
            ("   External  ", palette.get("muted")),
            (str(external_count), palette.get("highlight")),
            ("   Internal  ", palette.get("muted")),
            (str(internal_count), palette.get("muted")),
        )

        # ---- Services table ----
        svc_table = Table(
            show_header=True,
            header_style=palette.get("muted"),
            box=None,
            padding=(0, 1),
            expand=False,
        )
        svc_table.add_column("Port", no_wrap=True, justify="right")
        svc_table.add_column("Proto", no_wrap=True)
        svc_table.add_column("Service", style=palette.get("value") or palette.get("highlight"))
        svc_table.add_column("Risk", no_wrap=True)
        svc_table.add_column("Sensitive", justify="center")

        for svc in services[:12]:
            if not isinstance(svc, dict):
                continue
            port = svc.get("port", _MISSING)
            proto = svc.get("protocol", _MISSING)
            service = svc.get("service", _MISSING)
            risk = svc.get("risk_class", "unknown")
            sensitive = svc.get("sensitive", False)

            risk_style = _risk_style(risk, config)
            sens_text = Text("yes", style=palette.get("danger")) if sensitive \
                else Text("no", style=palette.get("muted"))

            svc_table.add_row(
                str(port), str(proto), str(service),
                Text(str(risk).upper(), style=risk_style),
                sens_text,
            )

        if len(services) > 12:
            svc_table.add_row(
                f"[dim]+{len(services) - 12} more[/dim]",
                "", "", "", ""
            )

        # ---- Note ----
        note = Text("OPEN ≠ VULNERABLE.", style=palette.get("muted"))

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(exposure_line)
        body.add_row(Text(""))
        body.add_row(svc_table)
        body.add_row(note)

        return section(11, "ATTACK SURFACE", body, config)
    except Exception as e:
        logging.debug(f"section 11 render failed: {e}")
        return _render_placeholder(11, "ATTACK SURFACE", config)


def _tech_status_style(status: Any, config: Dict[str, Any]) -> str:
    """Status color for a technology fingerprint row (Stage B4)."""
    palette = Palette(config)
    s = str(status).upper()
    if s == "OK":
        return palette.get("success")
    if s == "INSUFFICIENT_EVIDENCE":
        return palette.get("warning")
    if s == "UNKNOWN":
        return palette.get("muted")
    return palette.get("muted")


def _render_12_technology(report, config):
    """
    Render Section 12 — TECHNOLOGY (Stage B4). Read-only.

    Never claims technology without evidence: rows without a matched
    signature show the provider status (often INSUFFICIENT_EVIDENCE).
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        tech = (report.get("12_technology", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(tech, dict):
            tech = {}
        results = tech.get("results", []) or []
        summary = tech.get("summary", {}) or {}
        if not isinstance(results, list):
            results = []
        if not isinstance(summary, dict):
            summary = {}

        if not results:
            body = Text("No technology fingerprinting data available.",
                        style=palette.get("muted"))
            return section(12, "TECHNOLOGY", body, config)

        # ---- Summary line ----
        def _int(key: str, default: int = 0) -> int:
            try:
                return int(summary.get(key, default))
            except (TypeError, ValueError):
                return default

        summary_line = Text.assemble(
            ("Analyzed  ", palette.get("muted")),
            (str(_int("services_analyzed", len(results))), palette.get("highlight")),
            ("   Identified  ", palette.get("muted")),
            (str(_int("technologies_identified")), palette.get("success")),
            ("   Insufficient  ", palette.get("muted")),
            (str(_int("insufficient_evidence")), palette.get("warning")),
            ("   Unknown  ", palette.get("muted")),
            (str(_int("unknown")), palette.get("muted")),
        )

        # ---- Technology table ----
        tech_table = Table(
            show_header=True,
            header_style=palette.get("muted"),
            box=None,
            padding=(0, 1),
            expand=False,
        )
        tech_table.add_column("Port", no_wrap=True, justify="right")
        tech_table.add_column("Service", style=palette.get("muted"), no_wrap=True)
        tech_table.add_column("Product", style=palette.get("value") or palette.get("highlight"))
        tech_table.add_column("Version", no_wrap=True)
        tech_table.add_column("Conf", justify="right", no_wrap=True)
        tech_table.add_column("Status", no_wrap=True)

        rows_added = 0
        for result in results:
            if not isinstance(result, dict):
                continue
            port = result.get("port", _MISSING)
            service = result.get("service", _MISSING)
            status = result.get("status", "UNKNOWN")
            techs = result.get("technology", []) or []
            if not isinstance(techs, list):
                techs = []

            if not techs:
                tech_table.add_row(
                    str(port), str(service), _MISSING, _MISSING, _MISSING,
                    Text(str(status), style=_tech_status_style(status, config)),
                )
                rows_added += 1
            else:
                for t in techs:
                    if not isinstance(t, dict):
                        continue
                    try:
                        conf = float(t.get("confidence", 0))
                        conf_s = f"{conf:.2f}"
                    except (TypeError, ValueError):
                        conf_s = _MISSING
                    tech_table.add_row(
                        str(port),
                        str(service),
                        str(t.get("product", _MISSING)),
                        str(t.get("version") or _MISSING),
                        conf_s,
                        Text(str(status), style=_tech_status_style(status, config)),
                    )
                    rows_added += 1

            if rows_added >= 12:
                break

        if rows_added < len(results):
            tech_table.add_row(
                f"[dim]+{len(results) - rows_added} more[/dim]",
                "", "", "", "", ""
            )

        # ---- Notes ----
        note = Text("A banner is a hint, not a fact. UNKNOWN is honest.",
                    style=palette.get("muted"))

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(summary_line)
        body.add_row(Text(""))
        body.add_row(tech_table)
        body.add_row(note)

        return section(12, "TECHNOLOGY", body, config)
    except Exception as e:
        logging.debug(f"section 12 render failed: {e}")
        return _render_placeholder(12, "TECHNOLOGY", config)


def _section_summary_line(pairs: List[Tuple[str, Any]],
                          config: Dict[str, Any]) -> "Text":
    """
    Build a one-line summary from (label, value) pairs (Stage B5).
    """
    palette = Palette(config)
    parts: List[Tuple[str, str]] = []
    for i, (label, value) in enumerate(pairs):
        if i > 0:
            parts.append(("   ", ""))
        parts.append((f"{label} ", palette.get("muted")))
        parts.append((_present(value), palette.get("highlight")))
    return Text.assemble(*parts)


def _cve_severity_label(sev: Any) -> str:
    """CVSS float → severity label (Stage B5)."""
    try:
        v = float(sev)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if v >= 9.0:
        return "CRITICAL"
    if v >= 7.0:
        return "HIGH"
    if v >= 4.0:
        return "MEDIUM"
    if v > 0:
        return "LOW"
    return "UNKNOWN"


def _cve_severity_key(sev: Any) -> str:
    """CVSS float → severity key for styling (Stage B5)."""
    try:
        v = float(sev)
    except (TypeError, ValueError):
        return "informational"
    if v >= 9.0:
        return "critical"
    if v >= 7.0:
        return "high"
    if v >= 4.0:
        return "moderate"
    if v > 0:
        return "low"
    return "informational"


def _candidate_status_style(status: Any, config: Dict[str, Any]) -> str:
    """Status color for a vulnerability candidate row (Stage B5)."""
    palette = Palette(config)
    s = str(status).upper()
    if s == "CANDIDATE":
        return palette.get("warning")
    if s == "NEEDS_VALIDATION":
        return palette.get("accent")
    if s == "CONFIRMED":
        return palette.get("danger")
    return palette.get("muted")


def _render_13_vulnerability(report, config):
    """
    Render Section 13 — VULNERABILITY CANDIDATES (Stage B5). Read-only.

    A candidate is not a confirmed vulnerability: the warning note is
    always shown.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        vuln = (report.get("13_vulnerability_candidates", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(vuln, dict):
            vuln = {}
        candidates = vuln.get("candidates", []) or []
        summary = vuln.get("summary", {}) or {}
        if not isinstance(candidates, list):
            candidates = []
        if not isinstance(summary, dict):
            summary = {}

        if not candidates:
            body = Text.assemble(
                ("No vulnerability candidates identified.", palette.get("muted")),
                "\n",
                ("Reason: no technology with a confident version was identified.",
                 palette.get("muted")),
            )
            return section(13, "VULNERABILITY CANDIDATES", body, config)

        # ---- Summary line ----
        by_sev = summary.get("by_severity", {}) or {}
        if not isinstance(by_sev, dict):
            by_sev = {}
        try:
            total_c = int(summary.get("candidates", len(candidates)))
        except (TypeError, ValueError):
            total_c = len(candidates)
        summary_line = Text.assemble(
            ("Candidates  ", palette.get("muted")),
            (str(total_c), palette.get("highlight")),
            ("   ", ""),
            ("critical=", palette.get("muted")),
            (str(by_sev.get("critical", 0)), _sev_style("critical", config)),
            ("  ", ""),
            ("high=", palette.get("muted")),
            (str(by_sev.get("high", 0)), _sev_style("high", config)),
            ("  ", ""),
            ("medium=", palette.get("muted")),
            (str(by_sev.get("medium", 0)), _sev_style("moderate", config)),
            ("  ", ""),
            ("low=", palette.get("muted")),
            (str(by_sev.get("low", 0)), _sev_style("low", config)),
        )

        # ---- Candidate table (top 8) ----
        table = Table(
            show_header=True,
            header_style=palette.get("muted"),
            box=None,
            padding=(0, 1),
            expand=False,
        )
        table.add_column("Severity", no_wrap=True)
        table.add_column("CVE", style=palette.get("highlight"), no_wrap=True)
        table.add_column("Product", style=palette.get("value") or "")
        table.add_column("Version", no_wrap=True)
        table.add_column("Status", no_wrap=True)

        for c in candidates[:8]:
            if not isinstance(c, dict):
                continue
            sev = c.get("severity")
            sev_label = _cve_severity_label(sev)
            sev_style = _sev_style(_cve_severity_key(sev), config)
            try:
                tech = c.get("technology", {}) or {}
            except Exception:
                tech = {}
            if not isinstance(tech, dict):
                tech = {}
            table.add_row(
                Text(sev_label, style=sev_style),
                str(c.get("cve", _MISSING)),
                str(tech.get("product", _MISSING)),
                str(tech.get("version") or _MISSING),
                Text(str(c.get("status", "CANDIDATE")),
                     style=_candidate_status_style(c.get("status"), config)),
            )

        if len(candidates) > 8:
            table.add_row(f"[dim]+{len(candidates) - 8} more[/dim]",
                          "", "", "", "")

        # ---- Candidate vs confirmed note ----
        note = Text(
            "A candidate is not a confirmed vulnerability. Validation required.",
            style=palette.get("warning"),
        )

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(summary_line)
        body.add_row(Text(""))
        body.add_row(table)
        body.add_row(note)

        return section(13, "VULNERABILITY CANDIDATES", body, config)
    except Exception as e:
        logging.debug(f"section 13 render failed: {e}")
        return _render_placeholder(13, "VULNERABILITY CANDIDATES", config)


def _render_14_anomalies(report, config):
    """
    Render Section 14 — ANOMALIES (Stage B5). Read-only.

    An anomaly is a deviation, not a verdict.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        an = (report.get("14_anomalies", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(an, dict):
            an = {}
        checks = an.get("checks_executed", []) or []
        by_sev = an.get("by_severity", {}) or {}
        by_cat = an.get("by_category", {}) or {}
        anomalies = an.get("anomalies", []) or []
        if not isinstance(checks, list):
            checks = []
        if not isinstance(by_sev, dict):
            by_sev = {}
        if not isinstance(by_cat, dict):
            by_cat = {}
        if not isinstance(anomalies, list):
            anomalies = []

        # ---- Checks + severity line ----
        checks_line = Text.assemble(
            ("Checks executed  ", palette.get("muted")),
            (str(len(checks)), palette.get("highlight")),
            ("   ", ""),
            ("HIGH=", palette.get("muted")),
            (str(by_sev.get("HIGH", 0)), _sev_style("high", config)),
            ("  ", ""),
            ("MODERATE=", palette.get("muted")),
            (str(by_sev.get("MODERATE", 0)), _sev_style("moderate", config)),
            ("  ", ""),
            ("LOW=", palette.get("muted")),
            (str(by_sev.get("LOW", 0)), _sev_style("low", config)),
            ("  ", ""),
            ("INFO=", palette.get("muted")),
            (str(by_sev.get("INFORMATIONAL", 0)), palette.get("muted")),
        )

        # ---- Empty state ----
        if not anomalies:
            body = Table.grid(padding=(0, 0))
            body.add_column()
            body.add_row(checks_line)
            body.add_row(Text("No anomalies detected. All checks passed.",
                              style=palette.get("success")))
            return section(14, "ANOMALIES", body, config)

        # ---- Category line ----
        if by_cat:
            cat_line = Text.assemble(
                ("Categories  ", palette.get("muted")),
                (_truncate_list(
                    [f"{k}={v}" for k, v in sorted(by_cat.items())],
                    limit=6,
                ), palette.get("value") or palette.get("highlight")),
            )
        else:
            cat_line = Text("")

        # ---- Anomaly table (top 10) ----
        table = Table(
            show_header=True,
            header_style=palette.get("muted"),
            box=None,
            padding=(0, 1),
            expand=False,
        )
        table.add_column("Severity", no_wrap=True)
        table.add_column("Category", style=palette.get("muted"), no_wrap=True)
        table.add_column("Message", style=palette.get("value") or "")
        table.add_column("Conf", justify="right", no_wrap=True)

        for a in anomalies[:10]:
            if not isinstance(a, dict):
                continue
            sev = a.get("severity", "INFORMATIONAL")
            try:
                conf = float(a.get("confidence", 0.0))
                conf_s = f"{conf:.2f}"
            except (TypeError, ValueError):
                conf_s = _MISSING
            table.add_row(
                Text(str(sev), style=_sev_style(str(sev).lower(), config)),
                str(a.get("category", _MISSING)),
                str(a.get("message", ""))[:80],
                conf_s,
            )

        if len(anomalies) > 10:
            table.add_row(f"[dim]+{len(anomalies) - 10} more[/dim]",
                          "", "", "")

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(checks_line)
        body.add_row(cat_line)
        body.add_row(Text(""))
        body.add_row(table)

        return section(14, "ANOMALIES", body, config)
    except Exception as e:
        logging.debug(f"section 14 render failed: {e}")
        return _render_placeholder(14, "ANOMALIES", config)


def _render_15_evidence(report, config):
    """
    Render Section 15 — EVIDENCE (Stage B5). Read-only.

    Summarizes the evidence index; never dumps raw items.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        ev = (report.get("15_evidence", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(ev, dict):
            ev = {}
        try:
            total = int(ev.get("total", 0))
        except (TypeError, ValueError):
            total = 0
        by_status = ev.get("by_status", {}) or {}
        by_source = ev.get("by_source", {}) or {}
        if not isinstance(by_status, dict):
            by_status = {}
        if not isinstance(by_source, dict):
            by_source = {}

        if total == 0:
            body = Text("No evidence collected.", style=palette.get("muted"))
            return section(15, "EVIDENCE", body, config)

        # ---- Total line ----
        total_line = Text.assemble(
            ("Total items  ", palette.get("muted")),
            (str(total), palette.get("highlight")),
        )

        # ---- Status breakdown ----
        status_parts: List[Tuple[str, str]] = []
        for status in ("OK", "FAILED", "NOT_CONFIGURED", "PARTIAL", "DISABLED"):
            try:
                count = int(by_status.get(status, 0))
            except (TypeError, ValueError):
                count = 0
            if count == 0:
                continue
            style = _provider_status_style(status, config)
            status_parts.append(("   ", ""))
            status_parts.append((f"{status}=", palette.get("muted")))
            status_parts.append((str(count), style))
        status_line = Text.assemble(*status_parts) if status_parts else Text("")

        # ---- Source breakdown ----
        if by_source:
            source_line = Text.assemble(
                ("By source  ", palette.get("muted")),
                (_truncate_list(
                    [f"{k}={v}" for k, v in sorted(by_source.items())],
                    limit=8,
                ), palette.get("value") or palette.get("highlight")),
            )
        else:
            source_line = Text("")

        # ---- Note ----
        note = Text(
            "Evidence is the foundation of every claim in this report.",
            style=palette.get("muted"),
        )

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(total_line)
        body.add_row(status_line)
        body.add_row(source_line)
        body.add_row(note)

        return section(15, "EVIDENCE", body, config)
    except Exception as e:
        logging.debug(f"section 15 render failed: {e}")
        return _render_placeholder(15, "EVIDENCE", config)


def _style_label(label: Any, config: Dict[str, Any]) -> "Text":
    """
    Style a score label (VERY_LOW / LOW / MODERATE / HIGH / VERY_HIGH).
    Accepts a plain label or an existing Text (Stage B5).
    """
    palette = Palette(config)
    try:
        s = str(label).upper()
    except Exception:
        s = "UNKNOWN"
    if s == "VERY_HIGH":
        return Text(s, style=palette.get("danger"))
    if s == "HIGH":
        return Text(s, style=palette.get("warning"))
    if s == "MODERATE":
        return Text(s, style=palette.get("primary"))
    if s == "LOW":
        return Text(s, style=palette.get("muted"))
    return Text(s, style=palette.get("muted"))


def _render_16_confidence(report, config):
    """
    Render Section 16 — CONFIDENCE (Stage B5). Read-only.

    Confidence is a self-assessment, not accuracy.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        conf = (report.get("16_confidence", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(conf, dict):
            conf = {}
        data = conf.get("data_confidence", {}) or {}
        threat = conf.get("threat_confidence", {}) or {}
        geo = conf.get("geo_confidence", {}) or {}
        assessment = conf.get("assessment_confidence", {}) or {}
        for _d in (data, threat, geo, assessment):
            if not isinstance(_d, dict):
                _d = {}

        # ---- Confidence table ----
        table = Table(
            show_header=True,
            header_style=palette.get("muted"),
            box=None,
            padding=(0, 1),
            expand=False,
        )
        table.add_column("Metric", style=palette.get("muted"))
        table.add_column("Score", justify="right")
        table.add_column("Bar", no_wrap=True)
        table.add_column("Label", no_wrap=True)

        for label, entry in (
            ("Data Confidence",       data),
            ("Threat Confidence",     threat),
            ("Geo Confidence",        geo),
            ("Assessment Confidence", assessment),
        ):
            score = entry.get("score")
            if score is None:
                table.add_row(label, _MISSING, _MISSING, _MISSING)
                continue
            s = _to_float(score)
            value_0_100 = s * 100.0
            bar = _score_bar(value_0_100, config)
            lbl = entry.get("label") or _score_label_from_value(value_0_100, config)
            table.add_row(label, f"{s:.2f}", bar, _style_label(lbl, config))

        # ---- Assessment headline ----
        assessment_label = assessment.get("label", _MISSING)
        assessment_score = assessment.get("score")
        headline = Text.assemble(
            ("Assessment  ", palette.get("muted")),
            (str(assessment_label), _assessment_style(assessment_label, config)),
            ("  ", ""),
            (f"({assessment_score})" if assessment_score is not None else "",
             palette.get("muted")),
        )

        # ---- Note ----
        note = Text(
            "Confidence is not accuracy. A low-confidence report is an honest one.",
            style=palette.get("muted"),
        )

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(table)
        body.add_row(headline)
        body.add_row(note)

        return section(16, "CONFIDENCE", body, config)
    except Exception as e:
        logging.debug(f"section 16 render failed: {e}")
        return _render_placeholder(16, "CONFIDENCE", config)


def _interleave_newlines(items: List["Text"]) -> List[Any]:
    """
    Interleave a list of Text with newline separators (Stage B5).
    """
    out: List[Any] = []
    for i, t in enumerate(items):
        if i > 0:
            out.append("\n")
        out.append(t)
    return out


def _render_17_limitations(report, config):
    """
    Render Section 17 — LIMITATIONS (Stage B5, compacted in C3.7).

    Every limitation is shown in full — none are truncated. Density is
    reduced with a lighter bullet and stripped trailing punctuation.
    The panel uses the uniform expand=True rule. Display-only: the
    JSON report
    keeps the original text.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        lim = (report.get("17_limitations", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(lim, dict):
            lim = {}
        limitations = lim.get("limitations", []) or []
        if not isinstance(limitations, list):
            limitations = []

        if not limitations:
            body = Text("No limitations recorded.",
                        style=palette.get("muted"))
            return section(17, "LIMITATIONS", body, config)

        # ---- Compact bulleted list (complete, never truncated) ----
        lines: List[Text] = []
        for item in limitations:
            try:
                text = str(item).rstrip(" .;")
            except Exception:
                text = _MISSING
            lines.append(Text.assemble(
                ("· ", palette.get("accent")),
                (text, palette.get("value") or ""),
            ))

        # Join with single newlines — no blank line between items.
        parts: List[Any] = []
        for i, t in enumerate(lines):
            if i > 0:
                parts.append("\n")
            parts.append(t)
        body = Text.assemble(*parts)

        return section(17, "LIMITATIONS", body, config)
    except Exception as e:
        logging.debug(f"section 17 render failed: {e}")
        return _render_placeholder(17, "LIMITATIONS", config)


def _priority_style(priority: Any, config: Dict[str, Any]) -> str:
    """Severity color for a next-step priority (Stage B5)."""
    palette = Palette(config)
    p = str(priority).lower()
    if p == "high":
        return palette.get("danger")
    if p == "moderate":
        return palette.get("warning")
    if p == "low":
        return palette.get("primary")
    return palette.get("muted")


def _render_18_next_investigation(report, config):
    """
    Render Section 18 — NEXT INVESTIGATION (Stage B5). Read-only.

    Preserves the report's priority order; never re-sorts here.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        palette = Palette(config)
        ni = (report.get("18_next_investigation", {}) or {}) if isinstance(report, dict) else {}
        if not isinstance(ni, dict):
            ni = {}
        steps = ni.get("next_investigation", []) or []
        if not isinstance(steps, list):
            steps = []

        if not steps:
            body = Text("No next steps suggested.",
                        style=palette.get("muted"))
            return section(18, "NEXT INVESTIGATION", body, config)

        # ---- Table ----
        table = Table(
            show_header=True,
            header_style=palette.get("muted"),
            box=None,
            padding=(0, 1),
            expand=True,
        )
        table.add_column("Priority", no_wrap=True)
        table.add_column("Action", style=palette.get("value") or "", overflow="fold")
        table.add_column("Reason", style=palette.get("muted"), overflow="fold")

        for step in steps:
            if not isinstance(step, dict):
                continue
            priority = step.get("priority", "informational")
            table.add_row(
                Text(str(priority).upper(), style=_priority_style(priority, config)),
                str(step.get("action", _MISSING)),
                str(step.get("reason", _MISSING)),
            )

        # ---- Note ----
        note = Text(
            "These are suggested steps. The analyst decides the scope.",
            style=palette.get("muted"),
        )

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(table)
        body.add_row(note)

        return section(18, "NEXT INVESTIGATION", body, config)
    except Exception as e:
        logging.debug(f"section 18 render failed: {e}")
        return _render_placeholder(18, "NEXT INVESTIGATION", config)


def _render_banner(config: Dict[str, Any]) -> Optional["Panel"]:
    """
    Render the ReconIP ASCII banner (Stage B2).

    Config keys used:
      display.show_banner, display.banner_style ("block"|"compact"|"none"),
      identity.tool_name, identity.tagline, identity.version,
      display.colors.*, display border.

    Returns a Panel, or None when disabled or rich is unavailable.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        display_cfg = (config.get("display", {}) or {}) if isinstance(config, dict) else {}
    except Exception:
        display_cfg = {}
    if not isinstance(display_cfg, dict):
        display_cfg = {}
    if not display_cfg.get("show_banner", True):
        return None
    try:
        style = (display_cfg.get("banner_style") or "block").lower()
    except Exception:
        style = "block"
    if style == "none":
        return None

    try:
        identity = (config.get("identity", {}) or {}) if isinstance(config, dict) else {}
    except Exception:
        identity = {}
    if not isinstance(identity, dict):
        identity = {}
    tool_name = identity.get("tool_name") or DEFAULT_TOOL_NAME
    tagline = identity.get("tagline") or DEFAULT_TAGLINE
    try:
        version = identity.get("version") or (config.get("version", "v?") if isinstance(config, dict) else "v?")
    except Exception:
        version = "v?"

    try:
        palette = Palette(config)
        box = _resolve_box(config)
        try:
            _console_obj = _console(config)
            term_width = int(_console_obj.width) if _console_obj is not None else 80
        except Exception:
            term_width = 80

        if style == "compact":
            # Single-line banner for narrow terminals / minimal contexts.
            line = Text.assemble(
                ("▰▰▰  ", palette.get("primary")),
                (str(tool_name).upper(), palette.get("highlight")),
                ("  ", ""),
                (f"•  {version}", palette.get("accent")),
                ("  ▰▰▰", palette.get("primary")),
            )
            return Panel(
                Align.center(line),
                border_style=palette.get("border"),
                box=box,
                padding=(0, 1),
                expand=False,
            )

        # ---- Block banner (default): widest art that fits ----
        # Custom tool names cannot reuse the pre-rendered art,
        # so fall back to plain text (never wrapped, never truncated).
        if str(tool_name).upper() != DEFAULT_TOOL_NAME:
            art_text = Text(str(tool_name).upper(), style=palette.get("primary"))
            art_text.no_wrap = True
            art_width = len(str(tool_name).upper())
        else:
            art = _select_banner_art(term_width)
            art_width = _banner_art_width(art) if art is not None else 0
            if art is None:
                art_text = None
            else:
                art_text = Text(art, style=palette.get("primary"))
                art_text.no_wrap = True

        tagline_plain = f"{tagline}  •  {version}"
        short_plain = f"{tool_name}  •  {version}"

        # Total content width decides the layout. The tagline counts:
        # a fitting art with a cropping tagline is still truncation.
        content_width = max(art_width, len(tagline_plain))
        if art_text is not None and content_width + 4 <= term_width:
            tagline_text = Text.assemble(
                (str(tagline), palette.get("accent")),
                ("  •  ", palette.get("muted")),
                (str(version), palette.get("highlight")),
            )
            tagline_text.no_wrap = True

            content = Text.assemble(
                art_text, "\n\n",
                tagline_text,
            )
            content.no_wrap = True

            return Panel(
                Align.center(content),
                border_style=palette.get("border"),
                box=box,
                padding=(0, 1),
                expand=False,
            )

        # Narrow terminal — fall back to a compact line.
        line = Text.assemble(
            (str(tool_name).upper(), palette.get("highlight")),
            ("  •  ", palette.get("muted")),
            (str(version), palette.get("accent")),
        )
        if len(short_plain) + 4 <= term_width:
            return Panel(
                Align.center(line),
                border_style=palette.get("border"),
                box=box,
                padding=(0, 1),
                expand=False,
            )
        if len(short_plain) + 2 <= term_width:
            return Panel(
                Align.center(line),
                border_style=palette.get("border"),
                box=box,
                padding=(0, 1),
                expand=False,
            )
        # Extremely narrow: bare text, no panel. Never crashes.
        return line
    except Exception as e:
        logging.debug(f"banner render failed: {e}")
        return None


def _short_time(iso: str) -> str:
    """
    Extract HH:MM:SS from an ISO8601 UTC timestamp (Stage B2).
    Returns the input unchanged when parsing fails.
    """
    if not iso or iso == "unknown":
        return iso
    try:
        s = str(iso).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.strftime("%H:%M:%S")
    except Exception:
        return iso


def _render_target_header(report: Dict[str, Any],
                          config: Dict[str, Any],
                          scan_duration: Optional[float] = None) -> Optional["Panel"]:
    """
    Render the target + run context header (Stage C3.9.1).

    Layout:
      Row 1:  Target:   <value>           Profile:  <value>
      Row 2:  Time:     <value>           Scan:     <value>
      Row 3:  (blank spacer)
      Row 4:  IP: <value>   ASN: <value>   Org: <value>

    Design rationale:
      - No rich Table.grid. Grid columns negotiate widths and elide
        with "…" on narrow terminals.
      - Each row is a single Text.assemble. If a row is too wide,
        rich wraps it instead of truncating.
      - Labels use fixed-width padding so columns align visually.
      - Values are shortened only if they exceed their column width.

    Returns:
      A rich Panel, or None if disabled or rich is unavailable.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        display_cfg = (config.get("display", {}) or {}) if isinstance(config, dict) else {}
    except Exception:
        display_cfg = {}
    if not isinstance(display_cfg, dict):
        display_cfg = {}
    if not display_cfg.get("show_header", True):
        return None

    try:
        palette = Palette(config)
        box = _resolve_box(config)

        # ---- Extract fields safely ----
        try:
            metadata = (report.get("metadata", {}) or {}) if isinstance(report, dict) else {}
        except Exception:
            metadata = {}
        if not isinstance(metadata, dict):
            metadata = {}
        try:
            profile_info = metadata.get("profile", {}) or {}
        except Exception:
            profile_info = {}
        if not isinstance(profile_info, dict):
            profile_info = {}
        try:
            target_profile = (report.get("01_target_profile", {}) or {}) if isinstance(report, dict) else {}
        except Exception:
            target_profile = {}
        if not isinstance(target_profile, dict):
            target_profile = {}

        target = (
            metadata.get("target")
            or target_profile.get("target")
            or "unknown"
        )
        try:
            applied = (config.get("_applied_profile", {}) or {}) if isinstance(config, dict) else {}
        except Exception:
            applied = {}
        if not isinstance(applied, dict):
            applied = {}
        profile_name = (
            profile_info.get("name")
            or applied.get("name")
            or "base"
        )
        generated_at = metadata.get("generated_at") or "unknown"

        ip = target_profile.get("ip")
        asn = target_profile.get("asn")
        org = (
            target_profile.get("asn_name")
            or target_profile.get("organization")
        )

        # ---- Prepare display values ----
        target_v = _shorten(target, 30)
        profile_v = _shorten(profile_name, 20)
        time_v = _short_time(generated_at)
        scan_v = f"{scan_duration:.2f}s" if scan_duration is not None else "—"

        ip_v = _shorten(ip, 30) if ip else "—"
        asn_v = _shorten(asn, 10) if asn else "—"
        org_v = _shorten(org, 40) if org else "—"

        # ---- Fixed column widths for alignment ----
        # Row layout:
        #   [label1 (10)] [value1 (24)] [sep (2)] [label2 (11)] [value2 (rest)]
        LABEL1_W = 10
        VALUE1_W = 24
        SEP_W = 2
        LABEL2_W = 11

        def _pad(s: str, width: int) -> str:
            try:
                s = str(s)
            except Exception:
                s = ""
            try:
                width = int(width)
            except Exception:
                return s
            if len(s) >= width:
                return s[: width - 1] + "…" if width > 1 else s[:width]
            return s + " " * (width - len(s))

        label1_style = palette.get("muted")
        value_style = palette.get("highlight")
        label2_style = palette.get("muted")

        # ---- Row 1: Target + Profile ----
        row1 = Text.assemble(
            (_pad("Target:", LABEL1_W), label1_style),
            (_pad(target_v, VALUE1_W), value_style),
            (" " * SEP_W, ""),
            (_pad("Profile:", LABEL2_W), label2_style),
            (profile_v, value_style),
        )
        row1.no_wrap = False

        # ---- Row 2: Time + Scan ----
        row2 = Text.assemble(
            (_pad("Time:", LABEL1_W), label1_style),
            (_pad(time_v, VALUE1_W), value_style),
            (" " * SEP_W, ""),
            (_pad("Scan:", LABEL2_W), label2_style),
            (scan_v, value_style),
        )
        row2.no_wrap = False

        # ---- Row 4: IP + ASN + Org ----
        row4 = Text.assemble(
            ("IP: ", label1_style),
            (ip_v, value_style),
            ("   ", ""),
            ("ASN: ", label2_style),
            (asn_v, value_style),
            ("   ", ""),
            ("Org: ", label2_style),
            (org_v, value_style),
        )
        row4.no_wrap = False

        # ---- Compose body ----
        has_sub = bool(ip or asn or org)

        if has_sub:
            body = Text.assemble(
                row1, "\n",
                row2, "\n",
                "\n",
                row4,
            )
        else:
            body = Text.assemble(row1, "\n", row2)

        return Panel(
            body,
            border_style=palette.get("border"),
            box=box,
            padding=(0, 1),
            expand=True,
        )
    except Exception as e:
        logging.debug(f"header render failed: {e}")
        return None


def _render_footer(config: Dict[str, Any]) -> Optional["Text"]:
    """
    Render the closing footer as a centered Rule (Stage B2).

    Operator fields are optional (Phase D). Never fails on missing
    identity — every value has a default.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        display_cfg = (config.get("display", {}) or {}) if isinstance(config, dict) else {}
    except Exception:
        display_cfg = {}
    if not isinstance(display_cfg, dict):
        display_cfg = {}
    if not display_cfg.get("show_footer", True):
        return None

    try:
        palette = Palette(config)
        identity = (config.get("identity", {}) or {}) if isinstance(config, dict) else {}
        if not isinstance(identity, dict):
            identity = {}

        tool_name = identity.get("tool_name") or DEFAULT_TOOL_NAME
        try:
            version = identity.get("version") or (config.get("version", "v?") if isinstance(config, dict) else "v?")
        except Exception:
            version = "v?"
        tagline = identity.get("tagline") or DEFAULT_TAGLINE
        operator_name = identity.get("operator_name")
        operator_signature = identity.get("operator_signature")

        parts: List[Tuple[str, str]] = []
        parts.append((f"  {tool_name}", palette.get("accent")))
        parts.append(("  •  ", palette.get("muted")))
        parts.append((str(version), palette.get("highlight")))
        parts.append(("  •  ", palette.get("muted")))
        parts.append((str(tagline), palette.get("muted")))

        # Phase D will fill these in.
        if operator_signature:
            parts.append(("  •  ", palette.get("muted")))
            parts.append((str(operator_signature), palette.get("primary")))
        if operator_name:
            parts.append(("  —  ", palette.get("muted")))
            parts.append((str(operator_name), palette.get("value") or ""))

        line = Text.assemble(*parts)
        # Narrow-terminal fallback (Stage C3.2): a Rule crops content
        # wider than the console, so shorten the line instead of
        # letting rich silently truncate it.
        try:
            _fconsole = _console(config)
            _fwidth = int(_fconsole.width) if _fconsole is not None else 80
        except Exception:
            _fwidth = 80
        try:
            _plain_len = len(line.plain)
        except Exception:
            _plain_len = 0
        if _plain_len > _fwidth:
            short_parts: List[Tuple[str, str]] = [
                (f"  {tool_name}", palette.get("accent")),
                ("  •  ", palette.get("muted")),
                (str(version), palette.get("highlight")),
            ]
            if operator_signature:
                short_parts.append(("  •  ", palette.get("muted")))
                short_parts.append((str(operator_signature), palette.get("primary")))
            if operator_name:
                short_parts.append(("  —  ", palette.get("muted")))
                short_parts.append((str(operator_name), palette.get("value") or ""))
            line = Text.assemble(*short_parts)
        return Rule(line, style=palette.get("border"), align="center")
    except Exception as e:
        logging.debug(f"footer render failed: {e}")
        return None


def _render_reports_summary(paths: Dict[str, str],
                            config: Dict[str, Any]):
    """
    Render the reports summary panel, numbered 00 (Stage B5). Read-only.

    Args:
      paths: mapping of {format: filepath}.
    """
    if not _RICH_AVAILABLE:
        return None
    try:
        if not paths or not isinstance(paths, dict):
            return None
        palette = Palette(config)

        table = Table(
            show_header=True,
            header_style=palette.get("muted"),
            box=None,
            padding=(0, 1),
            expand=False,
        )
        table.add_column("Format", style=palette.get("accent"), no_wrap=True)
        table.add_column("Path", style=palette.get("value") or "")

        # Stable order
        order = ["json", "html", "markdown", "csv", "stix", "misp"]
        seen = set()
        for fmt in order:
            if fmt in paths:
                table.add_row(fmt.upper(), str(paths[fmt]))
                seen.add(fmt)
        # Any remaining formats not in the canonical order
        for fmt, path in paths.items():
            if fmt in seen:
                continue
            table.add_row(str(fmt).upper(), str(path))

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(Text.assemble(
            ("Reports generated  ", palette.get("muted")),
            (str(len(paths)), palette.get("highlight")),
        ))
        body.add_row(Text(""))
        body.add_row(table)

        return section(0, "REPORTS", body, config)
    except Exception as e:
        logging.debug(f"reports summary render failed: {e}")
        return None


def render_all(report: Dict[str, Any],
               config: Dict[str, Any],
               export_paths: Optional[Dict[str, str]] = None,
               scan_duration: Optional[float] = None) -> None:
    """
    Render the full report to the terminal (Stage B1 dispatcher, B2 duration).

    Behavior:
      - Skipped entirely if display is disabled.
      - Falls back silently if rich is unavailable.
      - Never raises. Any exception is caught and logged.
      - Never writes to disk.

    New in B2: scan_duration is passed to _render_target_header().
    """
    try:
        display_cfg = (config.get("display", {}) or {}) if isinstance(config, dict) else {}
    except Exception:
        display_cfg = {}
    if not isinstance(display_cfg, dict):
        display_cfg = {}
    if not display_cfg.get("enabled", True):
        return

    if not _RICH_AVAILABLE:
        # Silent fallback: print a single line, do not break the pipeline
        print("[display] rich not available; skipping rich rendering.")
        return

    try:
        console = _console(config)
        if console is None:
            return

        # ---- Banner (Stage B2 will implement) ----
        try:
            if display_cfg.get("show_banner", True):
                banner = _render_banner(config)
                if banner is not None:
                    console.print(banner)
        except Exception as e:
            logging.debug(f"banner render failed: {e}")

        # ---- Target header ----
        try:
            header = _render_target_header(report, config, scan_duration=scan_duration)
            if header is not None:
                console.print(header)
                console.print()
        except Exception as e:
            logging.debug(f"header render failed: {e}")

        # ---- Sections ----
        try:
            spacing = int(display_cfg.get("section_spacing", 1))
        except Exception:
            spacing = 1
        if spacing < 0:
            spacing = 0
        if display_cfg.get("show_all_sections", True):
            for number, title, fn_name in SECTION_REGISTRY:
                try:
                    fn = globals().get(fn_name)
                    if not callable(fn):
                        continue
                    panel_obj = fn(report, config)
                    if panel_obj is not None:
                        console.print(panel_obj)
                        if spacing > 0:
                            console.print("\n" * (spacing - 1))
                except Exception as e:
                    logging.exception(f"Render failed for section {number}: {e}")
                    try:
                        console.print(f"[red]Section {number:02d} failed to render.[/red]")
                    except Exception:
                        pass

        # ---- Reports summary (Stage B5 will implement) ----
        try:
            if display_cfg.get("show_reports_summary", True) and export_paths:
                summary = _render_reports_summary(export_paths, config)
                if summary is not None:
                    console.print(summary)
        except Exception as e:
            logging.debug(f"reports summary render failed: {e}")

        # ---- Footer (Stage B2 will implement) ----
        try:
            footer = _render_footer(config)
            if footer is not None:
                console.print(footer)
        except Exception as e:
            logging.debug(f"footer render failed: {e}")

    except Exception as e:
        # Display must NEVER break the pipeline
        logging.exception(f"Display failed: {e}")


def test_providers(target: str, config: Dict[str, Any]) -> int:
    """
    Test every enabled provider against a single target.

    Behavior:
      - Does NOT use cache.
      - Does NOT write to reconip.db.
      - Does NOT write to reports/.
      - Does NOT modify any persistent state.
      - Prints a rich table with status, latency, and error/evidence.
      - Returns an exit code (0 = clean, 2 = failures).

    Args:
      target: IP address or domain to test against.
      config: Effective configuration (after profile resolution).

    Returns:
      int exit code
    """
    if not isinstance(config, dict):
        config = {}
    # ---- Force-disable cache for this run ----
    try:
        config.setdefault("cache", {})
        config["cache"]["enabled"] = False
    except Exception:
        pass
    try:
        quiet = bool(config.get("batch", {}).get("quiet", False) or config.get("_quiet", False))
    except Exception:
        quiet = False

    # ---- Load providers ----
    try:
        providers = load_providers(config)
    except Exception as e:
        print(f"Failed to load providers: {e}", file=sys.stderr)
        return 2
    # Providers with enabled:false are skipped by load_providers;
    # list them as DISABLED rows from the declared config.
    try:
        declared = config.get("providers", {}) if isinstance(config, dict) else {}
        if not isinstance(declared, dict):
            declared = {}
        disabled_names = sorted(
            n for n, pc in declared.items()
            if isinstance(pc, dict) and not pc.get("enabled", True)
        )
    except Exception:
        disabled_names = []
    if not providers and not disabled_names:
        print("No providers configured.", file=sys.stderr)
        return 2

    # ---- Load auth state (secret registration only; no logging here) ----
    try:
        load_api_keys(providers, config)
    except Exception:
        pass

    # ---- Prepare table ----
    try:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        table = Table(
            title=f"ReconIP Provider Test — {target}",
            show_lines=False,
        )
        table.add_column("Provider", style="cyan", no_wrap=True)
        table.add_column("Auth", style="magenta", no_wrap=True)
        table.add_column("Status", style="bold", no_wrap=True)
        table.add_column("Latency", justify="right", no_wrap=True)
        table.add_column("Evidence / Error", style="dim")
        use_rich = True
    except ImportError:
        use_rich = False
        console = None
        table = None

    # ---- Counters ----
    ok = 0
    failed = 0
    not_configured = 0
    disabled = 0
    rows: List[Dict[str, Any]] = []

    # ---- Iterate providers (sequential: clean per-provider latency) ----
    for name in sorted(set(providers.keys()) | set(disabled_names)):
        if name not in providers:
            disabled += 1
            rows.append({
                "name": name,
                "auth": "-",
                "status": "DISABLED",
                "latency": "-",
                "detail": "enabled: false",
            })
            continue
        provider = providers[name]

        try:
            enabled = bool(getattr(provider, "enabled", True))
        except Exception:
            enabled = True
        if not enabled:
            disabled += 1
            rows.append({
                "name": name,
                "auth": "-",
                "status": "DISABLED",
                "latency": "-",
                "detail": "enabled: false",
            })
            continue

        auth_label = _auth_label(provider)

        try:
            configured = bool(provider.is_configured()) if hasattr(provider, "is_configured") else True
        except Exception:
            configured = True
        if not configured:
            not_configured += 1
            try:
                _env = getattr(provider, "auth_env", None)
            except Exception:
                _env = None
            rows.append({
                "name": name,
                "auth": auth_label,
                "status": "NOT_CONFIGURED",
                "latency": "-",
                "detail": f"missing {_env}" if _env else "misconfigured: no api_key_env",
            })
            continue

        # ---- Run the provider ----
        start = time.time()
        try:
            result = provider.query(target)
            latency = f"{time.time() - start:.2f}s"

            if result is None:
                failed += 1
                try:
                    detail = _scrub(getattr(provider, "last_error", None) or "no result")
                except Exception:
                    detail = "no result"
                rows.append({
                    "name": name,
                    "auth": auth_label,
                    "status": "FAILED",
                    "latency": latency,
                    "detail": detail,
                })
            else:
                ok += 1
                evidence = _summarize_result(result)
                rows.append({
                    "name": name,
                    "auth": auth_label,
                    "status": "OK",
                    "latency": latency,
                    "detail": evidence,
                })
        except Exception as e:
            failed += 1
            rows.append({
                "name": name,
                "auth": auth_label,
                "status": "ERROR",
                "latency": "-",
                "detail": _scrub(str(e))[:80],
            })

    # ---- Render ----
    if not quiet:
        if use_rich:
            _render_rich_table(console, table, rows)
        else:
            _render_plain_table(rows)

    # ---- Summary (always printed) ----
    summary = (
        f"OK: {ok} | FAILED: {failed} | "
        f"NOT_CONFIGURED: {not_configured} | DISABLED: {disabled}"
    )
    if not quiet:
        if use_rich:
            console.print(f"\n[bold]{summary}[/bold]")
        else:
            print(f"\n{summary}")
    else:
        print(summary)

    # ---- Exit code (NOT_CONFIGURED never fails) ----
    return 0 if failed == 0 else 2


def main() -> int:
    global INTEL_DB
    parser = build_parser()
    args = parser.parse_args()

    # Load config (fresh copy)
    try:
        config = load_config()
    except Exception:
        config = CFG if isinstance(CFG, dict) else {}

    # Resolve profile (Stage 21: CLI --profile > default_profile > base).
    # Unknown profiles fail loudly (argparse choices + ValueError here).
    try:
        config = resolve_effective_config(config, getattr(args, "profile", None))
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    # Execute the pipeline under the effective config.
    try:
        _sync_global_config(config)
    except Exception as e:
        log.debug(f"profile sync: {e}")

    # ---- Progress CLI overrides (Stage C1; config holds the defaults) ----
    try:
        if getattr(args, "no_progress", False):
            config.setdefault("display", {})["show_progress"] = False
        if getattr(args, "no_display", False):
            config.setdefault("display", {})["show_progress"] = False
    except Exception:
        pass

    # ---- Logging setup (Stage C3.6) ----
    # After CLI overrides so RichHandler is used only when display output
    # is wanted; before any branch that emits log records.
    try:
        _setup_logging(config)
    except Exception:
        pass

    # ---- Auth state for pipeline branches (Stage C3.6) ----
    # Computed once here so the summary can be emitted inside the
    # progress context (above the bar) instead of mid-pipeline.
    try:
        _diag_providers = load_providers(config)
    except Exception:
        _diag_providers = {}
    try:
        _set_providers_registry(_diag_providers)
    except Exception:
        pass
    try:
        _auth_info = load_api_keys(_diag_providers, config)
    except Exception:
        _auth_info = {"present": [], "missing": [], "misconfigured": [],
                      "disabled": [], "no_auth": [], "not_required": [],
                      "missing_env": {}}

    # ---- List-providers mode (Stage A3: instant, read-only discovery) ----
    if getattr(args, "list_providers", False):
        try:
            _list_providers = load_providers(config)
        except Exception as e:
            print(f"Failed to load providers: {e}", file=sys.stderr)
            return 2
        try:
            _set_providers_registry(_list_providers)
        except Exception:
            pass
        try:
            _render_providers_table(_list_providers, config)
        except Exception as e:
            print(f"Failed to render providers table: {e}", file=sys.stderr)
            return 2
        return 0

    # ---- Show-auth mode (Stage A2: instant, read-only diagnostics) ----
    if getattr(args, "show_auth", False):
        try:
            _show_providers = load_providers(config)
        except Exception as e:
            print(f"Failed to load providers: {e}", file=sys.stderr)
            return 2
        try:
            _set_providers_registry(_show_providers)
        except Exception:
            pass
        try:
            _show_auth = load_api_keys(_show_providers, config)
        except Exception as e:
            print(f"Failed to inspect auth state: {e}", file=sys.stderr)
            return 2
        try:
            _render_auth_table(_show_auth, _show_providers, config)
        except Exception as e:
            print(f"Failed to render auth table: {e}", file=sys.stderr)
            return 2
        return 0

    # ---- Test providers mode (Stage R5: read-only diagnostics) ----
    if getattr(args, "test_providers", False):
        if getattr(args, "quiet", False):
            try:
                config.setdefault("batch", {})["quiet"] = True
            except Exception:
                pass
        targets = load_targets(getattr(args, "targets", []), getattr(args, "input", None), config)
        if not targets:
            print("Error: --test-providers requires exactly one target.",
                  file=sys.stderr)
            return 1
        if len(targets) > 1:
            print(f"Warning: --test-providers uses only the first target "
                  f"({targets[0]}). Ignoring {len(targets) - 1} additional target(s).",
                  file=sys.stderr)
        try:
            _log_auth_summary(_auth_info, config)
        except Exception:
            pass
        return test_providers(targets[0], config)

    # Cache initialization (Stage 20: schema + purge expired)
    try:
        cache_cfg = config.get("cache", {}) if isinstance(config, dict) else {}
        if not isinstance(cache_cfg, dict):
            cache_cfg = {}
        cache_init(cache_cfg.get("db_path", "reconip_cache.db"))
        cache_purge_expired(config)
    except Exception as e:
        log.debug(f"cache init: {e}")

    # Apply global CLI overrides
    try:
        if getattr(args, "verbose", False):
            config.setdefault("logging", {})["level"] = "DEBUG"
            try:
                logging.getLogger().setLevel(logging.DEBUG)
            except Exception:
                pass
        if getattr(args, "debug", False):
            config.setdefault("logging", {})["level"] = "DEBUG"
            config.setdefault("logging", {})["debug"] = True
            try:
                logging.getLogger().setLevel(logging.DEBUG)
            except Exception:
                pass
        if getattr(args, "quiet", False):
            config.setdefault("batch", {})["quiet"] = True
    except Exception:
        pass

    if getattr(args, "allow_private", False):
        try:
            PN["allow_private_targets"] = True
        except Exception:
            pass
    if getattr(args, "timeout", None):
        try:
            http.to = (2, args.timeout)
        except Exception:
            pass

    if not getattr(args, "no_db", False) and PE.get("enabled", True):
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
    else:
        # Respect --no-db: disable DB for recon()
        INTEL_DB = None

    if getattr(args, "health", False):
        print(json.dumps({"providers": {n: h.to_dict() for n, h in _health.items()},
                          "uptime": round(time.time() - _START_T, 1)},
                         indent=2, default=str))
        return 0
    if getattr(args, "metrics", False):
        print(json.dumps({"jobs": len(JOBS),
                          "cache": CACHE.stats() if CACHE else {},
                          "providers_health": len(_health)}, indent=2))
        return 0
    if getattr(args, "api", False):
        httpd = start_api(args.api_host, args.api_port)
        print(f"{C.OK}API running on "
              f"http://{httpd.server_address[0]}:{httpd.server_address[1]}{C.RST}")
        print("Ctrl+C to stop.")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            httpd.shutdown()
        return 0

    # Load targets (positional + file, dedup + validate)
    try:
        targets = load_targets(getattr(args, "targets", []), getattr(args, "input", None), config)
    except Exception as e:
        logging.error(f"Failed to load targets: {e}")
        targets = []

    if not targets:
        # Explicit file input with no valid targets -> help + error
        if getattr(args, "input", None):
            parser.print_help()
            return 1
        # Legacy interactive mode (preserved single-target workflow)
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
            run_single(t, getattr(args, "output", "text"), getattr(args, "report", None), getattr(args, "report_file", None))
        return 0

    # Determine mode
    try:
        batch_cfg = config.get("batch", {}) if isinstance(config, dict) else {}
    except Exception:
        batch_cfg = {}
    if not isinstance(batch_cfg, dict):
        batch_cfg = {}
    batch_enabled = batch_cfg.get("enabled", True)

    if len(targets) == 1 and not getattr(args, "batch", False):
        # Single-target mode (v42 behavior preserved via _process_single_target)
        _scan_start = time.time()
        with _progress_context(config, total_stages=13,
                               stage_name=f"Scanning {targets[0]}") as _progress:
            # Auth summary above the bar (Stage C3.6), not mid-pipeline.
            try:
                _log_auth_summary(_auth_info, config, progress=_progress)
            except Exception:
                pass
            result = _process_single_target(targets[0], config, args,
                                            progress=_progress)
        try:
            _scan_duration = time.time() - _scan_start
        except Exception:
            _scan_duration = None
        if not isinstance(result, dict) or result.get("status") == "FAILED":
            try:
                print(f"Target {targets[0]} failed: {(result or {}).get('error', 'unknown')}")
            except Exception:
                pass
            return 2
        # Legacy display flags
        try:
            if getattr(args, "report", None):
                rep = build_report(result)
                content = render_report(rep, getattr(args, "report"))
                if getattr(args, "report_file", None):
                    open(getattr(args, "report_file"), "w", encoding="utf-8").write(content)
                    if not getattr(args, "quiet", False):
                        print(f"Written: {getattr(args, 'report_file')}")
                else:
                    print(content)
            elif getattr(args, "output", "text") == "json":
                print(json.dumps(redact(result), indent=2, ensure_ascii=False, default=str))
            else:
                # Text summary + export paths (recon already exported files)
                if not getattr(args, "quiet", False):
                    paths = result.get("export_paths", {})
                    # Single source of truth for output (Stage C3.5):
                    #   display enabled  -> render_all() (includes Section 00)
                    #   display disabled -> plain-text list ("off" mode)
                    # Reports are already on disk; display never blocks them.
                    # NOTE: no C2-style mode resolver exists in this codebase,
                    # so --no-display is honored here alongside display.enabled.
                    try:
                        _display_cfg = config.get("display", {}) if isinstance(config, dict) else {}
                    except Exception:
                        _display_cfg = {}
                    if not isinstance(_display_cfg, dict):
                        _display_cfg = {}
                    _display_enabled = bool(_display_cfg.get("enabled", True)) \
                        and not bool(getattr(args, "no_display", False))
                    if _display_enabled:
                        try:
                            _final = result.get("final_report", {}) if isinstance(result, dict) else {}
                            if isinstance(_final, dict) and _final:
                                try:
                                    _sd = _scan_duration
                                except NameError:
                                    _sd = None
                                render_all(_final, config, paths if isinstance(paths, dict) else None,
                                           scan_duration=_sd)
                        except Exception as e:
                            logging.debug(f"terminal display skipped: {e}")
                        if not isinstance(paths, dict) or not paths:
                            print(render_text(result))
                    else:
                        # "off" mode: plain-text output only, no rich rendering.
                        if isinstance(paths, dict) and paths:
                            for fmt, p in paths.items():
                                print(f"[{fmt}] {p}")
                        else:
                            print(render_text(result))
        except Exception as e:
            logging.error(f"Display failed: {e}")
        # Legacy --export print
        try:
            if getattr(args, "export", None) == "stix":
                print(json.dumps(export_stix(result), indent=2, default=str))
            elif getattr(args, "export", None) == "misp":
                print(json.dumps(export_misp(result), indent=2, default=str))
        except Exception:
            pass
        return 0

    if not batch_enabled:
        logging.error("Batch mode is disabled in config.")
        return 3

    # Batch mode
    workers = getattr(args, "workers", None) or batch_cfg.get("max_workers", 4)
    try:
        workers = int(workers)
    except Exception:
        workers = 4
    try:
        hard = int(batch_cfg.get("max_workers_hard_limit", 16))
    except Exception:
        hard = 16
    # Legacy --parallel maps to default batch workers when --workers unset
    if getattr(args, "parallel", False) and getattr(args, "workers", None) is None:
        workers = int(batch_cfg.get("max_workers", 4))
    workers = max(1, min(workers, hard))

    # Progress forces sequential execution to avoid interleaved output (C1).
    if _progress_wanted(config) and workers > 1:
        if not getattr(args, "quiet", False):
            print("[progress] forcing workers=1 to avoid interleaved output",
                  file=sys.stderr)
        workers = 1

    with _progress_context(config, total_stages=13,
                           stage_name=f"Batch ({len(targets)} targets)") as _bprogress:
        # Auth summary above the bar (Stage C3.6), not mid-pipeline.
        try:
            _log_auth_summary(_auth_info, config, progress=_bprogress)
        except Exception:
            pass
        batch_result = batch_process(targets, config, args, workers=workers,
                                     progress=_bprogress)

    # Cross-target correlation
    batch_corr = {"enabled": False}
    if not getattr(args, "no_correlate", False):
        try:
            batch_corr = batch_correlate(batch_result, config)
        except Exception as e:
            logging.exception(f"batch correlate failed: {e}")
            batch_corr = {"enabled": True, "status": "ERROR", "error": str(e), "related_targets": []}

    # Export per-target reports (reuse recon exports when present)
    exported: Dict[str, Dict[str, str]] = {}
    for target, report in (batch_result.get("results", {}) or {}).items():
        if not isinstance(report, dict) or report.get("status") == "FAILED":
            continue
        try:
            existing = report.get("export_paths")
            if isinstance(existing, dict) and existing and not getattr(args, "format", None) and not getattr(args, "output_dir", None):
                exported[target] = existing
            else:
                final_report = report.get("final_report", {})
                if not final_report:
                    continue
                # Honor per-target overrides via local config copy
                try:
                    local_config = _deep_copy_config(config)
                    _apply_cli_overrides(local_config, args)
                except Exception:
                    local_config = config
                exported[target] = export_all(final_report, local_config)
        except Exception as e:
            logging.error(f"Export failed for {target}: {e}")
            continue

    # Batch summary
    try:
        summary = batch_summary_report(batch_result, batch_corr, config)
    except Exception as e:
        logging.exception(f"summary failed: {e}")
        summary = {"error": str(e)}
    try:
        summary_path = export_batch_summary(summary, config)
    except Exception as e:
        logging.error(f"summary export failed: {e}")
        summary_path = f"ERROR: {e}"

    if not getattr(args, "quiet", False):
        try:
            print(f"\nBatch complete: {batch_result['stats']['ok']}/{batch_result['stats']['total']} OK")
            print(f"Summary: {summary_path}")
            for target, paths in exported.items():
                print(f"\n{target}:")
                if isinstance(paths, dict):
                    for fmt, p in paths.items():
                        print(f"  [{fmt}] {p}")
        except Exception:
            pass

    try:
        return 0 if batch_result["stats"]["failed"] == 0 else 2
    except Exception:
        return 0

if __name__ == "__main__":
    sys.exit(main())
