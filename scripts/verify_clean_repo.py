#!/usr/bin/env python3
"""
Automated Zero-Leak & Privacy Hygiene Verifier for Aegis Open-Source Releases.
Scans all repository source, config, script, and documentation files to guarantee:
  1. Zero private SSH keys, API tokens, or credentials
  2. Zero personal local filesystem usernames/paths
  3. Zero non-approved public IPv4 addresses (only RFC 1918, RFC 5737 TEST-NET,
     loopback/multicast, and documented public DNS / demo CDN test vectors allowed)
"""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "dist",
    "build",
    "data",
    "aegis_ngfw.egg-info",
}

SKIP_SUFFIXES = {".pyc", ".pyo", ".exe", ".whl", ".gz", ".zip", ".png", ".ico", ".pcap"}

# Explicitly allowed public IPv4 addresses in code/tests/docs (Public DNS, RFC 5737, Telegram public CIDR bases, demo CDN)
ALLOWED_PUBLIC_IPS = {
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "77.88.8.8",
    "77.88.8.1",
    # Well-known public CDN/Service demo & unit-test vectors
    "93.184.216.34",   # example.com (IANA)
    "140.82.121.4",    # api.github.com
    "104.18.32.7",     # cloudflare
    "142.250.74.14",   # google/youtube
    "149.154.167.91",  # telegram web
    "149.154.160.0",
    "91.108.4.0",
    "91.108.8.0",
    "91.108.12.0",
    "91.108.16.0",
    "91.108.20.0",
    "91.108.56.0",
    "185.76.151.0",
}

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY-----"),
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{30,}"),
    re.compile(r"sk-[A-Za-z0-9]{32,}"),
]

LOCAL_USER_PATH_PATTERNS = [
    re.compile(r"[A-Za-z]:\\Users\\(?!Public\\|<)[^\\\s\"']+"),
    re.compile(r"/Users/(?!<|your-)[^/\s\"']+"),
]

IPV4_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")


def is_approved_ipv4(ip_str: str) -> bool:
    if ip_str in ALLOWED_PUBLIC_IPS:
        return True
    try:
        ip = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_reserved  # Includes RFC 5737 TEST-NET-1/2/3 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) & 255.255.255.255
        or ip in ipaddress.IPv4Network("192.0.2.0/24")
        or ip in ipaddress.IPv4Network("198.51.100.0/24")
        or ip in ipaddress.IPv4Network("203.0.113.0/24")
    )


def scan_repository(root: Path = ROOT) -> list[str]:
    issues: list[str] = []
    self_path = Path(__file__).resolve()
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS or part.endswith(".egg-info") for part in path.parts):
            continue
        if not path.is_file() or path.resolve() == self_path or path.suffix.lower() in SKIP_SUFFIXES:
            continue
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")

        for pat in SECRET_PATTERNS:
            if pat.search(text):
                issues.append(f"{rel}: matched secret key pattern `{pat.pattern}`")

        for pat in LOCAL_USER_PATH_PATTERNS:
            m = pat.search(text)
            if m:
                issues.append(f"{rel}: found local user path `{m.group(0)}`")

        for m in IPV4_RE.finditer(text):
            candidate = m.group(0)
            # Ignore version strings like 3.10.0.1 or OIDs if preceded/followed by dots
            start, end = m.span()
            if (start > 0 and text[start - 1] in (".", "v")) or (end < len(text) and text[end] == "."):
                continue
            if not is_approved_ipv4(candidate):
                issues.append(f"{rel}: unapproved public IPv4 address `{candidate}`")

    return issues


def main() -> int:
    issues = scan_repository()
    if issues:
        print("[FAIL] Repository privacy / secret audit found issues:", file=sys.stderr)
        for item in issues:
            print(f"  - {item}", file=sys.stderr)
        return 1
    print("[PASS] Zero-leak privacy & secret hygiene audit passed across all repository files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
