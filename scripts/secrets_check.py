#!/usr/bin/env python3
"""
secrets_check.py - pre-publish scan for secrets and real public IPs.

Run from the repo root before every push:
    python scripts/secrets_check.py
Exit code 1 if anything is found, so it also works as a git pre-commit hook.
"""
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "pcaps", "screenshots"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pcap", ".pcapng", ".zip", ".pdf"}
SELF = Path(__file__).name

PATTERNS = {
    "password assignment": re.compile(r"(?i)\b(pass(word)?|pwd)\s*[:=]\s*['\"]?[^\s'\"]{4,}"),
    "API key / token":     re.compile(r"(?i)\b(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}"),
    "AWS access key":      re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token":        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "private key block":   re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
}
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Documentation ranges (RFC 5737) are fine to publish
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def public_ips(line: str) -> list[str]:
    hits = []
    for m in IP_RE.findall(line):
        try:
            ip = ipaddress.ip_address(m)
        except ValueError:
            continue
        if ip.is_global and not any(ip in n for n in DOC_NETS):
            hits.append(m)
    return hits


def scan(root: Path) -> list[str]:
    findings = []
    for path in root.rglob("*"):
        if not path.is_file() or path.name == SELF or path.suffix.lower() in SKIP_EXT:
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for label, rx in PATTERNS.items():
                if rx.search(line):
                    findings.append(f"{path.relative_to(root)}:{n}: {label}")
            for ip in public_ips(line):
                findings.append(f"{path.relative_to(root)}:{n}: public IP {ip}")
        if path.stat().st_size > 50 * 1024 * 1024:
            findings.append(f"{path.relative_to(root)}: file larger than 50 MB")
    return findings


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    findings = scan(root)
    for f in findings:
        print("[!]", f)
    print(f"\n{len(findings)} potential issue(s) found." if findings else "Clean: no secrets or public IPs found.")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
