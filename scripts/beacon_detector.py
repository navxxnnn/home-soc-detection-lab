#!/usr/bin/env python3
"""
beacon_detector.py - flag C2-style beaconing in Zeek conn.log data.  (MITRE ATT&CK T1071)

Beacons call home at regular intervals. For every (src, dst, dst_port) pair the script
measures the time between connections and scores how regular they are:

  * interval regularity : 1 - coefficient of variation of the gaps (jitter tolerant)
  * size regularity     : 1 - coefficient of variation of bytes sent
  * volume              : enough connections to be meaningful

Supported inputs: Zeek conn.log in TSV (default Zeek format) or JSON-lines, and CSV
with columns ts,src,dst,dport[,bytes].

Usage:
    python scripts/beacon_detector.py conn.log
    python scripts/beacon_detector.py conn.log --min-conns 20 --threshold 0.8 --json
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Iterator


@dataclass
class Conn:
    ts: float
    src: str
    dst: str
    dport: int
    bytes_out: int = 0


@dataclass
class BeaconResult:
    src: str
    dst: str
    dport: int
    connections: int
    median_interval_s: float
    interval_score: float
    size_score: float
    score: float


# ----------------------------------------------------------------- parsing
def _int(v) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def parse_zeek_tsv(lines: Iterable[str]) -> Iterator[Conn]:
    fields: list[str] = []
    for line in lines:
        line = line.rstrip("\n")
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if not line or line.startswith("#"):
            continue
        row = dict(zip(fields, line.split("\t")))
        yield Conn(float(row["ts"]), row["id.orig_h"], row["id.resp_h"],
                   _int(row["id.resp_p"]), _int(row.get("orig_bytes")))


def parse_zeek_json(lines: Iterable[str]) -> Iterator[Conn]:
    for line in lines:
        if not line.strip():
            continue
        r = json.loads(line)
        yield Conn(float(r["ts"]), r["id.orig_h"], r["id.resp_h"],
                   _int(r["id.resp_p"]), _int(r.get("orig_bytes")))


def parse_csv(lines: Iterable[str]) -> Iterator[Conn]:
    for r in csv.DictReader(lines):
        yield Conn(float(r["ts"]), r["src"], r["dst"], _int(r["dport"]), _int(r.get("bytes")))


def load(path: Path) -> list[Conn]:
    with path.open(encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    first = next((l for l in lines if l.strip()), "")
    if first.startswith("#"):
        parser = parse_zeek_tsv
    elif first.lstrip().startswith("{"):
        parser = parse_zeek_json
    else:
        parser = parse_csv
    return list(parser(lines))


# ----------------------------------------------------------------- scoring
def _regularity(values: list[float]) -> float:
    """1.0 = perfectly regular, 0.0 = highly irregular."""
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    if mean == 0:
        return 1.0 if all(v == 0 for v in values) else 0.0
    cv = statistics.pstdev(values) / mean
    return max(0.0, 1.0 - cv)


def score_pairs(conns: list[Conn], min_conns: int = 10) -> list[BeaconResult]:
    groups: dict[tuple[str, str, int], list[Conn]] = defaultdict(list)
    for c in conns:
        groups[(c.src, c.dst, c.dport)].append(c)

    results = []
    for (src, dst, dport), items in groups.items():
        if len(items) < min_conns:
            continue
        items.sort(key=lambda c: c.ts)
        gaps = [b.ts - a.ts for a, b in zip(items, items[1:]) if b.ts - a.ts > 0]
        if len(gaps) < min_conns - 1:
            continue
        # Use the median-centred middle 80% of gaps so a few missed check-ins don't hide a beacon
        gaps_sorted = sorted(gaps)
        cut = len(gaps_sorted) // 10
        core = gaps_sorted[cut: len(gaps_sorted) - cut] or gaps_sorted
        interval_score = _regularity(core)
        size_score = _regularity([float(c.bytes_out) for c in items])
        score = round(0.7 * interval_score + 0.3 * size_score, 3)
        results.append(BeaconResult(src, dst, dport, len(items),
                                    round(statistics.median(gaps), 2),
                                    round(interval_score, 3), round(size_score, 3), score))
    return sorted(results, key=lambda r: r.score, reverse=True)


# ----------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Detect beaconing in Zeek conn.log / CSV")
    ap.add_argument("logfile", type=Path)
    ap.add_argument("--min-conns", type=int, default=10, help="minimum connections per pair (default 10)")
    ap.add_argument("--threshold", type=float, default=0.8, help="score to flag as beacon (default 0.8)")
    ap.add_argument("--allow", nargs="*", default=[], help="destination IPs to ignore (NTP, update servers...)")
    ap.add_argument("--json", action="store_true", help="output JSON")
    args = ap.parse_args(argv)

    conns = [c for c in load(args.logfile) if c.dst not in set(args.allow)]
    flagged = [r for r in score_pairs(conns, args.min_conns) if r.score >= args.threshold]

    if args.json:
        print(json.dumps([asdict(r) for r in flagged], indent=2))
    elif not flagged:
        print(f"No beaconing found ({len(conns)} connections analysed).")
    else:
        print(f"{'SRC':<16}{'DST':<16}{'PORT':>6}{'CONNS':>7}{'INTERVAL':>10}{'SCORE':>7}")
        for r in flagged:
            print(f"{r.src:<16}{r.dst:<16}{r.dport:>6}{r.connections:>7}{r.median_interval_s:>9}s{r.score:>7}")
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
