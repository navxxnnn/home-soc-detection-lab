import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from beacon_detector import Conn, score_pairs  # noqa: E402


def make_beacon(n=60, interval=30, jitter=0.1, start=1_700_000_000):
    random.seed(1)
    ts, out = start, []
    for _ in range(n):
        ts += interval * (1 + random.uniform(-jitter, jitter))
        out.append(Conn(ts, "10.10.20.20", "10.10.10.10", 443, 512))
    return out


def make_noise(n=60, start=1_700_000_000):
    random.seed(2)
    ts, out = start, []
    for _ in range(n):
        ts += random.expovariate(1 / 30)
        out.append(Conn(ts, "10.10.20.20", "10.10.20.30", 80, random.randint(200, 50_000)))
    return out


def test_beacon_scores_high():
    r = score_pairs(make_beacon())[0]
    assert r.score >= 0.8 and 27 <= r.median_interval_s <= 33


def test_random_traffic_scores_low():
    r = score_pairs(make_noise())[0]
    assert r.score < 0.6


def test_min_conns_filter():
    assert score_pairs(make_beacon(n=5), min_conns=10) == []
