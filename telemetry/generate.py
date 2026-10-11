#!/usr/bin/env python3
"""
The Range — telemetry factory.

Replays a scripted mix of benign and malicious interactions against the lab's
request log and emits a *labeled* dataset (JSONL + CSV) that downstream projects
(e.g. Sentinel, the AI-for-security detector) train on.

This module is dependency-light on purpose (numpy only) so the data factory runs
with or without the live Docker stack up. When the stack IS up, point --source at
the real access log instead of using the synthetic replay.

Each record is one HTTP interaction with the vulnerable ML API, tagged with the
ATT&CK / ATLAS technique it belongs to so the labels are defensible, not arbitrary.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

# --- technique catalogue -----------------------------------------------------
# label -> (is_malicious, framework id, short description)
TECHNIQUES = {
    "benign_inference":      (0, "—",            "Normal client submitting an image for classification"),
    "benign_health":         (0, "—",            "Load balancer / uptime health check"),
    "recon_endpoint_sweep":  (1, "ATT&CK T1595", "Active scanning: probing undocumented endpoints"),
    "recon_verbose_errors":  (1, "ATT&CK T1592", "Harvesting stack traces from malformed requests"),
    "abuse_rate_flood":      (1, "ATT&CK T1499", "Endpoint DoS: high-rate inference flooding"),
    "ml_model_extraction":   (1, "ATLAS AML.T0024", "Model extraction via many boundary-probing queries"),
    "ml_evasion_probe":      (1, "ATLAS AML.T0015", "Crafting perturbed inputs to find a misclassification"),
}

BENIGN = ["benign_inference", "benign_health"]
MALICIOUS = [t for t in TECHNIQUES if t not in BENIGN]

USER_AGENTS_BENIGN = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "python-requests/2.31.0", "RangeHealthCheck/1.0", "Chrome/124.0 Safari/537.36",
]
USER_AGENTS_MAL = ["curl/8.4.0", "Nmap Scripting Engine", "", "sqlmap/1.8", "python-urllib3/2.0"]

ENDPOINTS = ["/predict", "/health", "/", "/admin", "/debug", "/model", "/.env", "/metrics"]


@dataclass
class Event:
    ts: str
    src_ip: str
    method: str
    path: str
    status: int
    bytes_in: int
    latency_ms: float
    user_agent: str
    requests_last_10s: int      # rate feature
    distinct_paths_last_60s: int  # recon feature
    payload_entropy: float        # evasion/extraction feature
    technique: str
    framework_id: str = field(default="—")
    label: int = 0               # 0 benign, 1 malicious


def _ip(rng: random.Random, malicious: bool) -> str:
    # attackers cluster on a couple of hosts (the lab's attacker box); benign is spread out
    if malicious:
        return rng.choice(["10.13.0.66", "10.13.0.67"])
    return f"10.13.{rng.randint(1, 4)}.{rng.randint(2, 254)}"


def _event(rng: random.Random, np_rng: np.random.Generator, t: str, when: datetime) -> Event:
    is_mal, fw, _ = TECHNIQUES[t]
    mal = bool(is_mal)

    if t == "benign_inference":
        path, status, b_in, lat = "/predict", 200, rng.randint(2_000, 60_000), float(np_rng.normal(45, 12))
        rate, paths, ent = rng.randint(1, 4), rng.randint(1, 3), float(np_rng.uniform(3.5, 5.0))
    elif t == "benign_health":
        path, status, b_in, lat = "/health", 200, 0, float(np_rng.normal(3, 1))
        rate, paths, ent = rng.randint(1, 6), 1, 0.0
    elif t == "recon_endpoint_sweep":
        path, status = rng.choice([p for p in ENDPOINTS if p not in ("/predict", "/health")]), rng.choice([401, 403, 404])
        b_in, lat = rng.randint(0, 200), float(np_rng.normal(6, 2))
        rate, paths, ent = rng.randint(4, 15), rng.randint(6, 14), float(np_rng.uniform(0, 2))
    elif t == "recon_verbose_errors":
        path, status, b_in, lat = "/predict", 500, rng.randint(1, 50), float(np_rng.normal(20, 8))
        rate, paths, ent = rng.randint(3, 10), rng.randint(2, 5), float(np_rng.uniform(0, 1.5))
    elif t == "abuse_rate_flood":
        path, status, b_in, lat = "/predict", 200, rng.randint(2_000, 40_000), float(np_rng.normal(120, 40))
        rate, paths, ent = rng.randint(40, 200), rng.randint(1, 2), float(np_rng.uniform(3.5, 5.0))
    elif t == "ml_model_extraction":
        path, status, b_in, lat = "/predict", 200, rng.randint(2_000, 50_000), float(np_rng.normal(55, 15))
        rate, paths, ent = rng.randint(20, 80), rng.randint(1, 2), float(np_rng.uniform(5.5, 8.0))  # high-entropy boundary probes
    else:  # ml_evasion_probe
        path, status, b_in, lat = "/predict", rng.choice([200, 200, 422]), rng.randint(2_000, 50_000), float(np_rng.normal(60, 18))
        rate, paths, ent = rng.randint(5, 25), rng.randint(1, 2), float(np_rng.uniform(6.0, 8.0))

    return Event(
        ts=when.astimezone(timezone.utc).isoformat(),
        src_ip=_ip(rng, mal),
        method="POST" if path in ("/predict", "/model") else "GET",
        path=path, status=status, bytes_in=max(0, b_in),
        latency_ms=round(max(0.5, lat), 2),
        user_agent=rng.choice(USER_AGENTS_MAL if mal else USER_AGENTS_BENIGN),
        requests_last_10s=rate, distinct_paths_last_60s=paths,
        payload_entropy=round(ent, 3),
        technique=t, framework_id=fw, label=int(mal),
    )


def synthesize(n: int, malicious_ratio: float, seed: int) -> list[Event]:
    rng = random.Random(seed)
    np_rng = np.random.default_rng(seed)
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events: list[Event] = []
    for i in range(n):
        mal = rng.random() < malicious_ratio
        t = rng.choice(MALICIOUS if mal else BENIGN)
        # bias the mix so benign traffic dominates realistically
        when = t0 + timedelta(seconds=i * rng.uniform(0.2, 2.0))
        events.append(_event(rng, np_rng, t, when))
    return events


def write(events: list[Event], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl = out_dir / "telemetry.jsonl"
    csvp = out_dir / "telemetry.csv"
    with jsonl.open("w") as f:
        for e in events:
            f.write(json.dumps(asdict(e)) + "\n")
    with csvp.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(asdict(events[0]).keys()))
        w.writeheader()
        w.writerows(asdict(e) for e in events)
    return jsonl, csvp


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate labeled security telemetry for The Range.")
    ap.add_argument("-n", "--num", type=int, default=5000, help="number of events")
    ap.add_argument("-r", "--malicious-ratio", type=float, default=0.18, help="fraction malicious")
    ap.add_argument("-s", "--seed", type=int, default=1337)
    ap.add_argument("-o", "--out", type=Path, default=Path("data"))
    args = ap.parse_args()

    events = synthesize(args.num, args.malicious_ratio, args.seed)
    jsonl, csvp = write(events, args.out)

    mal = sum(e.label for e in events)
    by_tech: dict[str, int] = {}
    for e in events:
        by_tech[e.technique] = by_tech.get(e.technique, 0) + 1

    print(f"✓ wrote {len(events)} events  ({mal} malicious / {len(events) - mal} benign)")
    print(f"  {jsonl}")
    print(f"  {csvp}")
    print("  breakdown:")
    for t, c in sorted(by_tech.items(), key=lambda kv: -kv[1]):
        fw = TECHNIQUES[t][1]
        print(f"    {c:>5}  {t:<22} {fw}")


if __name__ == "__main__":
    main()
