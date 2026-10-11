# The Range 🎯

A reproducible, container-based **security home lab that doubles as a data factory**: it runs a deliberately vulnerable ML service, lets you attack it from a segmented attacker host, and turns the resulting traffic into a **labeled telemetry dataset** that downstream projects train on.

> Project **[0]** in a portfolio on adversarial ML & AI security. The Range is the *spine* — [Sentinel](#whats-next) (detection) trains on the data it produces, and [Mirage](#whats-next) (evasion) attacks what Sentinel learns.

---

## Why this exists

Most "home lab" repos stop at *"I installed Kali and Wazuh."* The Range goes one step further: every attack you run is **captured, labeled with the MITRE ATT&CK / ATLAS technique it belongs to, and exported as a dataset** — so the lab isn't just a place to practice, it's the source of ground truth for the AI-for-security work that follows.

## Threat model

| | |
|---|---|
| **Asset** | An ML inference API (`/predict`) and its model metadata |
| **Adversary** | Unauthenticated remote attacker with network reach to the service |
| **Adversary goals** | Discover endpoints, harvest error info, exhaust the service, **extract the model**, and **evade the classifier** |
| **Trust boundary** | The lab's `10.13.0.0/16` bridge network; nothing is exposed beyond loopback |
| **Out of scope** | Host compromise of the Docker daemon, supply-chain attacks on base images |

## Architecture

```
            10.13.0.0/16  (range_net, bridge)
  ┌───────────────────────────────────────────────────────┐
  │                                                         │
  │   ┌──────────────────┐         ┌────────────────────┐  │
  │   │  attacker  box   │  HTTP   │   target service   │  │
  │   │  10.13.0.66      │ ──────► │   10.13.1.10:8000  │  │
  │   │  run_attacks.py  │         │  vulnerable-ml-api │  │
  │   └──────────────────┘         └─────────┬──────────┘  │
  │                                           │ access.jsonl│
  │                                           ▼             │
  │                                 ┌────────────────────┐  │
  │                                 │ telemetry factory  │  │
  │                                 │ generate.py ──► data/│ │
  │                                 │ telemetry.{jsonl,csv}│ │
  │                                 └─────────┬──────────┘  │
  └───────────────────────────────────────────┼────────────┘
                                               ▼
                       feeds  [1] Sentinel detector  /  [2] Mirage evasion
```

## Quickstart

```bash
# 1. generate a labeled dataset — needs nothing but Python (no Docker required)
make dataset        # -> data/telemetry.{jsonl,csv}, ~5k events
make baseline       # validates the dataset is learnable

# 2. (optional) bring up the live lab and attack it for real logs
make up             # target at http://127.0.0.1:8000
make attack         # runs the full attacker playbook
make logs           # watch captured access.jsonl
make down
```

Requirements: Python 3.11+ for the data factory; Docker + Docker Compose for the live stack.

## What the lab captures

The vulnerable service has **planted weaknesses**, each paired with the technique an attacker uses against it and the behavioural signal it leaves in telemetry:

| Technique | Framework | Planted weakness | Signal in telemetry |
|---|---|---|---|
| Endpoint discovery | ATT&CK **T1595** | Undocumented `/debug`, `/model` | spike in `distinct_paths_last_60s`, 401/403/404s |
| Info harvesting | ATT&CK **T1592** | Verbose stack traces | 500s with large response, malformed bodies |
| Endpoint DoS | ATT&CK **T1499** | No rate limiting | high `requests_last_10s` from one host |
| Model extraction | ATLAS **AML.T0024** | Raw confidences returned | many high-`payload_entropy` boundary queries |
| Model evasion | ATLAS **AML.T0015** | Classifier exposed | perturbation sweeps that flip the decision |

## Results

Running `make baseline` on a 5,000-event dataset (18% malicious):

```
ROC-AUC: 1.000
              precision   recall   f1
      benign     1.000    1.000  1.000
   malicious     1.000    1.000  1.000
top features: requests_last_10s (0.49), payload_entropy (0.18), status (0.12)
```

**This clean separation is the point — and the honest caveat.** On *un-evasive* traffic the behavioural features trivially separate the classes. The interesting problem is what happens when the attacker adapts: that's exactly what [Mirage](#whats-next) does to this dataset, and why [Sentinel](#whats-next) is evaluated against evasion rather than this baseline. Reporting the 1.000 and then attacking it is the research arc.

## Limitations & honesty notes

- The classifier is a hash-based stand-in, not a trained CNN — the lab models *attack behaviour and telemetry*, not image accuracy. Swapping in a real model is on the roadmap.
- Synthetic replay (`generate.py`) approximates distributions; the live stack (`make up` + `make attack`) produces the real logs. Prefer the live path when you can.
- Perfectly separable data flatters any model; treat the baseline as a pipeline test, not a performance claim.

## What's next

This repo is the base of a build-on-each-other series:

- **[1] Sentinel** — detection models trained on `data/telemetry.csv`, evaluated honestly against drift and evasion.
- **[2] Mirage** — adversarial/evasive traffic that defeats Sentinel (ATLAS AML.T0015).
- **[3] Adversarial CAPTCHA** — the same red/blue arms race in a self-contained domain.
- **[4] Aegis** — adversarial training & input defense applied back to Sentinel and the CAPTCHA.
- **[5] Redcell** — an LLM/agent red-team harness (OWASP LLM Top 10, MITRE ATLAS).

## ⚠️ Ethics & safe use

Everything here targets a service **you run locally**. The vulnerable API is intentionally insecure — never deploy it on a reachable network. The attack code is published for **defensive research and education**; use it only against systems you own or are authorized to test.

## License

MIT — see [LICENSE](LICENSE).
