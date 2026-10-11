#!/usr/bin/env python3
"""
Vulnerable ML inference service — a DELIBERATELY insecure target for The Range.

It exposes an image "classifier" with a set of planted weaknesses so that the
attack scripts have something real to hit and the telemetry pipeline has real
logs to label. DO NOT deploy this anywhere reachable. Localhost lab only.

Planted weaknesses (each maps to a technique the attacks exercise):
  - No authentication on any endpoint
  - No rate limiting            -> ATT&CK T1499 (flooding) / ATLAS AML.T0024 (extraction)
  - Verbose stack traces        -> ATT&CK T1592 (info harvesting)
  - Undocumented /debug, /model -> ATT&CK T1595 (endpoint discovery)
  - Confidence returned raw     -> ATLAS AML.T0015 (evasion boundary probing)
"""
from __future__ import annotations

import hashlib
import logging
import math
import os
import time
from collections import Counter

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

# structured access log -> telemetry collector tails this
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[logging.FileHandler(os.getenv("ACCESS_LOG", "/var/log/range/access.jsonl")),
              logging.StreamHandler()],
)
log = logging.getLogger("range.access")

app = FastAPI(title="Range Image Classifier", version="0.1-insecure")
START = time.time()
LABELS = ["cat", "dog", "truck", "ship", "frog", "plane", "deer", "horse", "bird", "car"]


class Image(BaseModel):
    # base64 or raw pixel list — we don't actually decode; this is a lab stand-in
    pixels: list[float]


def _entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@app.middleware("http")
async def access_log(request: Request, call_next):
    t0 = time.time()
    body = b""
    if request.method in ("POST", "PUT"):
        body = await request.body()

        async def receive():  # re-inject consumed body
            return {"type": "http.request", "body": body}
        request._receive = receive

    response = await call_next(request)
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "src_ip": request.client.host if request.client else "-",
        "method": request.method,
        "path": request.url.path,
        "status": response.status_code,
        "bytes_in": len(body),
        "latency_ms": round((time.time() - t0) * 1000, 2),
        "user_agent": request.headers.get("user-agent", ""),
        "payload_entropy": round(_entropy(body.decode("utf-8", "ignore")), 3),
    }
    log.info(__import__("json").dumps(rec))
    return response


@app.get("/health")
def health():
    return {"status": "ok", "uptime_s": round(time.time() - START, 1)}


@app.post("/predict")
async def predict(img: Image):
    # VULN: no auth, no rate limit, returns raw confidence (helps evasion/extraction)
    h = hashlib.md5(bytes(int(abs(p)) % 256 for p in img.pixels[:64])).hexdigest()
    idx = int(h, 16) % len(LABELS)
    conf = 0.5 + (int(h[:4], 16) % 5000) / 10000
    return {"label": LABELS[idx], "confidence": round(conf, 4), "model": "range-cnn-v0"}


@app.get("/model")
def model_card():
    # VULN: leaks architecture detail useful for extraction / evasion
    return {"arch": "resnet9", "classes": LABELS, "input": "32x32x3",
            "weights_sha": "deadbeef...", "note": "do not expose in prod"}


@app.get("/debug")
def debug():
    # VULN: undocumented endpoint leaking environment
    return {"env": {k: v for k, v in os.environ.items() if "KEY" not in k.upper()},
            "cwd": os.getcwd()}


@app.exception_handler(Exception)
async def verbose_errors(request: Request, exc: Exception):
    # VULN: full detail returned to the client
    import traceback
    return JSONResponse(status_code=500,
                        content={"error": str(exc), "trace": traceback.format_exc()})


@app.get("/", response_class=PlainTextResponse)
def root():
    return "Range Image Classifier (insecure lab target). Try /health /predict /model /debug"
