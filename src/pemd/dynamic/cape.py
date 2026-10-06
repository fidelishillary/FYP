"""Optional dynamic analysis fallback via a CAPE sandbox REST API (FR-14).

This module never runs a sample locally. It submits an escalated file to a CAPE
instance that must live on the isolated host-only lab network (NFR-01) and
turns CAPE's ``malscore`` into a verdict. As a guard against misconfiguration,
it refuses any sandbox URL that does not resolve to a private or loopback
address, and does nothing unless ``dynamic.enabled`` is true.

Endpoints follow CAPEv2's ``/apiv2`` API; check them against the version
installed in the lab.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class SandboxSafetyError(RuntimeError):
    pass


def assert_isolated(url: str) -> None:
    host = urlparse(url).hostname
    if not host:
        raise SandboxSafetyError(f"invalid sandbox URL {url!r}")
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise SandboxSafetyError(f"cannot resolve sandbox host {host!r}") from exc
    for a in addrs:
        ip = ipaddress.ip_address(a)
        if not (ip.is_private or ip.is_loopback):
            raise SandboxSafetyError(
                f"sandbox {host} resolves to public address {a}; the CAPE VM must be on the "
                "isolated host-only network (NFR-01)"
            )


@dataclass
class DynamicResult:
    task_id: int
    malscore: float
    verdict: int
    seconds: float
    signatures: list[str]


class CapeClient:
    def __init__(self, cfg: dict):
        d = cfg["dynamic"]
        if not d.get("enabled"):
            raise RuntimeError("dynamic analysis is disabled (set dynamic.enabled: true)")
        assert_isolated(d["cape_url"])
        import requests

        self.base = d["cape_url"].rstrip("/") + "/apiv2"
        self.session = requests.Session()
        if d.get("api_token"):
            self.session.headers["Authorization"] = f"Token {d['api_token']}"
        self.timeout_s = int(d.get("timeout_s", 600))
        self.poll_s = int(d.get("poll_interval_s", 15))
        self.threshold = float(d.get("malscore_threshold", 5.0))

    def submit(self, path: str | Path) -> int:
        with open(path, "rb") as fh:
            r = self.session.post(f"{self.base}/tasks/create/file/", files={"file": fh}, timeout=60)
        r.raise_for_status()
        data = r.json()
        ids = data.get("data", {}).get("task_ids") or data.get("task_ids") or []
        if not ids:
            raise RuntimeError(f"CAPE did not return a task id: {data}")
        return int(ids[0])

    def wait(self, task_id: int) -> None:
        deadline = time.monotonic() + self.timeout_s
        while time.monotonic() < deadline:
            r = self.session.get(f"{self.base}/tasks/status/{task_id}/", timeout=30)
            r.raise_for_status()
            status = r.json().get("data")
            if status == "reported":
                return
            if status in ("failed_analysis", "failed_processing", "failed_reporting"):
                raise RuntimeError(f"CAPE task {task_id} failed: {status}")
            time.sleep(self.poll_s)
        raise TimeoutError(f"CAPE task {task_id} not reported within {self.timeout_s}s")

    def report(self, task_id: int) -> dict:
        r = self.session.get(f"{self.base}/tasks/get/report/{task_id}/json/", timeout=120)
        r.raise_for_status()
        return r.json()

    def analyse(self, path: str | Path) -> DynamicResult:
        t0 = time.monotonic()
        task_id = self.submit(path)
        self.wait(task_id)
        rep = self.report(task_id)
        score = float(rep.get("malscore", 0.0) or 0.0)
        sigs = [s.get("name", "") for s in rep.get("signatures", []) or []]
        return DynamicResult(task_id, score, int(score >= self.threshold),
                             time.monotonic() - t0, sigs)
