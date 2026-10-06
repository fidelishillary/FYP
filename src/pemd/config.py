"""Configuration loading and reproducibility helpers (NFR-04)."""

from __future__ import annotations

import copy
import importlib.metadata
import json
import platform
import random
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import yaml

DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "configs" / "default.yaml"

TRACKED_PACKAGES = [
    "numpy", "pandas", "scikit-learn", "xgboost", "pefile", "lief", "capstone",
    "yara-python", "pyyaml", "joblib",
]


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load the default config, optionally overlaid with a user config file."""
    with open(DEFAULT_CONFIG, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    if path is not None and Path(path).resolve() != DEFAULT_CONFIG:
        with open(path, encoding="utf-8") as fh:
            cfg = _merge(cfg, yaml.safe_load(fh) or {})
    return cfg


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)


def _git_commit() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def environment_info() -> dict[str, Any]:
    versions = {}
    for pkg in TRACKED_PACKAGES:
        try:
            versions[pkg] = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            versions[pkg] = None
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "git_commit": _git_commit(),
        "packages": versions,
    }


def new_run_dir(cfg: dict, name: str) -> Path:
    """Create experiments/<timestamp>_<name>/ and record config + environment in it."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = Path(cfg["paths"]["experiments"]) / f"{stamp}_{name}"
    run_dir.mkdir(parents=True, exist_ok=True)
    with open(run_dir / "config.yaml", "w", encoding="utf-8") as fh:
        yaml.safe_dump(cfg, fh, sort_keys=False)
    write_json(run_dir / "environment.json", environment_info())
    return run_dir


def write_json(path: str | Path, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=_json_default)


def _json_default(obj: Any) -> Any:
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, Path):
        return str(obj)
    raise TypeError(f"not JSON serialisable: {type(obj)!r}")
