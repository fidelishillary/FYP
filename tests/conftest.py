"""Test fixtures.

Tests never use real malware. :func:`pemd.synthetic.make_pe` assembles tiny,
harmless PE32 images byte by byte (the code section just returns), which is
enough to exercise the parser, extractor and pipeline.
"""

from __future__ import annotations

import numpy as np
import pytest

from pemd.config import load_config
from pemd.synthetic import make_pe

__all__ = ["make_pe"]


@pytest.fixture
def cfg(tmp_path):
    c = load_config()
    c["paths"]["experiments"] = str(tmp_path / "experiments")
    c["selection"]["k"] = 60
    c["models"]["random_forest"]["n_estimators"] = 30
    c["models"]["xgboost"]["n_estimators"] = 30
    c["evaluation"]["cv_folds"] = 3
    return c


@pytest.fixture
def pe_corpus(tmp_path):
    """Small labelled corpus of synthetic PEs.

    "Malware" imports injection APIs and carries a high-entropy payload;
    "benign" imports ordinary APIs and carries low-entropy text. Tests only
    check that the pipeline runs and learns this trivially separable signal.
    """
    rng = np.random.default_rng(0)
    mal_dir, ben_dir = tmp_path / "raw" / "malware", tmp_path / "raw" / "benign"
    mal_dir.mkdir(parents=True)
    ben_dir.mkdir(parents=True)
    for i in range(30):
        mal = make_pe(
            imports={"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory",
                                      "CreateRemoteThread", "GetProcAddress"]},
            payload=rng.bytes(int(rng.integers(512, 4096))),
            text_name=b"UPX0" if i % 3 == 0 else b".text",
        )
        ben = make_pe(
            imports={"kernel32.dll": ["GetStdHandle", "WriteFile", "ExitProcess"],
                     "user32.dll": ["MessageBoxW"]},
            payload=(b"Hello world from a benign test program %d. " % i) * int(rng.integers(5, 60)),
        )
        (mal_dir / f"m{i}.bin").write_bytes(mal)
        (ben_dir / f"b{i}.bin").write_bytes(ben)
    (mal_dir / "not_a_pe.txt").write_bytes(b"just text")
    (ben_dir / "dup.bin").write_bytes((ben_dir / "b0.bin").read_bytes())
    return mal_dir, ben_dir
