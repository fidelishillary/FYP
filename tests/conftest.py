"""Test fixtures.

Tests never use real malware. :func:`make_pe` assembles tiny, harmless PE32
images byte by byte (the code section just returns), which is enough to
exercise the parser, extractor and pipeline.
"""

from __future__ import annotations

import struct

import numpy as np
import pytest

from pemd.config import load_config

FILE_ALIGN, SECT_ALIGN = 0x200, 0x1000
CODE = bytes.fromhex("5589e531c05dc3")  # push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def make_pe(imports: dict[str, list[str]] | None = None, payload: bytes = b"",
            text_name: bytes = b".text", dll: bool = False) -> bytes:
    imports = imports or {}
    text_rva, text_raw, text_size = 0x1000, 0x200, 0x400

    # ---- .text: code at +0, import structures from +0x100 -------------------
    text = bytearray(text_size)
    text[: len(CODE)] = CODE
    imp_dir = (0, 0)
    if imports:
        base = 0x100
        n = len(imports)
        desc_off = base
        cursor = desc_off + 20 * (n + 1)
        thunk_blocks, name_blobs = [], []
        layout = []
        for dll_name, funcs in imports.items():
            ilt = cursor
            cursor += 4 * (len(funcs) + 1)
            iat = cursor
            cursor += 4 * (len(funcs) + 1)
            layout.append((dll_name, funcs, ilt, iat))
        for dll_name, funcs, ilt, iat in layout:
            dll_off = cursor
            cursor = _align(cursor + len(dll_name) + 1, 2)
            hn = []
            for f in funcs:
                hn.append(cursor)
                cursor = _align(cursor + 2 + len(f) + 1, 2)
            name_blobs.append((dll_off, dll_name, list(zip(hn, funcs))))
            thunk_blocks.append((ilt, iat, hn))
        assert cursor <= text_size, "too many imports for the test builder"
        for i, ((ilt, iat, hn), (dll_off, dll_name, hnf)) in enumerate(
            zip(thunk_blocks, name_blobs)
        ):
            struct.pack_into("<IIIII", text, desc_off + 20 * i, text_rva + ilt, 0, 0,
                             text_rva + dll_off, text_rva + iat)
            for j, h in enumerate(hn):
                struct.pack_into("<I", text, ilt + 4 * j, text_rva + h)
                struct.pack_into("<I", text, iat + 4 * j, text_rva + h)
            text[dll_off : dll_off + len(dll_name)] = dll_name.encode()
            for h, f in hnf:
                text[h + 2 : h + 2 + len(f)] = f.encode()
        imp_dir = (text_rva + desc_off, 20 * (n + 1))

    # ---- .data: arbitrary payload ---------------------------------------------
    data_rva = 0x2000
    data_raw = text_raw + text_size
    data_size = _align(max(len(payload), 1), FILE_ALIGN)
    data = payload.ljust(data_size, b"\x00")
    size_of_image = data_rva + _align(data_size, SECT_ALIGN)

    # ---- headers ---------------------------------------------------------------
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    characteristics = 0x0102 | (0x2000 if dll else 0)
    coff = struct.pack("<HHIIIHH", 0x14C, 2, 0x5F000000, 0, 0, 0xE0, characteristics)
    dirs = [(0, 0)] * 16
    dirs[1] = imp_dir
    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0, text_size, data_size, 0, text_rva, text_rva, data_rva, 0x400000,
        SECT_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0, size_of_image, 0x200, 0, 3, 0x8140,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + b"".join(struct.pack("<II", *d) for d in dirs)
    sections = struct.pack("<8sIIIIIIHHI", text_name, text_size, text_rva, text_size, text_raw,
                           0, 0, 0, 0, 0x60000020)
    sections += struct.pack("<8sIIIIIIHHI", b".data", data_size, data_rva, data_size, data_raw,
                            0, 0, 0, 0, 0xC0000040)
    header = bytes(dos) + b"PE\x00\x00" + coff + opt + sections
    header = header.ljust(text_raw, b"\x00")
    return header + bytes(text) + data


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
