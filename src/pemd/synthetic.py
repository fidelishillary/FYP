"""Harmless synthetic PE files for tests and the dashboard demo.

:func:`make_pe` assembles a tiny PE32 image byte by byte. Its only code is
``push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret``, so the file does nothing
even if it were run. The imports and the ``.data`` payload are chosen to
*look* benign or suspicious to the static extractor, which is enough to
exercise the parser, the models, the decision gate and the dashboard without
handling any real malware (NFR-01, NFR-02).

:func:`generate_corpus` builds a noisy two-class corpus. The classes overlap on
purpose (some "benign" files import GetProcAddress or carry compressed data,
some "malware" files look clean), so the demo produces realistic, imperfect
metrics and a non-empty escalation band instead of a perfect score.
These files are **not** malware and the demo results are **not** research results.
"""

from __future__ import annotations

import csv
import hashlib
import struct
from datetime import date, timedelta
from pathlib import Path

import numpy as np

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
        if cursor > text_size:
            raise ValueError("too many imports for the synthetic PE builder")
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


# ----------------------------------------------------------------- demo corpus
BENIGN_APIS = {
    "kernel32.dll": ["GetStdHandle", "WriteFile", "ReadFile", "CreateFileW", "CloseHandle",
                     "ExitProcess", "GetCommandLineW", "HeapAlloc"],
    "user32.dll": ["MessageBoxW", "CreateWindowExW", "ShowWindow", "DispatchMessageW"],
    "gdi32.dll": ["TextOutW", "SelectObject"],
}
# APIs that legitimate software also uses, so they blur the class boundary
GREY_APIS = {
    "kernel32.dll": ["GetProcAddress", "LoadLibraryA", "VirtualAlloc", "VirtualProtect",
                     "GetTickCount", "CreateProcessW", "FindFirstFileW"],
    "advapi32.dll": ["RegOpenKeyExW", "OpenProcessToken"],
}
SUSPICIOUS_APIS = {
    "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                     "IsDebuggerPresent", "OpenProcess", "WinExec"],
    "advapi32.dll": ["RegSetValueExA", "CryptEncrypt", "CryptGenKey", "AdjustTokenPrivileges"],
    "wininet.dll": ["InternetOpenA", "InternetOpenUrlA", "InternetReadFile"],
    "user32.dll": ["SetWindowsHookExA", "GetAsyncKeyState"],
}
BENIGN_STRINGS = [b"Copyright (C) Example Software Ltd.", b"C:\\Program Files\\Example\\",
                  b"Usage: example.exe [options] <file>", b"Settings saved successfully.",
                  b"Error: could not open file", b"Version 2.4.1 build 1187"]
SUSPICIOUS_STRINGS = [b"cmd.exe /c ", b"powershell -nop -w hidden",
                      b"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      b"http://198.51.100.23/gate.php", b"Your files have been encrypted",
                      b"bitcoin", b"rundll32.exe"]


def _pick(rng: np.random.Generator, pool: dict[str, list[str]], k: int) -> dict[str, list[str]]:
    flat = [(d, f) for d, fs in pool.items() for f in fs]
    k = min(k, len(flat))
    out: dict[str, list[str]] = {}
    for i in rng.choice(len(flat), size=k, replace=False):
        d, f = flat[i]
        out.setdefault(d, []).append(f)
    return out


def _merge(*parts: dict[str, list[str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in parts:
        for d, fs in p.items():
            out.setdefault(d, [])
            out[d] += [f for f in fs if f not in out[d]]
    return out


def _payload(rng: np.random.Generator, high_entropy: bool, strings: list[bytes]) -> bytes:
    size = int(rng.integers(600, 6000))
    if high_entropy:
        body = rng.bytes(size)
    else:
        words = [b"the", b"file", b"user", b"value", b"window", b"data", b"config", b"open"]
        body = b" ".join(words[i] for i in rng.integers(0, len(words), size // 5))
    return body + b"\x00" + b"\x00".join(strings) + b"\x00"


def synthetic_sample(rng: np.random.Generator, malicious: bool) -> bytes:
    """One harmless synthetic PE that looks benign- or malware-like to the extractor."""
    if malicious:
        evasive = rng.random() < 0.15  # looks clean: few suspicious traits
        imports = _merge(
            _pick(rng, BENIGN_APIS, int(rng.integers(1, 4))),
            _pick(rng, GREY_APIS, int(rng.integers(0, 3))),
            _pick(rng, SUSPICIOUS_APIS, int(rng.integers(0, 2) if evasive else
                                            rng.integers(2, 6))),
        )
        high_entropy = rng.random() < (0.3 if evasive else 0.7)
        strings = [SUSPICIOUS_STRINGS[i] for i in
                   rng.choice(len(SUSPICIOUS_STRINGS), int(rng.integers(0, 3)), replace=False)]
        strings += [BENIGN_STRINGS[int(rng.integers(len(BENIGN_STRINGS)))]]
        text_name = b"UPX0" if rng.random() < 0.25 else b".text"
    else:
        unusual = rng.random() < 0.15  # installers, protectors, admin tools
        imports = _merge(
            _pick(rng, BENIGN_APIS, int(rng.integers(2, 6))),
            _pick(rng, GREY_APIS, int(rng.integers(1, 4) if unusual else rng.integers(0, 2))),
            _pick(rng, SUSPICIOUS_APIS, int(rng.integers(0, 2)) if unusual else 0),
        )
        high_entropy = rng.random() < (0.5 if unusual else 0.1)
        strings = [BENIGN_STRINGS[i] for i in
                   rng.choice(len(BENIGN_STRINGS), int(rng.integers(1, 4)), replace=False)]
        if unusual and rng.random() < 0.3:
            strings.append(SUSPICIOUS_STRINGS[int(rng.integers(len(SUSPICIOUS_STRINGS)))])
        text_name = b"UPX0" if unusual and rng.random() < 0.1 else b".text"
    return make_pe(imports=imports, payload=_payload(rng, high_entropy, strings),
                   text_name=text_name, dll=bool(rng.random() < 0.1))


def generate_corpus(out_dir: str | Path, n_per_class: int = 300, seed: int = 42,
                    n_holdout: int = 20) -> dict[str, Path]:
    """Write ``malware/``, ``benign/``, ``first_seen.csv`` and a ``samples/`` folder of
    unlabelled hold-out files (for trying the scanner) under ``out_dir``."""
    out_dir = Path(out_dir)
    rng = np.random.default_rng(seed)
    dirs = {k: out_dir / k for k in ("malware", "benign", "samples")}
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    start = date(2024, 1, 1)
    rows = []
    for label, folder in ((1, dirs["malware"]), (0, dirs["benign"])):
        for i in range(n_per_class):
            data = synthetic_sample(rng, malicious=bool(label))
            name = f"{'mal' if label else 'ben'}_{i:04d}.bin"
            (folder / name).write_bytes(data)
            seen = start + timedelta(days=int(rng.integers(0, 730)))
            rows.append((hashlib.sha256(data).hexdigest(), seen.isoformat()))
    for i in range(n_holdout):
        data = synthetic_sample(rng, malicious=bool(i % 2))
        (dirs["samples"] / f"sample_{i:02d}.bin").write_bytes(data)
    dates = out_dir / "first_seen.csv"
    with open(dates, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["sha256", "first_seen"])
        w.writerows(rows)
    return {**dirs, "dates": dates}
