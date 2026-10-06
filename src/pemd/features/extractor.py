"""Static PE feature extraction (FR-01, FR-02, FR-03, report Table 3.1).

The file is only ever *parsed* (pefile, LIEF) and *disassembled* (capstone);
it is never loaded or executed. Every sample maps to a fixed-length numeric
vector whose layout is described by :func:`feature_names`.

Feature groups and name prefixes
--------------------------------
hdr:*        PE header fields (COFF + optional header, DLL characteristics)
sec:*        section statistics and entropy, packer section names
sec_name_h:* hashed section names
imp:*        import counts;  imp_dll_h:* / imp_fn_h:* hashed DLLs and DLL:function pairs
api_cat:*    RE-guided API capability groups (see api_categories.py)
exp:*        export count;   exp_h:* hashed export names
op:*         opcode statistics; op_h:* hashed mnemonic n-gram frequencies
byte_hist:*  normalised byte histogram
str:*        printable string statistics
meta:*       file metadata (size, overlay, signature, resources, TLS, debug, ...)
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
import zlib
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np
import pefile

from pemd.features.api_categories import API_CATEGORIES, normalise_api

log = logging.getLogger(__name__)

try:  # optional: opcode n-grams
    import capstone
except ImportError:  # pragma: no cover
    capstone = None

try:  # used for metadata checks (FR-03)
    import lief

    if hasattr(lief, "logging"):
        lief.logging.disable()
except ImportError:  # pragma: no cover
    lief = None


class InvalidPEError(ValueError):
    """Raised for files that are not valid / are corrupted PE images (FR-01)."""


DEFAULT_DIMS = {
    "imports_dll": 128,
    "imports_func": 512,
    "exports": 64,
    "section_names": 32,
    "opcode_ngrams": 256,
}

HEADER_FIELDS = [
    "machine_i386", "machine_amd64", "machine_other", "is_dll", "is_64", "n_sections",
    "timedatestamp", "char_relocs_stripped", "char_executable", "char_large_address_aware",
    "char_system", "size_of_code", "size_of_init_data", "size_of_uninit_data", "entry_point",
    "base_of_code", "image_base", "section_alignment", "file_alignment", "major_linker_version",
    "major_os_version", "major_image_version", "major_subsystem_version", "size_of_image",
    "size_of_headers", "checksum", "checksum_zero", "subsystem_gui", "subsystem_console",
    "subsystem_native", "subsystem_other", "dllchar_high_entropy_va", "dllchar_aslr",
    "dllchar_force_integrity", "dllchar_nx", "dllchar_no_seh", "dllchar_guard_cf",
    "size_of_stack_reserve", "size_of_heap_reserve", "n_rva_and_sizes",
]

SECTION_FIELDS = [
    "count", "entropy_mean", "entropy_min", "entropy_max", "raw_size_mean", "virtual_size_mean",
    "virtual_raw_ratio_max", "n_executable", "n_writable", "n_wx", "n_zero_raw",
    "n_high_entropy", "n_nonstandard_names", "packer_name", "entry_entropy",
    "entry_not_executable", "entry_in_last", "entry_outside_sections",
]

IMPORT_FIELDS = ["n_dlls", "n_functions", "n_ordinal"]
OPCODE_FIELDS = ["n_insn", "n_unique_mnemonics", "frac_invalid"]
STRING_FIELDS = [
    "count", "avg_len", "n_urls", "n_ips", "n_paths", "n_registry", "n_embedded_mz",
    "n_shell", "n_crypto_wallet",
]
META_FIELDS = [
    "file_size", "overlay_size", "overlay_ratio", "file_entropy", "has_signature",
    "has_resources", "n_resources", "has_version_info", "has_tls", "has_debug",
    "has_relocations", "has_rich_header", "has_load_config", "has_exceptions",
]

STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata", ".pdata", ".tls",
    ".bss", ".crt", ".didat", ".gfids", ".00cfg", ".xdata", "code", "data", ".textbss",
}
PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", ".aspack", ".adata", ".petite", ".nsp0", ".nsp1", ".themida",
    ".vmp0", ".vmp1", ".vmp2", "mpress1", "mpress2", ".enigma1", ".enigma2", "pec1", "pec2",
    ".packed", ".mew", ".yp", "fsg!",
}

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_CNT_CODE = 0x00000020

_STRING_RE_CACHE: dict[int, re.Pattern] = {}
_URL_RE = re.compile(rb"https?://", re.I)
_IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PATH_RE = re.compile(rb"[a-z]:\\", re.I)
_REG_RE = re.compile(rb"HKEY_|software\\", re.I)
_SHELL_RE = re.compile(rb"cmd\.exe|powershell|wscript|cscript|rundll32|regsvr32", re.I)
_WALLET_RE = re.compile(rb"bitcoin|monero|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")


@dataclass
class ExtractionResult:
    vector: np.ndarray
    sha256: str
    seconds: float


def _h(token: str, dims: int) -> int:
    """Stable (process-independent) feature hashing bucket."""
    return zlib.crc32(token.encode("utf-8", "ignore")) % dims


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


@lru_cache(maxsize=8)
def feature_names(dims_items: tuple | None = None, ngram: int = 2) -> list[str]:
    """Ordered names of the feature vector. ``dims_items`` is ``tuple(dims.items())``."""
    dims = dict(dims_items) if dims_items else DEFAULT_DIMS
    names: list[str] = []
    names += [f"hdr:{f}" for f in HEADER_FIELDS]
    names += [f"sec:{f}" for f in SECTION_FIELDS]
    names += [f"sec_name_h:{i}" for i in range(dims["section_names"])]
    names += [f"imp:{f}" for f in IMPORT_FIELDS]
    names += [f"imp_dll_h:{i}" for i in range(dims["imports_dll"])]
    names += [f"imp_fn_h:{i}" for i in range(dims["imports_func"])]
    names += [f"api_cat:{c}" for c in API_CATEGORIES]
    names += ["exp:count"]
    names += [f"exp_h:{i}" for i in range(dims["exports"])]
    names += [f"op:{f}" for f in OPCODE_FIELDS]
    names += [f"op_h:{i}" for i in range(dims["opcode_ngrams"])]
    names += [f"byte_hist:{i}" for i in range(256)]
    names += [f"str:{f}" for f in STRING_FIELDS]
    names += [f"meta:{f}" for f in META_FIELDS]
    return names


class FeatureExtractor:
    """Turns a PE file into a fixed-length feature vector."""

    def __init__(self, cfg: dict | None = None):
        fcfg = (cfg or {}).get("features", {})
        self.dims = {**DEFAULT_DIMS, **fcfg.get("hash_dims", {})}
        opcfg = fcfg.get("opcode", {})
        self.opcode_enabled = bool(opcfg.get("enabled", True))
        if self.opcode_enabled and capstone is None:
            log.warning("capstone is not importable; opcode n-gram features will be zero")
            self.opcode_enabled = False
        self.ngram = int(opcfg.get("ngram", 2))
        self.op_max_bytes = int(opcfg.get("max_bytes", 65536))
        self.min_str = int(fcfg.get("strings", {}).get("min_length", 5))
        self.max_size = int(float(fcfg.get("max_file_size_mb", 64)) * 1024 * 1024)
        self.names = feature_names(tuple(self.dims.items()), self.ngram)
        self.index = {n: i for i, n in enumerate(self.names)}
        # Optional record of which tokens fell into each hash bucket, so hashed
        # features can be explained (e.g. imp_fn_h:12 -> kernel32.dll:virtualallocex).
        self.vocab: dict[str, Counter] | None = None

    def collect_vocabulary(self) -> None:
        self.vocab = {}

    def vocabulary(self, top: int = 5) -> dict[str, list[str]]:
        return {k: [t for t, _ in c.most_common(top)] for k, c in (self.vocab or {}).items()}

    # ------------------------------------------------------------------ public
    def extract_file(self, path: str | Path) -> ExtractionResult:
        path = Path(path)
        size = path.stat().st_size
        if size > self.max_size:
            raise InvalidPEError(f"file larger than limit ({size} bytes)")
        return self.extract_bytes(path.read_bytes(), path=path)

    def extract_bytes(self, data: bytes, path: Path | None = None) -> ExtractionResult:
        start = time.perf_counter()
        pe = self._parse(data)
        vec = np.zeros(len(self.names), dtype=np.float32)
        try:
            self._header(pe, vec)
            self._sections(pe, vec)
            self._imports(pe, vec)
            self._exports(pe, vec)
            self._opcodes(pe, data, vec)
            self._bytes_and_strings(data, vec)
            self._metadata(pe, data, path, vec)
        except InvalidPEError:
            raise
        except Exception as exc:  # malformed structures deep inside the file
            raise InvalidPEError(f"feature extraction failed: {exc}") from exc
        finally:
            pe.close()
        return ExtractionResult(
            vector=vec,
            sha256=hashlib.sha256(data).hexdigest(),
            seconds=time.perf_counter() - start,
        )

    # ----------------------------------------------------------------- helpers
    def _set(self, vec: np.ndarray, name: str, value: float) -> None:
        vec[self.index[name]] = value

    def _add_hashed(self, vec: np.ndarray, prefix: str, dims: int, tokens) -> None:
        base = self.index[f"{prefix}:0"]
        for tok in tokens:
            b = _h(tok, dims)
            vec[base + b] += 1.0
            self._record(f"{prefix}:{b}", tok)

    def _record(self, bucket: str, token: str) -> None:
        if self.vocab is not None:
            self.vocab.setdefault(bucket, Counter())[token] += 1

    @staticmethod
    def _parse(data: bytes) -> pefile.PE:
        if len(data) < 64 or data[:2] != b"MZ":
            raise InvalidPEError("missing MZ header")
        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY[d]
                    for d in (
                        "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT",
                        "IMAGE_DIRECTORY_ENTRY_RESOURCE", "IMAGE_DIRECTORY_ENTRY_TLS",
                        "IMAGE_DIRECTORY_ENTRY_DEBUG", "IMAGE_DIRECTORY_ENTRY_BASERELOC",
                        "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
                    )
                ]
            )
        except pefile.PEFormatError as exc:
            raise InvalidPEError(str(exc)) from exc
        if not hasattr(pe, "OPTIONAL_HEADER") or pe.OPTIONAL_HEADER is None:
            pe.close()
            raise InvalidPEError("missing optional header")
        if len(pe.sections) < pe.FILE_HEADER.NumberOfSections:
            pe.close()
            raise InvalidPEError("truncated section table")
        for sec in pe.sections:
            if sec.SizeOfRawData and sec.PointerToRawData >= len(data):
                pe.close()
                raise InvalidPEError("truncated file: section data lies beyond end of file")
        return pe

    # ---------------------------------------------------------------- groups
    def _header(self, pe: pefile.PE, vec: np.ndarray) -> None:
        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        s = lambda k, v: self._set(vec, f"hdr:{k}", float(v))  # noqa: E731
        s("machine_i386", fh.Machine == 0x14C)
        s("machine_amd64", fh.Machine == 0x8664)
        s("machine_other", fh.Machine not in (0x14C, 0x8664))
        s("is_dll", pe.is_dll())
        s("is_64", oh.Magic == 0x20B)
        s("n_sections", fh.NumberOfSections)
        s("timedatestamp", fh.TimeDateStamp)
        s("char_relocs_stripped", fh.Characteristics & 0x0001 != 0)
        s("char_executable", fh.Characteristics & 0x0002 != 0)
        s("char_large_address_aware", fh.Characteristics & 0x0020 != 0)
        s("char_system", fh.Characteristics & 0x1000 != 0)
        s("size_of_code", oh.SizeOfCode)
        s("size_of_init_data", oh.SizeOfInitializedData)
        s("size_of_uninit_data", oh.SizeOfUninitializedData)
        s("entry_point", oh.AddressOfEntryPoint)
        s("base_of_code", oh.BaseOfCode)
        s("image_base", oh.ImageBase)
        s("section_alignment", oh.SectionAlignment)
        s("file_alignment", oh.FileAlignment)
        s("major_linker_version", oh.MajorLinkerVersion)
        s("major_os_version", oh.MajorOperatingSystemVersion)
        s("major_image_version", oh.MajorImageVersion)
        s("major_subsystem_version", oh.MajorSubsystemVersion)
        s("size_of_image", oh.SizeOfImage)
        s("size_of_headers", oh.SizeOfHeaders)
        s("checksum", oh.CheckSum)
        s("checksum_zero", oh.CheckSum == 0)
        s("subsystem_gui", oh.Subsystem == 2)
        s("subsystem_console", oh.Subsystem == 3)
        s("subsystem_native", oh.Subsystem == 1)
        s("subsystem_other", oh.Subsystem not in (1, 2, 3))
        dc = oh.DllCharacteristics
        s("dllchar_high_entropy_va", dc & 0x0020 != 0)
        s("dllchar_aslr", dc & 0x0040 != 0)
        s("dllchar_force_integrity", dc & 0x0080 != 0)
        s("dllchar_nx", dc & 0x0100 != 0)
        s("dllchar_no_seh", dc & 0x0400 != 0)
        s("dllchar_guard_cf", dc & 0x4000 != 0)
        s("size_of_stack_reserve", oh.SizeOfStackReserve)
        s("size_of_heap_reserve", oh.SizeOfHeapReserve)
        s("n_rva_and_sizes", oh.NumberOfRvaAndSizes)

    def _entry_section(self, pe: pefile.PE):
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for idx, sec in enumerate(pe.sections):
            if sec.contains_rva(ep):
                return idx, sec
        return None, None

    def _sections(self, pe: pefile.PE, vec: np.ndarray) -> None:
        s = lambda k, v: self._set(vec, f"sec:{k}", float(v))  # noqa: E731
        secs = pe.sections
        s("count", len(secs))
        names = []
        if secs:
            ents = [sec.get_entropy() for sec in secs]
            raw = [sec.SizeOfRawData for sec in secs]
            virt = [sec.Misc_VirtualSize for sec in secs]
            chars = [sec.Characteristics for sec in secs]
            names = [sec.Name.rstrip(b"\x00").decode("latin-1").lower() for sec in secs]
            s("entropy_mean", np.mean(ents))
            s("entropy_min", min(ents))
            s("entropy_max", max(ents))
            s("raw_size_mean", np.mean(raw))
            s("virtual_size_mean", np.mean(virt))
            s("virtual_raw_ratio_max", max(v / r if r else float(v > 0) for v, r in zip(virt, raw)))
            ex = [c & IMAGE_SCN_MEM_EXECUTE != 0 for c in chars]
            wr = [c & IMAGE_SCN_MEM_WRITE != 0 for c in chars]
            s("n_executable", sum(ex))
            s("n_writable", sum(wr))
            s("n_wx", sum(a and b for a, b in zip(ex, wr)))
            s("n_zero_raw", sum(r == 0 for r in raw))
            s("n_high_entropy", sum(e > 7.0 for e in ents))
            s("n_nonstandard_names", sum(n not in STANDARD_SECTIONS for n in names))
            s("packer_name", any(n in PACKER_SECTIONS for n in names))
        idx, entry = self._entry_section(pe)
        if entry is None:
            s("entry_outside_sections", 1)
        else:
            s("entry_entropy", entry.get_entropy())
            s("entry_not_executable", entry.Characteristics & IMAGE_SCN_MEM_EXECUTE == 0)
            s("entry_in_last", idx == len(secs) - 1)
        self._add_hashed(vec, "sec_name_h", self.dims["section_names"], names)

    def _imports(self, pe: pefile.PE, vec: np.ndarray) -> None:
        dlls, funcs, n_ord = [], [], 0
        cats = Counter()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = (entry.dll or b"").decode("latin-1").lower()
            dlls.append(dll)
            for imp in entry.imports:
                if imp.name is None:
                    n_ord += 1
                    funcs.append(f"{dll}:ord{imp.ordinal}")
                    continue
                fname = imp.name.decode("latin-1")
                funcs.append(f"{dll}:{fname.lower()}")
                norm = normalise_api(fname)
                for cat, members in API_CATEGORIES.items():
                    if norm in members:
                        cats[cat] += 1
        self._set(vec, "imp:n_dlls", len(dlls))
        self._set(vec, "imp:n_functions", len(funcs))
        self._set(vec, "imp:n_ordinal", n_ord)
        self._add_hashed(vec, "imp_dll_h", self.dims["imports_dll"], dlls)
        self._add_hashed(vec, "imp_fn_h", self.dims["imports_func"], funcs)
        for cat in API_CATEGORIES:
            self._set(vec, f"api_cat:{cat}", cats[cat])

    def _exports(self, pe: pefile.PE, vec: np.ndarray) -> None:
        exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        names = []
        if exp is not None:
            names = [(e.name or b"").decode("latin-1").lower() for e in exp.symbols]
        self._set(vec, "exp:count", len(names))
        self._add_hashed(vec, "exp_h", self.dims["exports"], [n for n in names if n])

    def _opcodes(self, pe: pefile.PE, data: bytes, vec: np.ndarray) -> None:
        if not self.opcode_enabled:
            return
        machine = pe.FILE_HEADER.Machine
        if machine == 0x14C:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif machine == 0x8664:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            return
        md.skipdata = True
        _, sec = self._entry_section(pe)
        if sec is None:
            return
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        start = sec.PointerToRawData + (ep - sec.VirtualAddress)
        end = min(sec.PointerToRawData + sec.SizeOfRawData, start + self.op_max_bytes, len(data))
        if start < 0 or start >= end:
            return
        mnems, invalid = [], 0
        for _addr, _size, mnem, _ops in md.disasm_lite(data[start:end], ep):
            if mnem == ".byte":
                invalid += 1
                continue
            mnems.append(mnem)
        n = len(mnems) + invalid
        self._set(vec, "op:n_insn", len(mnems))
        self._set(vec, "op:n_unique_mnemonics", len(set(mnems)))
        self._set(vec, "op:frac_invalid", invalid / n if n else 0.0)
        k = self.ngram
        grams = [" ".join(mnems[i : i + k]) for i in range(len(mnems) - k + 1)]
        if grams:
            base = self.index["op_h:0"]
            dims = self.dims["opcode_ngrams"]
            for g, c in Counter(grams).items():
                b = _h(g, dims)
                vec[base + b] += c / len(grams)
                self._record(f"op_h:{b}", g)

    def _bytes_and_strings(self, data: bytes, vec: np.ndarray) -> None:
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        base = self.index["byte_hist:0"]
        vec[base : base + 256] = counts / max(len(data), 1)

        pat = _STRING_RE_CACHE.get(self.min_str)
        if pat is None:
            pat = re.compile(rb"[\x20-\x7e]{%d,}" % self.min_str)
            _STRING_RE_CACHE[self.min_str] = pat
        strings = pat.findall(data)
        blob = b"\n".join(strings)
        s = lambda k, v: self._set(vec, f"str:{k}", float(v))  # noqa: E731
        s("count", len(strings))
        s("avg_len", np.mean([len(x) for x in strings]) if strings else 0.0)
        s("n_urls", len(_URL_RE.findall(blob)))
        s("n_ips", len(_IP_RE.findall(blob)))
        s("n_paths", len(_PATH_RE.findall(blob)))
        s("n_registry", len(_REG_RE.findall(blob)))
        s("n_embedded_mz", max(data.count(b"MZ\x90\x00") - 1, 0))
        s("n_shell", len(_SHELL_RE.findall(blob)))
        s("n_crypto_wallet", len(_WALLET_RE.findall(blob)))

    def _metadata(self, pe: pefile.PE, data: bytes, path: Path | None, vec: np.ndarray) -> None:
        s = lambda k, v: self._set(vec, f"meta:{k}", float(v))  # noqa: E731
        overlay_off = pe.get_overlay_data_start_offset()
        overlay = len(data) - overlay_off if overlay_off is not None else 0
        s("file_size", len(data))
        s("overlay_size", overlay)
        s("overlay_ratio", overlay / len(data))
        s("file_entropy", entropy(data))
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        s("has_rich_header", pe.parse_rich_header() is not None)

        res = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        n_res = 0
        has_version = False
        if res is not None:
            for rtype in res.entries:
                if rtype.id == 16:  # RT_VERSION
                    has_version = True
                n_res += len(getattr(getattr(rtype, "directory", None), "entries", []) or [])

        def dir_present(i: int) -> bool:
            return len(sec_dir) > i and sec_dir[i].Size > 0

        # Directory presence from pefile (data directory size > 0). LIEF versions
        # disagree on empty directories, so it is only used for the checks below.
        info = {
            "has_signature": dir_present(4),
            "has_resources": res is not None,
            "has_tls": dir_present(9),
            "has_debug": dir_present(6),
            "has_relocations": dir_present(5),
            "has_load_config": dir_present(10),
            "has_exceptions": dir_present(3),
        }
        info.update(self._lief_flags(data, path) or {})
        for key, value in info.items():
            s(key, bool(value))
        s("n_resources", n_res)
        s("has_version_info", has_version)

    @staticmethod
    def _lief_flags(data: bytes, path: Path | None) -> dict | None:
        if lief is None:
            return None
        try:
            binary = lief.PE.parse(str(path)) if path is not None else lief.PE.parse(list(data))
        except Exception:  # noqa: BLE001 - LIEF raises many types on malformed input
            return None
        if binary is None:
            return None

        def flag(attr: str) -> bool:
            return bool(getattr(binary, attr, False))

        # Parsed structures (an Authenticode blob, a resource tree, ...), which are
        # stricter than a non-empty data directory entry.
        return {
            "has_signature": flag("has_signatures"),
            "has_resources": flag("has_resources"),
            "has_tls": flag("has_tls"),
            "has_debug": flag("has_debug"),
        }

