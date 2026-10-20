"""Pre-fill the reverse engineering case-study notes (FR-05) - run INSIDE the analysis VM.

    python scripts/case_study_prep.py                      # all samples in samples.csv
    python scripts/case_study_prep.py --only sample_02     # one sample

For each row of docs/re_case_study/samples.csv this writes docs/re_case_study/<id>.md with
the parts that can be collected statically and automatically:

* the model's view (`pemd scan`: p(malware), route, top features) from the latest raw run;
* PE facts: machine, .NET or native, sections (size, entropy, R/W/X), entry-point section,
  imports per DLL, API capability groups, TLS / signature / overlay / resources;
* notable strings (URLs, IPs, registry, shell commands, ...), defanged so nothing is clickable.

Sections 3-6 of the note are left for my own Ghidra analysis. Files are only parsed, never
executed. Existing notes are not overwritten unless --force is given.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

import pefile

from pemd.config import load_config
from pemd.features.api_categories import API_CATEGORIES, normalise_api
from pemd.features.extractor import entropy
from pemd.scanner import Scanner

NOTES = Path("docs/re_case_study")
STRING_PATTERNS = {
    "URL": rb"https?://[\x21-\x7e]{4,120}",
    "IP address": rb"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "Registry": rb"(?:HKEY_[A-Z_]+|SOFTWARE\\)[\x20-\x7e]{3,120}",
    "Shell / LOLBin": rb"(?:cmd\.exe|powershell|wscript|cscript|rundll32|regsvr32|schtasks)"
                      rb"[\x20-\x7e]{0,100}",
    "Crypto / ransom": rb"(?:bitcoin|monero|wallet|encrypt|decrypt|ransom)[\x20-\x7e]{0,80}",
    "File path": rb"[A-Za-z]:\\[\x20-\x7e]{3,100}",
}


def defang(s: str) -> str:
    s = re.sub(r"http(s?)://", r"hxxp\1://", s, flags=re.I)
    return re.sub(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", r"\1[.]\2[.]\3[.]\4", s).replace("|", "/")


def find_file(sha: str) -> Path | None:
    for p in (Path("data/raw/malware") / sha, Path("data/raw/benign") / f"{sha}.bin"):
        if p.exists():
            return p
    return None


def latest_run() -> Path:
    runs = sorted(p for p in Path("experiments").glob("*_raw") if (p / "gate.json").exists())
    if not runs:
        sys.exit("error: no raw-track run found in experiments/ (run `pemd ... --name raw` first)")
    return runs[-1]


def sections_table(pe: pefile.PE) -> list[str]:
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    rows = ["| Section | Raw size | Virtual size | Entropy | Flags | Entry point |",
            "|---|---|---|---|---|---|"]
    for s in pe.sections:
        c = s.Characteristics
        flags = ("R" if c & 0x40000000 else "-") + ("W" if c & 0x80000000 else "-") + \
                ("X" if c & 0x20000000 else "-")
        name = s.Name.rstrip(b"\x00").decode("latin-1") or "(empty)"
        rows.append(f"| `{name}` | {s.SizeOfRawData} | {s.Misc_VirtualSize} | "
                    f"{s.get_entropy():.2f} | {flags} | {'yes' if s.contains_rva(ep) else ''} |")
    return rows


def imports_block(pe: pefile.PE) -> tuple[list[str], dict[str, list[str]]]:
    lines, cats = [], {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = (entry.dll or b"").decode("latin-1")
        funcs = []
        for imp in entry.imports:
            name = imp.name.decode("latin-1") if imp.name else f"ord{imp.ordinal}"
            funcs.append(name)
            norm = normalise_api(name)
            for cat, members in API_CATEGORIES.items():
                if norm in members:
                    cats.setdefault(cat, []).append(name)
        shown = ", ".join(funcs[:25]) + (f", ... (+{len(funcs) - 25})" if len(funcs) > 25 else "")
        lines.append(f"- **{dll}** ({len(funcs)}): {shown}")
    return lines, cats


def strings_block(data: bytes, per_kind: int = 6) -> list[str]:
    out = []
    for kind, pat in STRING_PATTERNS.items():
        hits = []
        for m in re.finditer(pat, data):
            s = m.group(0).decode("latin-1", "replace").strip()
            if s not in hits:
                hits.append(s)
            if len(hits) >= per_kind:
                break
        if hits:
            out.append(f"- **{kind}:** " + "; ".join(f"`{defang(h)}`" for h in hits))
    return out or ["- (no notable strings in plain text; may be encrypted or packed)"]


def build_note(row: dict, path: Path, scanner: Scanner) -> str:
    data = path.read_bytes()
    res = scanner.scan_bytes(data, name=row["id"], top=10)
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories()
    oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER
    dirs = oh.DATA_DIRECTORY
    is_net = len(dirs) > 14 and dirs[14].Size > 0
    overlay = pe.get_overlay_data_start_offset()
    imp_lines, cats = imports_block(pe)
    machine = {0x14C: "x86 (32-bit)", 0x8664: "x64 (64-bit)"}.get(fh.Machine, hex(fh.Machine))

    feats = ["| Feature | Value | Contribution |", "|---|---|---|"]
    for f in res.get("influential_features", []):
        toks = f" ({', '.join(f['tokens'][:2])})" if f["tokens"] else ""
        feats.append(f"| `{f['feature']}`{toks} | {f['value']:.3g} | {f['contribution']:+.3f} |")
    source = ("MalwareBazaar (see data/raw/malwarebazaar_metadata.csv)" if row["label"] == "malware"
              else "Clean Windows 11 install (benign_manifest.csv)")

    lines = [
        f"# RE note: {row['id']}", "",
        "| Field | Value |", "|---|---|",
        f"| SHA-256 | `{row['sha256']}` |",
        f"| Label / family | {row['label']} / {row['family']} |",
        f"| Why chosen | {row['role']}: {row['why']} |",
        f"| Source and date obtained | {source} |",
        "| Analysed on (date, VM snapshot) | TODO: date, snapshot `dataset-ready` |",
        f"| Tools | Ghidra (version: TODO), pemd run `{scanner.run_dir.name}` |", "",
        "## 1. Static pipeline view (auto-filled)", "",
        f"- **p(malware) = {res.get('p_malware')}**, route **{res.get('route')}** "
        f"(gate: benign < {res.get('t_benign')}, malware >= {res.get('t_malware')}), "
        f"model `{res.get('model')}`",
        f"- Explanation method: {res.get('explanation_method')}", "", *feats, "",
        "## 2. Structure (auto-filled, then checked in Ghidra)", "",
        f"- Machine: {machine}; type: {'DLL' if pe.is_dll() else 'EXE'}; "
        f"**{'.NET assembly (CLR header present)' if is_net else 'native code'}**",
        f"- File size {len(data)} bytes, overall entropy {entropy(data):.2f}; overlay "
        f"{len(data) - overlay if overlay else 0} bytes",
        f"- TLS callbacks directory: {'yes' if dirs[9].Size else 'no'}; Authenticode signature: "
        f"{'yes' if dirs[4].Size else 'no'}; resources: {'yes' if dirs[2].Size else 'no'}", "",
        *sections_table(pe), "",
        "- Packed? TODO (entropy > 7.2, W+X section, few imports, entry point in last "
        "section?)", "",
        "### Imports", "", *(imp_lines or ["- (no import table)"]), "",
        "### API capability groups found (api_cat features)", "",
        *([f"- `{c}`: {', '.join(v[:8])}" for c, v in cats.items()] or
          ["- none in the import table (normal for small benign files; in malware this points "
           "to runtime API resolution, packing or .NET - check in Ghidra)"]), "",
        "### Notable strings (defanged)", "", *strings_block(data), "",
        "## 3. Behaviour indicated by code (Ghidra)", "",
        "| Capability | Evidence (function address, API, string) "
        "| Visible in static features? (which) |",
        "|---|---|---|", "| TODO | | |", "",
        "## 4. Feature decisions", "",
        "| Feature / pattern | Decision (retain / prioritise / discard) | Reason |",
        "|---|---|---|",
        "| TODO | | |", "",
        "## 5. Mutation resistance", "",
        "TODO: how could an attacker change this sample to evade each feature above, and what "
        "would it cost them in behaviour?", "",
        "## 6. Notes for the dissertation", "", "TODO", "",
    ]
    pe.close()
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--samples", default=str(NOTES / "samples.csv"))
    ap.add_argument("--run-dir", default=None, help="raw-track run (default: newest *_raw)")
    ap.add_argument("--only", default=None, help="one sample id, e.g. sample_02")
    ap.add_argument("--force", action="store_true", help="overwrite existing notes")
    args = ap.parse_args(argv)

    scanner = Scanner(args.run_dir or latest_run(), load_config())
    with open(args.samples, newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if not args.only or r["id"] == args.only]
    for row in rows:
        note = NOTES / f"{row['id']}.md"
        path = find_file(row["sha256"])
        if path is None:
            print(f"{row['id']}: file not found for {row['sha256'][:16]}")
            continue
        if note.exists() and not args.force:
            print(f"{row['id']}: {note} exists (use --force to overwrite)")
            continue
        note.write_text(build_note(row, path, scanner), encoding="utf-8")
        print(f"{row['id']}: wrote {note}  ({row['family']}, {row['role']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
