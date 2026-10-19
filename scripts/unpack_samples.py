"""Extract MalwareBazaar zips into data/raw/malware/ - ONLY inside the isolated VM (NFR-01).

    python scripts/unpack_samples.py

Safety checks before anything is extracted:
* refuses to run if the machine can reach the internet (the VM must be host-only);
* refuses to run on Windows (samples are only unpacked in the Ubuntu analysis VM).

Each sample is written as data/raw/malware/<sha256> (no extension, read-only, not
executable) after its SHA-256 is verified. data/raw/first_seen.csv is written from the
download metadata so `pemd extract --dates` can use it (FR-13).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import socket
import stat
import sys
from pathlib import Path

PASSWORD = b"infected"
PROBES = [("1.1.1.1", 53), ("8.8.8.8", 53), ("9.9.9.9", 443)]


def internet_reachable(timeout: float = 3.0) -> bool:
    for host, port in PROBES:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def open_zip(path: Path):
    try:
        import pyzipper  # AES zips (MalwareBazaar uses AES-128)

        return pyzipper.AESZipFile(path)
    except ImportError:  # pragma: no cover
        sys.exit("error: pip install pyzipper (MalwareBazaar zips are AES-encrypted)")


def unpack(zip_path: Path, out_dir: Path) -> tuple[str, str]:
    """Returns (sha256, status)."""
    expected = zip_path.stem.lower()
    target = out_dir / expected
    if target.exists():
        return expected, "exists"
    with open_zip(zip_path) as zf:
        zf.setpassword(PASSWORD)
        members = [m for m in zf.infolist() if not m.is_dir()]
        if len(members) != 1:
            return expected, f"unexpected archive layout ({len(members)} files)"
        data = zf.read(members[0])
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        return expected, f"hash mismatch ({digest[:12]})"
    target.write_bytes(data)
    os.chmod(target, stat.S_IRUSR | stat.S_IRGRP)  # read-only, never executable
    return expected, "ok"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zips", default="data/raw/malware_zips")
    ap.add_argument("--out", default="data/raw/malware")
    ap.add_argument("--metadata", default="data/raw/malwarebazaar_metadata.csv")
    ap.add_argument("--dates-out", default="data/raw/first_seen.csv")
    ap.add_argument("--skip-network-check", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    if os.name == "nt":
        print("error: unpack samples only inside the Ubuntu analysis VM, never on Windows",
              file=sys.stderr)
        return 2
    if not args.skip_network_check and internet_reachable():
        print("error: this machine can reach the internet. Switch the VM network adapter to "
              "Host-only, take the 'clean-isolated' snapshot, then run this again.",
              file=sys.stderr)
        return 2

    zips = sorted(Path(args.zips).glob("*.zip"))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for z in zips:
        _, status = unpack(z, out)
        key = status.split(" (")[0]
        counts[key] = counts.get(key, 0) + 1
        if status not in ("ok", "exists"):
            print(f"{z.name}: {status}")
    print(f"{len(zips)} zips: {counts}")

    meta = Path(args.metadata)
    if meta.exists():
        with open(meta, newline="", encoding="utf-8") as fh:
            rows = [r for r in csv.DictReader(fh) if (out / r["sha256"]).exists()]
        with open(args.dates_out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["sha256", "first_seen"])
            w.writerows((r["sha256"], r["first_seen"]) for r in rows)
        print(f"wrote {args.dates_out} ({len(rows)} dated samples)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
