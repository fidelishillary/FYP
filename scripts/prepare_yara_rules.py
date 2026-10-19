"""Build the published YARA rule set for the signature baseline (FR-09, RQ4).

    git clone https://github.com/Yara-Rules/rules.git ~/yara-rules     # while the VM has NAT
    python scripts/prepare_yara_rules.py ~/yara-rules/malware

Copies every rule file that compiles on its own with yara-python into rules/yara_published/
(git-ignored: check the rule set's licence before committing it) and writes SOURCE.md there
with the repository URL, commit and commit date, which the dissertation must report. Rules
needing modules or external variables that yara-python lacks are skipped and listed.
Then run with configs/raw_track.yaml, which points the baseline at rules/yara_published.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path


def git_info(path: Path) -> tuple[str, str, str]:
    def run(*cmd):
        try:
            return subprocess.check_output(["git", "-C", str(path), *cmd], text=True,
                                           stderr=subprocess.DEVNULL).strip()
        except (OSError, subprocess.CalledProcessError):
            return "unknown"

    return (run("config", "--get", "remote.origin.url"), run("rev-parse", "HEAD"),
            run("log", "-1", "--format=%cs"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", help="folder of .yar/.yara files (searched recursively)")
    ap.add_argument("--out", default="rules/yara_published")
    args = ap.parse_args(argv)
    import yara

    src, out = Path(args.source).expanduser(), Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    files = sorted([*src.rglob("*.yar"), *src.rglob("*.yara")])
    kept, skipped = [], []
    for i, f in enumerate(files):
        if "index" in f.name.lower():  # index files only include other files
            continue
        try:
            yara.compile(filepath=str(f))
        except yara.Error as exc:
            skipped.append((f, str(exc).splitlines()[0][:100]))
            continue
        dest = out / f"{i:04d}_{f.name}"
        shutil.copyfile(f, dest)
        kept.append(f)
    try:  # the whole set must also compile together (duplicate rule names, ...)
        yara.compile(filepaths={f"r{i}": str(p) for i, p in enumerate(sorted(out.iterdir()))})
    except yara.Error as exc:
        print(f"warning: combined compile failed: {exc}")

    url, commit, cdate = git_info(src)
    lines = [
        "# Published YARA rule set used for the signature baseline (FR-09)", "",
        f"- Source: {url} (folder `{src.name}`)", f"- Commit: `{commit}` dated {cdate}",
        f"- Prepared: {date.today().isoformat()}",
        f"- Rule files kept: {len(kept)}; skipped (did not compile alone): {len(skipped)}", "",
        "Report the commit date in the dissertation: a fair baseline uses rules published "
        "before the test samples.", "", "## Skipped files", "",
    ] + [f"- `{f.relative_to(src)}`: {why}" for f, why in skipped]
    (out / "SOURCE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"kept {len(kept)} rule files, skipped {len(skipped)} -> {out} (see SOURCE.md)")
    return 0 if kept else 1


if __name__ == "__main__":
    sys.exit(main())
