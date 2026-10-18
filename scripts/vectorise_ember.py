"""Turn the downloaded EMBER 2018 jsonl files into the .dat files `pemd import-ember` reads.

Run this in its OWN virtual environment (see docs/ember_setup.md), not the project one:

    python scripts/vectorise_ember.py C:/fyp-data/ember2018

It writes X_train.dat, y_train.dat, X_test.dat, y_test.dat and metadata.csv into the
same folder (about 9.5 GB) and takes 30-90 minutes. No binaries are involved: the jsonl
files already contain EMBER's pre-extracted raw features.
"""

import sys
import warnings
from pathlib import Path

import numpy as np

# The ember package still uses aliases that NumPy removed (np.int, ...). Restoring them
# here keeps ember's own code unchanged.
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    for _alias, _type in (("int", int), ("float", float), ("bool", bool), ("object", object)):
        if not hasattr(np, _alias):
            setattr(np, _alias, _type)

import ember  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    d = Path(sys.argv[1])
    if not (d / "test_features.jsonl").exists():
        print(f"error: {d} does not contain test_features.jsonl - point at the extracted "
              "ember2018 folder")
        return 1
    folder = str(d).replace("\\", "/").rstrip("/") + "/"
    print("vectorising features (this is the slow part) ...")
    ember.create_vectorized_features(folder, feature_version=2)
    print("writing metadata.csv ...")
    ember.create_metadata(folder)
    for name in ("X_train.dat", "y_train.dat", "X_test.dat", "y_test.dat", "metadata.csv"):
        p = d / name
        print(f"  {name:14s} {p.stat().st_size / 1e9:6.2f} GB" if p.exists() else
              f"  {name:14s} MISSING")
    print("done - next: pemd import-ember --ember-dir", d, "--balance 6000 "
          "--out data/processed/ember.npz")
    return 0


if __name__ == "__main__":  # required on Windows: ember uses multiprocessing
    sys.exit(main())
