# data/

Everything in this folder except this README is **git-ignored**. Never commit samples (NFR-01, NFR-08).

| Folder | Contents | Where |
|---|---|---|
| `raw/malware/`, `raw/benign/` | Raw PE files for `pemd extract` | **Analysis VM only** |
| `raw/first_seen.csv` | Optional `sha256,first_seen` for the time-based split | VM |
| `external/` | Downloaded datasets, e.g. vectorised EMBER 2018 (`X_train.dat`, `y_train.dat`, `metadata.csv`, ...) | Anywhere (feature vectors only) |
| `processed/` | `*.npz` feature datasets produced by `pemd` and `*.rejected.csv` logs | Anywhere |

EMBER: download the 2018 release from the EMBER project, then create the vectorised `.dat` files with the official `ember` package (`ember.create_vectorized_features` and `ember.create_metadata`).
