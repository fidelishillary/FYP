# EMBER 2018 setup (tested)

The official `ember` package is old. It needs older library versions than this project, so it
gets its **own** virtual environment. Tested on Windows 11 with Python 3.11.

| Item | Value |
|---|---|
| Download | `https://ember.elastic.co/ember_dataset_2018_2.tar.bz2` (1.58 GB) |
| Disk needed | about 25 GB (archive + extracted jsonl + 9.5 GB of `.dat` files) |
| Location | outside OneDrive and with an English-only path, e.g. `C:\fyp-data` |
| Time | download ~10–30 min, extract ~10 min, vectorise 30–90 min |

## Steps (PowerShell)

```powershell
mkdir C:\fyp-data; cd C:\fyp-data
curl.exe -L -o ember_dataset_2018_2.tar.bz2 https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
tar -xjf ember_dataset_2018_2.tar.bz2          # -> C:\fyp-data\ember2018\*.jsonl

py -3.11 -m venv C:\fyp-data\.venv-ember
C:\fyp-data\.venv-ember\Scripts\Activate.ps1
pip install numpy==1.26.4 scikit-learn==1.1.3 lightgbm==4.5.0 lief==0.12.3 pandas tqdm `
    https://github.com/elastic/ember/archive/refs/heads/master.zip
python C:\fyp\FYP\scripts\vectorise_ember.py C:\fyp-data\ember2018
deactivate
```

Version notes (each one was found by testing):

- `scikit-learn==1.1.3`: newer versions reject how ember calls `FeatureHasher`
  ("Samples can not be a single string").
- `lightgbm`: `import ember` needs it even though we never train LightGBM.
- `scripts/vectorise_ember.py` restores the `np.int` aliases that ember's code still uses, and
  has the `if __name__ == "__main__"` guard that multiprocessing needs on Windows.
- The LIEF version warning ("computed using lief version 0.9.0") is expected and harmless for
  vectorising: the jsonl files already hold the raw features, so LIEF does not parse anything.

## Then, in the project environment

```powershell
cd C:\fyp\FYP; .venv\Scripts\Activate.ps1
pemd import-ember --ember-dir C:/fyp-data/ember2018 --balance 6000 --out data/processed/ember.npz
pemd run --dataset data/processed/ember.npz --name ember --cv
```
