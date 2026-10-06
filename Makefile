.PHONY: install test lint features ember run clean

PY ?= python

install:
	$(PY) -m pip install -r requirements.txt
	$(PY) -m pip install -e .

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check .

features:
	pemd features

# EMBER track (no binaries needed). Set EMBER_DIR to the vectorised EMBER folder.
EMBER_DIR ?= data/external/ember2018
ember:
	pemd import-ember --ember-dir $(EMBER_DIR) --balance 6000 --out data/processed/ember.npz
	pemd run --dataset data/processed/ember.npz --name ember --cv

# Raw track - run inside the isolated analysis VM only (NFR-01).
run:
	pemd extract --balance 6000
	pemd run --name raw --cv

clean:
	rm -rf .pytest_cache .ruff_cache build dist src/*.egg-info
