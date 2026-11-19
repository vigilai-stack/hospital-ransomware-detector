.PHONY: install demo test backup-check

install:
	python3 -m pip install -e ".[dev]"

demo:
	vigil-detect demo

backup-check:
	vigil-detect check-backup

test:
	python3 -m pytest -q
