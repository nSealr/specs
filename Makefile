.PHONY: setup test lint audit docs ci

setup:
	python3 -m pip install --disable-pip-version-check --user -r requirements.txt

test:
	python3 scripts/verify_repo.py
	python3 scripts/verify_specs.py
	python3 -m unittest discover -s tests

lint:
	python3 scripts/verify_repo.py
	python3 scripts/verify_specs.py

audit:
	python3 scripts/verify_repo.py
	python3 scripts/verify_specs.py

docs:
	python3 scripts/verify_repo.py
	python3 scripts/verify_specs.py

ci: setup test lint audit docs
