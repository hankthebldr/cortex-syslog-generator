# Makefile for cortex-syslog-generator

PYTHON := python3
PIP := $(VENV)/bin/pip
VENVBIN := .venv/bin
VENV := .venv

.DEFAULT_GOAL := help

## Create virtual environment (.venv)
venv: $(VENV)/bin/activate
$(VENV)/bin/activate: requirements.txt
	$(PYTHON) -m venv $(VENV)
	$(VENVBIN)/python -m pip install --upgrade pip
	$(VENVBIN)/pip install -r requirements.txt
	@echo "source $(VENVBIN)/activate" > .activate
	@echo "Run: source .activate"

## Install/upgrade dependencies into venv
install: venv
	$(VENVBIN)/pip install -r requirements.txt

## Run Flask app (GUI) on localhost:5001
run: venv
	$(VENVBIN)/python app.py

## Run demo script (interactive)
demo: venv
	$(VENVBIN)/python demo_xgen.py

## Format code (black + ruff)
format: venv
	$(VENVBIN)/black .
	$(VENVBIN)/ruff check . --fix

## Run tests
pytest: venv
	$(VENVBIN)/pytest -q

## Clean caches and build artifacts
clean:
	rm -rf __pycache__ .pytest_cache build dist *.egg-info htmlcov .coverage

## Show help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## ' Makefile | sed 's/:.*## /\t- /'
