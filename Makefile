SHELL := /bin/sh

GREEN='[\033[0;32m'
YELLOW='[\033[1;33m'
END='\033[0m]'	# No Color
DONE="$(GREEN)DONE$(END)"
PROGRESS="$(YELLOW)....$(END)"

.PHONY: test model
bt-y2j:
	@cat bt.yaml | \yq > bt.json

check:
	@python check.py -i catalog/bt.yaml


analyze: check
	@python analyze.py

inalyze: check
	@ipython -i analyze.py

test:
	@pytest

test-analyze:
	@pytest analyze_test.py

test-parse:
	@pytest parse_test.py

test-check:
	@pytest check_test.py

model:
	@echo "Generating Threat Model"
	@cd visualization && jekyll build && cd ..
	@echo "$(DONE) Model generated, open visualization/_site/index.html"

setup: requirements.txt
	@echo "$(PROGRESS) Installing requirements"
	@pip install -r requirements.txt
	@echo "$(DONE) Installed requirements"

dev-setup: setup requirements-dev.txt
	@echo "$(PROGRESS) Installing development requirements"
	@pip install -r requirements-dev.txt
	@pre-commit install
	@echo "$(DONE) Installed development requirements"

cloc:
	@tokei .

clean:
	@ rm -rf *.gv *.pdf .pytest_cache *__pycache__*
