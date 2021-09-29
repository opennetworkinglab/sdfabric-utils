# SPDX-FileCopyrightText: Copyright 2021-present Open Networking Foundation.
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

VENV ?= venv

$(VENV):
	python3 -m venv $(VENV)

format: $(VENV)
	source $(VENV)/bin/activate; pip install -r requirements.txt; \
	isort --sp linters/isort deepinsight; \
	black --config linters/black deepinsight; \
	isort --sp linters/isort di setup.py; \
	black --config linters/black di setup.py
