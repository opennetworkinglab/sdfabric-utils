# SPDX-FileCopyrightText: Copyright 2021-present Open Networking Foundation.
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

VENV ?= venv
IMAGE_NAME = registry.opennetworking.org/deepinsight/utility:4.2.0-ONF

$(VENV):
	python3 -m venv $(VENV)

format: $(VENV)
	source $(VENV)/bin/activate; pip install -r requirements.txt; \
	isort --sp linters/isort deepinsight; \
	black --config linters/black deepinsight; \
	isort --sp linters/isort di topo_watchdog setup.py; \
	black --config linters/black di topo_watchdog setup.py

build-image:
	docker build -t $(IMAGE_NAME) .

push-image:
	docker push $(IMAGE_NAME)
