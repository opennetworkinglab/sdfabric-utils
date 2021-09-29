# SPDX-FileCopyrightText: Copyright 2021-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

VENV ?= venv
DI_URL ?= https://127.0.0.1:3030
DI_USER ?= diadmin
DI_PASS ?= diadmin
ONOS_ADDR ?= 127.0.0.1:8181
ONOS_USER ?= onos
ONOS_PASS ?= rocks
TOPO_JSON ?= topo.json
K8S_SUBNET ?= 10.0.0.0/16
NODE_IFACE_NO ?= 0
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
