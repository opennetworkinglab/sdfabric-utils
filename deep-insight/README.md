<!--
SPDX-FileCopyrightText: Copyright 2021-present Open Networking Foundation.
SPDX-License-Identifier: Apache-2.0
-->

# DeepInsight Utility

The utility for Intel/Barefoot DeepInsight.

## Install the utility

Install the utility from local source

```bash
python3 setup.py install
```

Or install the utility with `pip3` command

```bash
pip3 install git+ssh://git@github.com/opennetworkinglab/sdfabric-utils.git#subdirectory=deep-insight
```

## Usage

```sh
usage: di [-h] [--server-url SERVER_URL] [-s] [-u USERNAME] [-p PASSWORD] {upload-license,upload-topology,get-flows,get-switch-packet-drop,get-switch-anomalies,get-switch-latencies,gen-topology} ...

positional arguments:
  {upload-license,upload-topology,get-flows,get-switch-packet-drop,get-switch-anomalies,get-switch-latencies,gen-topology}
                        The command
    upload-license      Upload license file
    upload-topology     Upload topology json file
    get-flows           Get flows
    get-switch-packet-drop
                        Get packet drop from a switch
    get-switch-anomalies
                        Get anomalies from a switch
    get-switch-latencies
                        Get latencies from a switch
    gen-topology        Generate topology json file

optional arguments:
  -h, --help            show this help message and exit
  --server-url SERVER_URL
                        DeepInsight server URL (default: https://127.0.0.1:3030)
  -s, --secure          Verify SSL certificate (default: False)
  -u USERNAME, --username USERNAME
                        username (default: diadmin)
  -p PASSWORD, --password PASSWORD
                        password (default: diadmin)
```

## Auto-generate topology from ONOS and upload to DI

If using TOST (Trellis+ONOS+Stratum+Tofino), you can use the subcommand
`gen-topology` to automatically generate a topology file from a running ONOS instance.

The subcommand uses the ONOS REST API to fetch the required information:

```bash
./di gen-topology -s localhost:8181 -u karaf -p karaf -o topo.json
```

### Auto-generate topology for end-host INT

If you use end-host INT support for the Kubernetes CNI, you can generate the DI topology file by
using `--k8s-subnet` and `--node-iface-no` argument.

The subcommand will use both ONOS and Kubernetes API to build the topology file if `--k8s-subnet` parameter is present.

```bash
./di gen-topology -s localhost:8181 -u karaf -p karaf -o topo.json --k8s-subnet 192.168.99.0/24 --node-iface-no 3 [--k8s-config ~/.kube/config]
```

Note that `--k8s-config` is optional, by default the script will use the default config file (`~/.kube/config`).

### Upload the topology to DeepInsight

To upload the topology file to the DI. Use `upload-topology` subcommand:

```bash
./di upload-topology topo.json
```
