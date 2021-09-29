<!--
SPDX-FileCopyrightText: Copyright 2021-present Open Networking Foundation.
SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
-->

# DeepInsight Utility

The utility for Intel/Barefoot DeepInsight.

## Install the utility

Install from local source

```bash
python3 setup.py install
```

Or install with `pip3` command

```bash
pip3 install git+ssh://git@github.com/opennetworkinglab/sdfabric-utils.git#subdirectory=deep-insight
```

## Usage

```sh
usage: di [-h] [--server-addr SERVER_ADDR] [-s] [-u USERNAME] [-p PASSWORD]
          {upload-license,upload-topology,get-flows,get-switch-packet-drop,get-switch-anomalies,get-switch-latencies,get-anomaly-records,gen-topology}
          ...

positional arguments:
  {upload-license,upload-topology,get-flows,get-switch-packet-drop,get-switch-anomalies,get-switch-latencies,get-anomaly-records,gen-topology}
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
    get-anomaly-records
                        Get anomaly records
    gen-topology        Generate topology json file

optional arguments:
  -h, --help            show this help message and exit
  --server-addr SERVER_ADDR
                        DeepInsight API address (default: 127.0.0.1:3030)
  -s, --secure          Verify SSL certificate (default: False)
  -u USERNAME, --username USERNAME
                        DeepInsight username (default: diadmin)
  -p PASSWORD, --password PASSWORD
                        DeepInsight password (default: diadmin)
```

## Auto-generate topology from ONOS and upload to DeepInsight

You can use the subcommand `gen-topology` to generate a topology file from a running ONOS instance.

The subcommand uses the ONOS REST API to fetch the required information:

```bash
./di gen-topology -s localhost:8181 -u karaf -p karaf -o topo.json
```

### Auto-generate topology with end-host INT

If you use end-host INT support for the Kubernetes CNI, you can generate the DeepInsight topology file by
using `--k8s-subnet` and `--node-iface-no` argument.

The subcommand will use both ONOS and Kubernetes API to build the topology file if `--k8s-subnet` parameter is present.

```bash
./di gen-topology -s localhost:8181 -u karaf -p karaf -o topo.json --k8s-subnet 192.168.99.0/24 --node-iface-no 3 [--k8s-config ~/.kube/config]
```

Note that `--k8s-config` is optional, by default the script will use the default config file (`~/.kube/config`).

### Upload the topology to DeepInsight

To upload the topology file to the DeepInsight. Use `upload-topology` subcommand:

```bash
./di upload-topology topo.json
```
