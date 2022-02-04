# SPDX-FileCopyrightText: Copyright 2021-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import ipaddress
import logging
import re
from collections import Counter, defaultdict

import kubernetes as k8s
import requests
from netaddr import IPAddress

log = logging.getLogger("DeepInsightTopoUtility")

INT_HOST_REPORTER_TOPO_API="http://{}:4048/api/v1/topology"

PORT_MAPPINGS = {}

def parse_port_id(port_string):
    # Port string can be "[port/channel](id)" or just "id".
    # Only return the ID of port.
    match = re.match(r"\[([0-9]+/[0-9]+)\]\(([0-9]+)\)", port_string)
    if not match:
        return int(port_string)
    else:
        return int(match.group(2))

def parse_port_name(port_string):
    # Port string can be "[port/channel](id)" or just "id".
    # Return the "port/channel" string, if exists.
    # Otherwise, return the ID of port.
    match = re.match(r"\[([0-9]+/[0-9]+)\]\(([0-9]+)\)", port_string)
    if not match:
        return port_string
    elif match.group(1):
        return match.group(1)
    else:
        return match.group(2)


def gen_topo(
    onos_url="http://localhost:8181/onos/v1",
    onos_user="onos",
    onos_pass="rocks",
    with_end_host=False,
    k8s_clusters=[],
):
    """
    Generate topology based on ONOS and K8s cluster topology.

    :param onos_url: The ONOS URL, default is http://localhost:8181/onos/v1
    :param onos_user: The ONOS user, default is onos
    :param onos_pass: The ONOS password, default is rocks
    :param with_end_host: Include end hosts(k8s nodes), default is False
    :param k8s_clusters: [For end host] The list of K8s cluster info, default is empty
    """
    log.info(
        "Using ONOS REST APIs at %s (user:%s, password:%s)",
        onos_url,
        onos_user,
        onos_pass,
    )
    auth = requests.auth.HTTPBasicAuth(onos_user, onos_pass)

    netcfg = requests.get(onos_url + "/network/configuration", auth=auth)
    if not netcfg.ok:
        log.fatal("Unable to retrieve netcfg\n%s", netcfg.text)
    netcfg = netcfg.json()

    topo = {"switches": [], "links": [], "subnets": [], "hosts": []}

    for key, value in netcfg["devices"].items():
        topo["switches"].append(
            {
                "switchId": value["segmentrouting"]["ipv4NodeSid"],
                "name": key,
                "deviceType": "legacy",
                "ip": value["segmentrouting"]["ipv4Loopback"],
            }
        )

    devices = requests.get(onos_url + "/devices", auth=auth)
    if not devices.ok:
        log.fatal("Unable to retrieve devices\n%s", devices.text)
    devices = devices.json()["devices"]
    for device in devices:
        device_ports = requests.get(onos_url + "/devices/" + device['id'] + "/ports", auth=auth)
        if not device_ports.ok:
            log.fatal("Unable to retrieve ports of device\n%s", device_ports.text)
        for elem in device_ports.json()['ports']:
            port_name = parse_port_name(elem['port'])
            port_id = parse_port_id(elem['port'])
            if not device['id'] in PORT_MAPPINGS:
                PORT_MAPPINGS[device['id']] = {}
            PORT_MAPPINGS[device['id']][port_id] = port_name

    print(PORT_MAPPINGS)

    subnets = defaultdict(lambda: {})
    for key, value in netcfg["ports"].items():
        if "interfaces" not in value:
            continue

        ifaces = value["interfaces"]
        for iface in ifaces:
            for ip in iface["ips"]:
                ip = ipaddress.ip_interface(ip)
                subnets[str(ip.network)][key] = True

    subnet_id = 1
    for subnet, ports in subnets.items():
        topo["subnets"].append(
            {"ip_subnet": subnet, "name": subnet, "subnet_id": subnet_id}
        )
        for port in ports:
            switch_id, port_num = port.split("/")
            topo["links"].append(
                {
                    "node1": switch_id,
                    "port1": PORT_MAPPINGS[switch_id][int(port_num)],
                    "node2": subnet,
                    "port2": "-1",
                    "switchPort1": int(port_num),
                }
            )
        subnet_id = subnet_id + 1

    hosts = requests.get(onos_url + "/hosts", auth=auth)
    if not hosts.ok:
        log.fatal("Unable to retrieve hosts\n%s", hosts.text)
    hosts = hosts.json()["hosts"]

    # A dictionary stores mapping from host IP to locations.
    # Later we will use this dictionary to find the location of next hop for each routes.
    host_ip_to_locations = {}
    # Host names in ONOS are not unique, in case of duplicates, append count
    # suffix (e.h., myhost_1, myhost_2). Similarly, we use different names for hosts with
    # multiple IP addresses.
    name_ctr = Counter()
    for host in hosts:
        try:
            name = host["annotations"]["name"]
        except KeyError:
            name = host["id"]
        for ip in host["ipAddresses"]:
            name_ctr.update([name])
            unique_name = "%s_%s" % (name, name_ctr[name])
            topo["hosts"].append(
                {
                    "ip": ip,
                    "name": unique_name,
                }
            )
            for location in host["locations"]:
                port_num = parse_port_id(location["port"])
                topo["links"].append(
                    {
                        "node1": location["elementId"],
                        "port1": PORT_MAPPINGS[location["elementId"]][int(port_num)],
                        "node2": unique_name,
                        "port2": "-1",
                        "switchPort1": port_num,
                    }
                )
            host_ip_to_locations[ip] = host["locations"]

    links = requests.get(onos_url + "/links", auth=auth)
    if not links.ok:
        log.fatal("Unable to retrieve hosts\n%s", links.text)
    links = links.json()["links"]

    for app, value in netcfg["apps"].items():
        if app == "org.omecproject.up4":
            if "up4" not in value:
                continue
            up4 = value["up4"]
            if "devices" in up4:
                up4_switch_ids = up4["devices"]
            else:
                # TODO: For backward compatibility
                # remove this when we are no longer need it.
                up4_switch_ids = [up4["deviceId"]]
            s1uaddr = up4["s1uAddr"]
            s1uaddr = ipaddress.ip_address(s1uaddr)
            uepools = set([str(ipaddress.ip_network(n)) for n in up4["uePools"]])
            for uepool in uepools:
                topo["subnets"].append(
                    {"ip_subnet": uepool, "name": uepool, "subnet_id": subnet_id}
                )
                subnet_id = subnet_id + 1
            subnets_with_ue = []
            for s in subnets:
                if s1uaddr in ipaddress.ip_network(s):
                    subnets_with_ue.append(s)
            if len(subnets_with_ue) == 0:
                log.warning("Unable to map UP4 S1U address to switch port: %s", s1uaddr)
                continue
            for s in subnets_with_ue:
                for port in subnets[s]:
                    switch_id, port_num = port.split("/")
                    if switch_id in up4_switch_ids:
                        for uepool in uepools:
                            topo["links"].append(
                                {
                                    "node1": switch_id,
                                    "port1": PORT_MAPPINGS[switch_id][int(port_num)],
                                    "node2": uepool,
                                    "port2": "-1",
                                    "switchPort1": int(port_num),
                                }
                            )
        elif app == "org.onosproject.route-service":
            if "routes" not in value:
                continue
            for route in value["routes"]:
                if "prefix" not in route or "nextHop" not in route:
                    continue
                prefix = route["prefix"]
                next_hop = route["nextHop"]
                topo["subnets"].append(
                    {"ip_subnet": prefix, "name": prefix, "subnet_id": subnet_id}
                )
                subnet_id = subnet_id + 1
                route_locations = host_ip_to_locations.get(next_hop, [])
                for route_location in route_locations:
                    port_num = parse_port_id(route_location["port"])
                    topo["links"].append(
                        {
                            "node1": route_location["elementId"],
                            "port1": PORT_MAPPINGS[route_location["elementId"]][int(port_num)],
                            "node2": prefix,
                            "port2": "-1",
                            "switchPort1": port_num,
                        }
                    )

    # ONOS returns an entry for each direction of a bidirectional link, but
    # DeepInsight expects only one entry for both directions.
    bidi_links = {}
    for link in links:
        key = [str(link["src"]), str(link["dst"])]
        key.sort()
        key = tuple(key)
        port1_num = parse_port_id(link["src"]["port"])
        port2_num = parse_port_id(link["dst"]["port"])
        bidi_links[key] = {
            "node1": link["src"]["device"],
            "port1": PORT_MAPPINGS[link["src"]["device"]][int(port1_num)],
            "node2": link["dst"]["device"],
            "port2": PORT_MAPPINGS[link["dst"]["device"]][int(port2_num)],
            "switchPort1": port1_num,
            "switchPort2": port2_num,
        }
    topo["links"].extend(bidi_links.values())

    if not with_end_host:
        return topo

    # End hosts topology config
    for idx, cluster in enumerate(k8s_clusters):
        if not 'subnet' in cluster:
            log.error("Missing 'subnet' in K8s cluster info [argument index=%d]: %s, skipping to add K8s cluster to topology file.", idx, cluster)
            continue
        k8s_config = cluster['config'] if 'config' in cluster else None
        k8s_cluster_subnet = cluster['subnet']

        k8s.config.load_kube_config(config_file=k8s_config)
        k8s_node_ips = []
        for node in k8s.client.CoreV1Api().list_node().items:
            k8s_node_ips += [
                item.address for item in node.status.addresses if item.type == "InternalIP"
            ]

        for subnet in topo["subnets"]:
            if subnet["ip_subnet"] == k8s_cluster_subnet:
                k8s_subnet = subnet
                subnet_id = subnet["subnet_id"]
                break
        else:
            k8s_subnet = {
                "name": k8s_cluster_subnet,
                "ip_subnet": k8s_cluster_subnet,
                "subnet_id": subnet_id,
            }
            subnet_id += 1

        k8s_node_cidrs = []
        ipam_blocks = k8s.client.CustomObjectsApi().list_cluster_custom_object(
            group="crd.projectcalico.org", version="v1", plural="ipamblocks"
        )
        for item in ipam_blocks["items"]:
            cidr = item["spec"]["cidr"]
            k8s_node_cidrs.append(
                {"name": str(cidr), "ip_subnet": str(cidr), "subnet_id": subnet_id}
            )
            subnet_id += 1


        vswitch_links = dict()
        vswitches = []
        for node_id, node_ip in enumerate(k8s_node_ips):
            url = INT_HOST_REPORTER_TOPO_API.format(node_ip)
            host_topology = requests.get(url)
            if not host_topology.ok:
                log.fatal("Unable to access Topology API from K8s node %s\n%s", node_ip, host_topology.text)

            for link in host_topology.json()["links"]:
                if link["is-node-iface"]:
                    node_iface = link["id"]
                    vswitch_ip = link["ip-addresses"][0]

            hostname = [host["name"] for host in topo["hosts"] if host["ip"] == vswitch_ip]
            hostname = hostname[0] if len(hostname) != 0 else ""

            name = "device:vswitch" + str(node_id)
            vswitches.append(
                {
                    "name": name,
                    "ip": vswitch_ip,
                    "default-intf": str(node_iface),
                    "deviceType": "legacy",
                    "switchId": int(IPAddress(node_ip)),
                    "hostname": hostname,
                }
            )
            vswitch_links[name] = host_topology.json()["links"]
        topo['switches'].extend(vswitches)

        all_host_subnets = k8s_node_cidrs + [k8s_subnet]

        # Overrides links in the topology config.
        # Connects the physical switch to the host vswitch
        for link in topo["links"]:
            for sw in vswitches:
                # find IP of an attached host
                host_ip = [host["ip"] for host in topo["hosts"] if host["name"] == link["node2"]]
                host_ip = host_ip[0] if len(host_ip) != 0 else ""
                if host_ip == sw["ip"]:
                    link["port2"] = sw["default-intf"]
                    link["node2"] = sw["name"]
                    link["switchPort2"] = int(sw["default-intf"])

        # Connect vswitch to all possible subnets with all possible ports.
        for sw in vswitches:
            for host_subnet in all_host_subnets:
                for link in vswitch_links[sw["name"]]:
                    if link["is-node-iface"]:
                        # skip data interfaces
                        continue
                    topo["links"].append(
                        {
                            "node1": sw["name"],
                            "node2": host_subnet["name"],
                            "port1": str(link["id"]),
                            "port2": "-1",
                            "switchPort1": int(link["id"]),
                        }
                    )

        # Overrides subnets in the topology config.
        if k8s_subnet not in topo["subnets"]:
            topo["subnets"].append(k8s_subnet)
        topo["subnets"] += k8s_node_cidrs

    return topo
