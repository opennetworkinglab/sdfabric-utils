# SPDX-FileCopyrightText: Copyright 2021-present Open Networking Foundation.
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

import json
import logging
import math
import time
from functools import partial, wraps

import requests

log = logging.getLogger("DeepInsightClient")
requests.packages.urllib3.disable_warnings()

URL_GET_TOKEN = "/auth/realms/deepinsight/protocol/openid-connect/token"
URL_LOGOUT = "/realms/deepinsight/protocol/openid-connect/logout"
URL_GET_FLOWS = "/api/v2/flows"
URL_UPLOAD_LICENSE = "/api/v2/licenseUpload"
URL_SWITCH_APCKET_DROP = "/api/v2/switch-packet-drops"
URL_SWITCH_LATENCIES = "/api/v2/switch-latencies"
URL_SWITCH_ANOMALIES = "/api/v2/switch-anomalies"
URL_ANOMALY_RECORDS = "/api/v2/anomaly-records"

URL_GET_TOPO = "/topology-server/v1/get-topologies"
URL_POST_TOPO = "/topology-server/v1/post-topology"


def di_api_error_handling(default_msg=[]):
    def decorate(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            resp = func(*args, **kwargs)
            if resp is None:
                return None
            msg = resp.json()
            # Replace null return with a default value like empty list.
            if msg is None and resp.text == "null":
                msg = default_msg
            if not resp.ok and "error" in msg:
                log.error("Got error message: {}".format(msg["error"]))
            return msg

        return wrapper

    return decorate


class DeepInsightClient:
    def __init__(
        self,
        server_url="https://127.0.0.1:3030",
        username="diadmin",
        password="diadmin",
        verify_ssl=False,
    ):
        self.server_url = server_url
        self.verify_ssl = verify_ssl
        # Get access token
        data = {
            "username": username,
            "password": password,
            "client_id": "deep-insight",
            "grant_type": ["password"],
            "code": "",
            "redirect_url": "",
        }
        resp = requests.post(
            url=self.server_url + URL_GET_TOKEN, data=data, verify=self.verify_ssl
        )
        token = resp.json()
        if "error" in token:
            raise RuntimeError("Failed to get access token: {}".format(token["error"]))
        self.access_token = token["access_token"]
        self.refresh_token = token["refresh_token"]
        self.request_auth_header = {
            "Authorization": "Bearer {}".format(self.access_token)
        }

        # Include access token and SSL verification to every GET/POST requests by default.
        for method in ["get", "post"]:
            setattr(
                self,
                method,
                partial(
                    getattr(requests, method),
                    headers=self.request_auth_header,
                    verify=verify_ssl,
                ),
            )

    def logout(self):
        data = {"client_id": "deep-insight", "refresh_token": self.refresh_token}
        requests.post(
            url=self.server_url + URL_LOGOUT, data=data, verify=self.verify_ssl
        )

    @di_api_error_handling()
    def upload_license_file(self, license_path):
        license_content = ""
        with open(license_path, "rb") as f:
            license_content = f.read()
        return self.post(
            self.server_url + URL_UPLOAD_LICENSE, files={"license": license_content}
        )

    @di_api_error_handling()
    def upload_topology_json(self, topo_json):
        resp = self.post(self.server_url + URL_POST_TOPO, json=topo_json)

        # Sometimes the server will return EOF message, usually we can solve this issue
        # by uploading again.
        if not resp.ok:
            error_msg = resp.json()["error"]
            if "EOF" in error_msg:
                resp = self.post(self.server_url + URL_POST_TOPO, json=topo_json)

        return resp

    def upload_topology_json_file(self, topology_json_path):
        with open(topology_json_path, "rb") as f:
            topo_json = json.load(f)
        return self.upload_topology_json(topo_json)

    @di_api_error_handling()
    def get_topology(self):
        return self.get(self.server_url + URL_GET_TOPO)

    @di_api_error_handling()
    def get_flows(
        self,
        start_time=None,
        end_time=None,
        max_results=100,
        src_ip=None,
        dst_ip=None,
        src_port=None,
        dst_port=None,
        ip_proto=None,
    ):

        # Use the current time as default end time and one second before as default begin time.
        if not end_time:
            end_time = math.floor(time.time() * 1000)
        if not start_time:
            start_time = end_time - 1000
        if start_time >= end_time:
            log.error("Start time should be less than end time")
            return None

        start_time = int(start_time)
        end_time = int(end_time)
        query_params = {
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": max_results,
        }

        if src_ip:
            query_params["SourceIP"] = src_ip
        if dst_ip:
            query_params["DestinationIP"] = dst_ip
        if src_port:
            query_params["SourcePort"] = src_port
        if dst_port:
            query_params["DestinationPort"] = dst_port
        if ip_proto:
            query_params["IPProtocol"] = ip_proto

        return self.get(self.server_url + URL_GET_FLOWS, params=query_params)

    @di_api_error_handling()
    def get_switch_packet_drop(
        self,
        switch_id,
        egress_port=0,
        queue_id=0,
        start_time=None,
        end_time=None,
        num_buckets=100,
    ):
        # Use the current time as default end time and one second before as default begin time.
        if not end_time:
            end_time = math.floor(time.time() * 1000)
        if not start_time:
            start_time = end_time - 1000
        if start_time >= end_time:
            log.error("Start time should be less than end time")
            return None

        start_time = int(start_time)
        end_time = int(end_time)
        query_params = {
            "StartTime": start_time,
            "EndTime": end_time,
            "StartTimeNano": start_time * 1000000,
            "EndTimeNano": end_time * 1000000,
            "NumBuckets": num_buckets,
            "SwitchID": switch_id,
            "EgressPort": egress_port,
            "QueueID": queue_id,
        }
        return self.get(self.server_url + URL_SWITCH_APCKET_DROP, params=query_params)

    @di_api_error_handling()
    def get_switch_anomalies(self, switch_id, start_time=None, end_time=None):
        # Use the current time as default end time and one second before as default begin time.
        if not end_time:
            end_time = math.floor(time.time() * 1000)
        if not start_time:
            start_time = end_time - 1000
        if start_time >= end_time:
            log.error("Start time should be less than end time")
            return None

        start_time = int(start_time)
        end_time = int(end_time)
        query_params = {
            "StartTime": start_time,
            "EndTime": end_time,
            "SwitchID": switch_id,
        }
        return self.get(self.server_url + URL_SWITCH_ANOMALIES, params=query_params)

    @di_api_error_handling()
    def get_switch_latencies(
        self,
        switch_id,
        start_time=None,
        end_time=None,
        granularity=1000,
    ):
        # Use the current time as default end time and one second before as default begin time.
        if not end_time:
            end_time = math.floor(time.time() * 1000)
        if not start_time:
            start_time = end_time - 1000
        if start_time >= end_time:
            log.error("Start time should be less than end time")
            return None

        start_time = int(start_time)
        end_time = int(end_time)
        query_params = {
            "StartTime": start_time,
            "EndTime": end_time,
            "SwitchID": switch_id,
            "Granularity": granularity,
        }
        return self.get(self.server_url + URL_SWITCH_LATENCIES, params=query_params)

    @di_api_error_handling()
    def get_anomaly_records(
        self,
        start_time=None,
        end_time=None,
        src_ip=None,
        dst_ip=None,
        src_port=None,
        dst_port=None,
        ip_proto=None,
        anomaly_type=None,
    ):
        # Use the current time as default end time and one second before as default begin time.
        if not end_time:
            end_time = math.floor(time.time() * 1000)
        if not start_time:
            start_time = end_time - 1000
        if start_time >= end_time:
            log.error("Start time should be less than end time")
            return None

        start_time = int(start_time)
        end_time = int(end_time)
        query_params = {
            "StartTime": start_time,
            "EndTime": end_time,
        }

        if src_ip:
            query_params["SourceIP"] = src_ip
        if dst_ip:
            query_params["DestinationIP"] = dst_ip
        if src_port:
            query_params["SourcePort"] = src_port
        if dst_port:
            query_params["DestinationPort"] = dst_port
        if ip_proto:
            query_params["IPProtocol"] = ip_proto
        if anomaly_type:
            query_params["AnomalyType"] = anomaly_type

        return self.get(self.server_url + URL_ANOMALY_RECORDS, params=query_params)
