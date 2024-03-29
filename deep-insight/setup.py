# SPDX-FileCopyrightText: Copyright 2021-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import os

from setuptools import setup

project_root = os.path.dirname(os.path.realpath(__file__))

setup(
    name="deepinsight-utility",
    version="0.0.1",
    packages=["deepinsight"],
    install_requires=[
        "ipaddress==1.0.23",
        "requests==2.24.0",
        "netaddr==0.8.0",
        "kubernetes==17.17.0",
    ],
    author="PDP Team",
    author_email="yi@opennetworking.org",
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
    ],
    description="The utility for DeepInsight",
    license="Apache-2.0",
    url="https://github.com/opennetworkinglab/sdfabric-utils/",
    scripts=[
        "di"
    ],
)
