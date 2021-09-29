# SPDX-FileCopyrightText: Copyright 2021-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

FROM python:3.9 as builder
ADD . /tmp/di-utils
RUN mkdir /output
RUN pip install --root /output /tmp/di-utils

FROM python:3.9
COPY --from=builder /output /
ENTRYPOINT ["bash"]
CMD []
