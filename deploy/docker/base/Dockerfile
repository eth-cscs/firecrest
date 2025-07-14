##
##  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
FROM python:3.13-alpine

LABEL org.opencontainers.image.source=https://github.com/eth-cscs/firecrest

ADD deploy/docker/base/requirements.txt base/requirements.txt
RUN pip3 install --upgrade pip && pip3 install -r base/requirements.txt
