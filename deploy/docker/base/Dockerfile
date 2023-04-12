##
##  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
FROM python:3.8.12-slim

RUN pip3 install --upgrade pip

ADD deploy/docker/base/requirements.txt base/requirements.txt
RUN pip3 install -r base/requirements.txt
