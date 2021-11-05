##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
from centos:7 as f7t-base

# install epel repo for python-pip package
RUN yum install -y epel-release
RUN yum -y update
RUN yum install -y python3-pip

RUN pip3 install --upgrade pip

ADD deploy/docker/base/requirements.txt base/requirements.txt
RUN pip3 install -r base/requirements.txt
