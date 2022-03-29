##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
ARG BASE_IMAGE=centos:7
from $BASE_IMAGE

RUN yum install -y epel-release
RUN yum -y update
RUN yum install -y python3-pip

RUN pip3 install --upgrade pip

ADD deploy/docker/base/requirements.txt base/requirements.txt
ADD deploy/docker/certificator/requirements.txt deps/requirements.txt
RUN pip3 install -r base/requirements.txt
RUN pip3 install -r deps/requirements.txt

RUN yum install -y openssh-7.4p1

ADD src/certificator/certificator.py certificator.py

ENTRYPOINT ["python3"]
CMD ["certificator.py"]
