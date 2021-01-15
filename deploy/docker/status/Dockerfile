##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
FROM centos:7

# install epel repo for python-pip package
RUN yum install -y epel-release
# update yum
RUN yum -y update

# install python-pip from repo
# this install also python 3.6
RUN yum install -y python3-pip
# RUN yum remove -y cyrus-sasl-gssapi python-gssapi

# upgrade
RUN pip3 install --upgrade pip

RUN pip3 install Flask paramiko cryptography pyjwt requests

ADD src/status/status.py status.py
ADD src/common/cscs_api_common.py cscs_api_common.py

ENTRYPOINT ["python3"]
CMD ["status.py"]

