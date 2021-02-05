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
RUN yum install -y python3-3.6.8 python3-pip-9.0.3

# upgrade
RUN pip3 install --upgrade pip==21.0.1

RUN pip3 install cryptography==3.1.1 Flask==1.1.2 paramiko==2.6.0 pyjwt==1.7.1 requests==2.24.0

ADD src/status/status.py status.py
ADD src/common/cscs_api_common.py cscs_api_common.py

ENTRYPOINT ["python3"]
CMD ["status.py"]

