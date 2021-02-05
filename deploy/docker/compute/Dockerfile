##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
from centos:7

RUN yum install -y epel-release
RUN yum -y update
RUN yum install -y python3-3.6.8 python3-pip-9.0.3

RUN pip3 install --upgrade pip==21.0.1

RUN pip3 install cryptography==3.1.1 Flask==1.1.2 paramiko==2.6.0 pyjwt==1.7.1 requests==2.24.0

ADD src/compute/compute.py compute.py
ADD src/common/async_task.py async_task.py
ADD src/common/cscs_api_common.py cscs_api_common.py
ADD src/common/job_time.py job_time.py

ENTRYPOINT ["python3"]
CMD ["compute.py"]

