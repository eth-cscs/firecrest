##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
from centos:7

# install epel repo for python-pip package
RUN yum install -y epel-release
# update yum
RUN yum -y update

# install python-pip from repo
RUN yum install -y python3-3.6.8 python3-pip-9.0.3

# upgrade
RUN pip3 install --upgrade pip==21.0.1

# RUN pip3 install Flask paramiko lxml cryptography pyjwt keystoneauth1 python-keystoneclient
RUN pip3 install cryptography==3.1.1 Flask==1.1.2 keystoneauth1==4.2.1 lxml==4.6.1 paramiko==2.6.0 python-keystoneclient==4.1.1 PyJWT==1.7.1 requests==2.24.0

ADD src/storage/storage.py storage.py
ADD src/storage/keystone.py keystone.py
ADD src/storage/objectstorage.py objectstorage.py
ADD src/storage/s3v2OS.py s3v2OS.py
ADD src/storage/s3v4OS.py s3v4OS.py
ADD src/storage/swiftOS.py swiftOS.py

ADD src/common/async_task.py async_task.py
ADD src/common/job_time.py job_time.py
ADD src/common/cscs_api_common.py cscs_api_common.py


ENTRYPOINT ["python3"]
CMD ["storage.py"]
