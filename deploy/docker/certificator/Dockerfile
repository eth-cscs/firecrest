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
RUN pip3 install pip==21.0.1

RUN yum install -y openssh-7.4p1

RUN pip3 install Flask==1.1.2 cryptography==3.1.1 pyjwt==1.7.1 requests==2.24.0

ADD src/certificator/certificator.py certificator.py
# ADD src/common/cscs_api_common.py cscs_api_common.py

ENTRYPOINT ["python3"]
CMD ["certificator.py"]

