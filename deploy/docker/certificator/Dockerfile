##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
ARG BASE_IMAGE=f7t-base
from $BASE_IMAGE

RUN yum install -y openssh-7.4p1

ADD deploy/docker/certificator/requirements.txt deps/requirements.txt
RUN pip3 install -r deps/requirements.txt

ADD src/certificator/certificator.py certificator.py

ENTRYPOINT ["python3"]
CMD ["certificator.py"]
