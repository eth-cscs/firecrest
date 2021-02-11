##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
##
##  Usage:
##        # (from repository root level)
##        docker build -t f7t-tester -f deploy/docker/tester/Dockerfile .
##        docker run -ti --rm -v $PWD:/firecrest f7t-tester
##        # (now inside the container run pytest as you want)
##        See scripts in ci folder.
from python:3.8.5-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ADD deploy/docker/base/requirements.txt base/requirements.txt
ADD deploy/docker/tester/requirements.txt deps/requirements.txt
RUN pip3 install -r deps/requirements.txt

WORKDIR /firecrest/src/tests/automated_tests

CMD [ "python3" ]
