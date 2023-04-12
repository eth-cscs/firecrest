##
##  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
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
from python:3.8.12-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ADD deploy/docker/tester/requirements.txt deps/requirements.txt
RUN pip3 install -r deps/requirements.txt

ADD src/tests/automated_tests /firecrest/src/tests/automated_tests
WORKDIR /firecrest/src/tests/automated_tests

CMD [ "python3" ]
