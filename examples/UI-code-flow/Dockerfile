##
##  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
FROM python:3.8.12-slim

RUN pip3 install --upgrade pip

ADD ./ app

WORKDIR app

RUN pip3 install -r requirements.txt


EXPOSE 5000

ENTRYPOINT ["python", "firecrest_demo.py"]
