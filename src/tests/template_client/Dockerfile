##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
FROM python:3.7-alpine

RUN pip install itsdangerous==2.0.1 flask flask-WTF flask-bootstrap flask-oidc flask_sslify requests

ADD ./ app

WORKDIR app

EXPOSE 5000

ENTRYPOINT ["python", "firecrest_demo.py"]
