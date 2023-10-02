##
##  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
FROM python:3.8.12-slim

RUN pip3 install --upgrade pip

RUN pip3 install markupsafe==2.1.2 Flask==2.0.0 itsdangerous==2.0.1 flask-WTF flask-bootstrap flask-oidc flask_sslify requests==2.22.0 Werkzeug==2.2

ADD ./ app

WORKDIR app

EXPOSE 5000

ENTRYPOINT ["python", "firecrest_demo.py"]
