##
##  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
ARG BASE_IMAGE=f7t-base
FROM $BASE_IMAGE

LABEL org.opencontainers.image.source=https://github.com/eth-cscs/firecrest

RUN apt-get update && apt-get -y install openssh-client

ADD deploy/docker/base/requirements.txt base/requirements.txt
ADD deploy/docker/certificator/requirements.txt deps/requirements.txt
RUN pip3 install -r deps/requirements.txt

ADD src/certificator/certificator.py certificator.py

RUN mkdir /var/log/profs

ENV F7T_CERTIFICATOR_PORT 5000
ENV F7T_LOG_PATH /var/log
ENV F7T_SSL_CRT /ssl/f7t_internal.crt
ENV F7T_SSL_KEY /ssl/f7t_internal.key
ENV F7T_GUNICORN_LOG --error-logfile ${F7T_LOG_PATH}/certificator.gunicorn.log
ENV F7T_GUNICORN_SSL --ciphers TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_GCM_SHA256,DHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES128-GCM-SHA256 \
                     --ssl-version TLSv1_2 --keyfile $F7T_SSL_KEY --certfile $F7T_SSL_CRT
ENV F7T_GUNICORN_WORKER --workers=1 --threads=1

ENTRYPOINT /usr/local/bin/gunicorn ${F7T_GUNICORN_SSL} ${F7T_GUNICORN_WORKER} --bind :${F7T_CERTIFICATOR_PORT} ${F7T_GUNICORN_LOG} certificator:app
