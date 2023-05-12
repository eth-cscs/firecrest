##
##  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
ARG BASE_IMAGE=centos:7
FROM $BASE_IMAGE

RUN yum install -y epel-release
RUN yum -y update
RUN yum -y groupinstall "Development Tools"
RUN yum -y install openssl-devel bzip2-devel libffi-devel xz-devel wget
RUN wget https://www.python.org/ftp/python/3.8.12/Python-3.8.12.tgz
RUN tar xvf Python-3.8.12.tgz && cd Python-3.8.12 && ./configure --enable-optimizations && make altinstall

RUN ln -fs /usr/local/bin/python3.8 /usr/bin/python3

RUN yum install -y python3.8-pip openssh

RUN pip3.8 install --upgrade pip

ADD deploy/docker/base/requirements.txt base/requirements.txt
ADD deploy/docker/certificator/requirements.txt deps/requirements.txt
RUN pip3.8 install -r deps/requirements.txt

ADD src/certificator/certificator.py certificator.py

ENV F7T_CERTIFICATOR_PORT 5000
ENV F7T_LOG_PATH /var/log
ENV F7T_SSL_CRT /ssl/f7t_internal.crt
ENV F7T_SSL_KEY /ssl/f7t_internal.key
ENV F7T_GUNICORN_SSL --ciphers TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_GCM_SHA256,DHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES128-GCM-SHA256 \
                     --ssl-version TLSv1_2 --keyfile $F7T_SSL_KEY --certfile $F7T_SSL_CRT
ENV F7T_GUNICORN_WORKER --workers=1 --threads=1

ENTRYPOINT /usr/local/bin/gunicorn ${F7T_GUNICORN_SSL} ${F7T_GUNICORN_WORKER} --bind :${F7T_CERTIFICATOR_PORT} --error-logfile ${F7T_LOG_PATH}/certificator.gunicorn.log certificator:app
