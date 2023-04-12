##
##  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
ARG BASE_IMAGE=ubuntu
FROM $BASE_IMAGE

ARG HELM_VERSION=3.9.0

RUN apt update; apt-get install -y curl gnupg jq lsb-release software-properties-common; \
      curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add -;  \
      apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"; \
      apt update; \
      apt -y upgrade; \
      apt install -y vault; \
      apt-get install --reinstall -y vault;

RUN curl -s -O https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz; \
      tar -xvf helm-v${HELM_VERSION}-linux-amd64.tar.gz; \
      mv linux-amd64/helm /usr/bin/ ; \
      curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"; \
      chmod +x kubectl; \
      mv kubectl /usr/bin/; \
      curl -fL https://getcli.jfrog.io | sh ; \
      mv jfrog /usr/bin

