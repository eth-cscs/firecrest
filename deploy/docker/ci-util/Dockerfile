##
##  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
ARG BASE_IMAGE=ubuntu
FROM $BASE_IMAGE

ARG CRANE_ARCH=x86_64
ARG CRANE_VERSION="v0.16.1"
ARG HELM_VERSION=3.9.0
ARG VAULT_VERSION=1.14.3

RUN apt update && apt-get install -y curl jq unzip && \
      curl -s -O https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip && \
      unzip vault_${VAULT_VERSION}_linux_amd64.zip && \
      mv vault /usr/bin && \
      rm vault_${VAULT_VERSION}_linux_amd64.zip && \
      curl -s -O https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz && \
      tar -xvf helm-v${HELM_VERSION}-linux-amd64.tar.gz && \
      mv linux-amd64/helm /usr/bin/ && \
      rm -fr linux-amd64 helm-v${HELM_VERSION}-linux-amd64.tar.gz && \
      curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
      chmod +x kubectl && \
      mv kubectl /usr/bin/  &&  \
      curl -fL https://getcli.jfrog.io | sh  && \
      mv jfrog /usr/bin &&  \
      curl -sL "https://github.com/google/go-containerregistry/releases/download/${CRANE_VERSION}/go-containerregistry_Linux_${CRANE_ARCH}.tar.gz" > go-containerregistry.tar.gz && \
      tar -zxvf go-containerregistry.tar.gz -C /usr/bin/ crane && \
      rm go-containerregistry.tar.gz

