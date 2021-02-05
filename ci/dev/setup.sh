#!/bin/bash
##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
set -euo pipefail

echo "starting" $0
WORKSPACE=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)/../../

echo "prepare fresh logs folder..."
mkdir -pv ${WORKSPACE}/deploy/test-build/logs/firecrest
chmod 775 ${WORKSPACE}/deploy/test-build/logs/firecrest

echo "adjusting keys..."
chmod 400 ${WORKSPACE}/deploy/test-build/environment/keys/ca-key
chmod 400 ${WORKSPACE}/deploy/test-build/environment/keys/user-key

echo "building images with cache"
docker build -f ${WORKSPACE}/deploy/docker/base/Dockerfile -t f7t-base --pull ${WORKSPACE}
docker build -f ${WORKSPACE}/deploy/docker/tester/Dockerfile -t f7t-tester --pull ${WORKSPACE}
docker-compose -f ${WORKSPACE}/deploy/test-build/docker-compose.yml build

echo "finished" $0