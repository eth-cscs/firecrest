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

echo "removing potential leftovers"
rm -rfv ${WORKSPACE}/deploy/test-build/logs/firecrest || true
docker-compose -f ${WORKSPACE}/deploy/test-build/docker-compose.yml down -v --rmi all --remove-orphans || true
docker rmi f7t-base f7t-tester || echo "no base image to delete, no problem!"

echo "building images from scratch (no caches)"
# Building from scratch is slower, but prevents cache-invalidation issues, typical of cached CI machines.
# You may want to do this only once a while, not for every feature branch.
docker build -f ${WORKSPACE}/deploy/docker/base/Dockerfile -t f7t-base --no-cache --pull ${WORKSPACE}
docker build -f ${WORKSPACE}/deploy/docker/tester/Dockerfile -t f7t-tester --no-cache --pull ${WORKSPACE}
docker-compose -f ${WORKSPACE}/deploy/test-build/docker-compose.yml build --no-cache

echo "finished" $0
