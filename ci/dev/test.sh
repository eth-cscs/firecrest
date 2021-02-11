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

${WORKSPACE}/ci/dev/clean.sh

echo "starting containers..."
docker-compose -f ${WORKSPACE}/deploy/test-build/docker-compose.yml up --build -d

echo "waiting for Firecrest stack to be ready..."
attempts=0
while [[ "$attempts" -lt 9 && "$(curl -s -o /dev/null -w ''%{http_code}'' localhost:9000)" == "000" ]]; do
    let "attempts+=1"
    echo "API NOT ready, next attempt in 60 seconds"
    sleep 60
done
if [[ "$attempts" -ge 9 ]]; then
    echo "TIMEOUT waiting API. Shutting down cluster..."
    docker-compose -f ${WORKSPACE}/deploy/test-build/docker-compose.yml down -v
    exit 1
fi

echo "running unit_tests..."
docker run --rm -u $(id -u):$(id -g) -v ${WORKSPACE}:/firecrest --network f7t-frontend f7t-tester bash \
    -c 'pytest -c test-build.ini unit'

echo "running integration_tests..."
docker run --rm -u $(id -u):$(id -g) -v ${WORKSPACE}:/firecrest --network f7t-frontend f7t-tester bash \
    -c 'pytest -c test-build.ini integration'

echo "finished" $0