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

echo "sleeping..."
sleep 120

# We start with the reservation tests because other tests still need a proper cleanup step.
echo "running reservation tests..."
docker run --rm -u $(id -u):$(id -g) -v ${WORKSPACE}:/firecrest --network f7t-frontend f7t-tester bash \
    -c 'pytest -m reservations -c test-build.ini'

echo "running unit tests..."
docker run --rm -u $(id -u):$(id -g) -v ${WORKSPACE}:/firecrest --network f7t-frontend f7t-tester bash \
    -c 'pytest -m "not reservations" -c test-build.ini unit'

echo "running integration tests..."
docker run --rm -u $(id -u):$(id -g) -v ${WORKSPACE}:/firecrest --network f7t-frontend f7t-tester bash \
    -c 'pytest -m "not reservations" -c test-build.ini integration'

echo "finished" $0