#!/bin/bash
##
##  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
set -euo pipefail

echo "starting" $0
WORKSPACE=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)/../../

rm -rfv ${WORKSPACE}/deploy/test-build/logs/firecrest/* || true
docker-compose -f ${WORKSPACE}/deploy/test-build/docker-compose.yml down -v

echo "finished" $0