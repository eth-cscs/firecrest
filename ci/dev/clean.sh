#!/bin/bash
set -euo pipefail

echo "starting" $0
WORKSPACE=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)/../../

sudo rm -rfv ${WORKSPACE}/deploy/test-build/logs/firecrest/* || true
sudo docker-compose -f ${WORKSPACE}/deploy/test-build/docker-compose.yml down -v

echo "finished" $0