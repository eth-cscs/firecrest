#!/bin/bash
set -euo pipefail

echo "starting" $0
WORKSPACE=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)/../../

echo "removing potential leftovers"
sudo rm -rfv ${WORKSPACE}/deploy/test-build/logs/firecrest || true
sudo docker-compose -f ${WORKSPACE}/deploy/test-build/docker-compose.yml down -v --rmi all --remove-orphans || true
sudo docker rmi f7t-base f7t-tester || echo "no base image to delete, no problem!"

echo "building images from scratch"
sudo docker build -f ${WORKSPACE}/deploy/docker/base/Dockerfile -t f7t-base --pull ${WORKSPACE}
sudo docker build -f ${WORKSPACE}/deploy/docker/tester/Dockerfile -t f7t-tester --pull ${WORKSPACE}
sudo docker-compose -f ${WORKSPACE}/deploy/test-build/docker-compose.yml build #--no-cache

echo "finished" $0
