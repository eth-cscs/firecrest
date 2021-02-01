#!/bin/bash
set -euo pipefail

echo "starting" $0
WORKSPACE=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)/../../

${WORKSPACE}/ci/dev/clean.sh

echo "starting containers..."
sudo docker-compose -f ${WORKSPACE}/deploy/test-build/docker-compose.yml up --build -d

echo "waiting for Firecrest stack to be ready..."
attempts=0
while [[ "$attempts" -lt 9 && "$(curl -s -o /dev/null -w ''%{http_code}'' localhost:9000)" == "000" ]]; do
    let "attempts+=1"
    echo "API NOT ready, next attempt in 5 seconds"
    sleep 5
done
if [[ "$attempts" -ge 9 ]]; then
    echo "TIMEOUT waiting API. Shutting down cluster..."
    sudo docker-compose -f ${WORKSPACE}/deploy/test-build/docker-compose.yml down -v
    exit 1
fi

echo "running unit_tests..."
sudo docker run -ti --rm -v ${WORKSPACE}:/firecrest --network test-build_frontend python:3.8.5-slim bash \
    -c 'pip install -r /firecrest/src/tests/automated_tests/requirements.txt; cd /firecrest/src/tests/automated_tests && pytest -c test-build.ini unit'

echo "running integration_tests..."
sudo docker run -ti --rm -v ${WORKSPACE}:/firecrest --network test-build_frontend python:3.8.5-slim bash \
    -c 'pip install -r /firecrest/src/tests/automated_tests/requirements.txt; cd /firecrest/src/tests/automated_tests && pytest -c test-build.ini integration'

echo "finished" $0