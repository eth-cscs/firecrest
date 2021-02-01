#!/bin/bash
set -euo pipefail

echo "starting" $0
WORKSPACE=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)/../../

echo "prepare fresh logs folder..."
mkdir -pv ${WORKSPACE}/deploy/test-build/logs/firecrest
chmod 775 ${WORKSPACE}/deploy/test-build/logs/firecrest

echo "adjusting keys..."
chmod 400 ${WORKSPACE}/deploy/test-build/environment/keys/ca-key
chmod 400 ${WORKSPACE}/deploy/test-build/environment/keys/user-key

echo "finished" $0