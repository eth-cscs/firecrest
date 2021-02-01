#!/bin/bash
set -euo pipefail

echo "starting" $0
WORKSPACE=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)

$WORKSPACE/refresh.sh
$WORKSPACE/setup.sh
$WORKSPACE/test.sh

echo "finished" $0