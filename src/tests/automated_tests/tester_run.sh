#!/bin/bash
##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##

exit_code=0

# We start with the reservation tests because other tests still need a proper cleanup step.
# echo "running reservation tests..."
pytest -m "reservations" -c $PYTEST_CONFIG_FILE unit
exit_code=$(( $? | exit_code ))

pytest -m "not reservations" -c $PYTEST_CONFIG_FILE unit
exit_code=$(( $? | exit_code ))

pytest -m "not reservations" -c $PYTEST_CONFIG_FILE integration
exit_code=$(( $? | exit_code ))

echo "Finished $0 with status $exit_code"

exit $exit_code