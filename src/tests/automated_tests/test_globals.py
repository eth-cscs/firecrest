#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import os

# name of user firing the tests:
#     will be TEST_USER for fake jwt, or service-account-{SA_CLIENT_ID} for sa login
CURRENT_USER = ""

if os.environ.get("F7T_SA_LOGIN", "").lower() != 'true':
    CURRENT_USER = os.environ.get("TEST_USER")
else:
    CURRENT_USER = 'service-account-' + os.environ.get("F7T_SA_CLIENT_ID")

USER_HOME = "/home/" + CURRENT_USER

