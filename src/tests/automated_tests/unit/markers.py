#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import os
import pytest

host_environment_test = pytest.mark.skipif(os.environ.get("HOST_NETWORK", "").lower() != "true", reason="test not valid for this environment")
