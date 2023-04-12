#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import os
import pytest

skipif_uses_gateway = pytest.mark.skipif(os.environ.get("USE_GATEWAY", "").lower() == "true", reason="This test does not use the gateway to test microservice")
skipif_not_uses_gateway = pytest.mark.skipif(os.environ.get("USE_GATEWAY", "").lower() == "false", reason="This test uses the gateway to test microservice")