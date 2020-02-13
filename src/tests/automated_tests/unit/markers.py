import os
import pytest

host_environment_test = pytest.mark.skipif(os.environ.get("HOST_NETWORK", "").lower() != "true", reason="test not valid for this environment")
