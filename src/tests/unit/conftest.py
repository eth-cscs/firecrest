#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest

# fake JWT, only works if REALM_RSA_PUBLIC_KEY is empty
JWT = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InRlc3R1c2VyIiwic2NvcGUiOiIiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ0ZXN0dXNlciIsImlhdCI6MTUxNjIzOTAyMiwianRpIjoiZTk3YWIyMjctZDZjMC00NjBkLThkMWUtMzliODZmZWQ4M2RiIiwiZXhwIjoxNTcxMzQ3MTc3fQ.3GMrdY0TXTcHouFemtcHz-eutf7DdQtFK1AMjiDxtp8"


@pytest.fixture(scope='session')
def headers():
    return {"Authorization": JWT, "Accept" : "application/json", "X-Firecrest-Service": "storage"}
    
