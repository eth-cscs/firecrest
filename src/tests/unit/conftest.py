#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import os
import jwt

# create a fake JWT, only works if REALM_RSA_PUBLIC_KEY is empty
TEST_USER = os.environ.get("TEST_USER")
SCOPES = os.environ.get("SCOPES")

payload = {
  "sub": "1234567890",
  "name": "{}".format(TEST_USER),
  "scope": "",
  "preferred_username": "{}".format(TEST_USER),
  "iat": "1516239022",
  "jti": "e97ab227-d6c0-460d-8d1e-39b86fed83db",
  "exp": "1571347177"
}
auth = "Bearer " + jwt.encode(payload, 'secret', algorithm='HS256').decode("utf-8") 

# get request headers
@pytest.fixture(scope='session')
def headers():
    return {"Authorization": auth, "Accept" : "application/json", "X-Firecrest-Service": "storage"}