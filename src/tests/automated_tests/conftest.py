#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import os
import jwt
import requests
from base64 import b64encode


# fake JWT, only works if REALM_RSA_PUBLIC_KEY is empty
TEST_USER = os.environ.get("TEST_USER")
SCOPES = os.environ.get("F7T_SCOPES")
payload = {
  "sub": "1234567890",
  "name": "{}".format(TEST_USER),
  "scope": "",
  "preferred_username": "{}".format(TEST_USER),
  "iat": "1516239022",
  "jti": "e97ab227-d6c0-460d-8d1e-39b86fed83db",
  "exp": "1571347177"
}


# Service account JWT
SA_LOGIN      = os.environ.get("F7T_SA_LOGIN", "")
SA_TOKEN_URI  = os.environ.get("F7T_SA_TOKEN_URI")
SA_SECRET_KEY = os.environ.get("F7T_SA_SECRET_KEY")
SA_CLIENT_ID  = os.environ.get("F7T_SA_CLIENT_ID")


@pytest.fixture(scope='session')
def headers():
    
    # authorization with fake jwt
    if SA_LOGIN.lower() != 'true':
        auth = "Bearer " + jwt.encode(payload, 'secret', algorithm='HS256').decode("utf-8")
        return {"Authorization": auth, "Accept" : "application/json", "X-Firecrest-Service": "storage"}

    # authorization with sa account
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"grant_type":"client_credentials"}
    
    resp = requests.post(SA_TOKEN_URI, headers=headers, data=data, auth=(SA_CLIENT_ID, SA_SECRET_KEY))
    auth = resp.json()["token_type"] + " " + resp.json()["access_token"]
    return {"Authorization": auth, "Accept" : "application/json", "X-Firecrest-Service": "storage"}

   
    
