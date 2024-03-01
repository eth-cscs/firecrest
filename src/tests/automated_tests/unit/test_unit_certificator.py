#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import requests
import os
from markers import skipif_uses_gateway
import base64

### SSL parameters
USE_SSL = (str(os.environ.get("F7T_SSL_USE","false")).lower() == "true")
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"

FIRECREST_URL = os.environ.get("FIRECREST_URL","")
USE_GATEWAY  = (str(os.environ.get("USE_GATEWAY","false")).lower() == "true")

if FIRECREST_URL and USE_GATEWAY:
	CERTIFICATOR_URL = os.environ.get("FIRECREST_URL") + "/certificator"
	
else:
	F7T_SCHEME_PROTOCOL = ("https" if USE_SSL else "http")
	CERTIFICATOR_HOST = os.environ.get("F7T_CERTIFICATOR_HOST","127.0.0.1") 
	CERTIFICATOR_PORT = os.environ.get("F7T_CERTIFICATOR_PORT","5000")
	CERTIFICATOR_URL = f"{F7T_SCHEME_PROTOCOL}://{CERTIFICATOR_HOST}:{CERTIFICATOR_PORT}"

SYSTEM_NAME = os.environ.get("F7T_SYSTEMS_PUBLIC_NAME").strip('\'"').split(";")[0]
SYSTEM_ADDR = os.environ.get("F7T_SYSTEMS_INTERNAL_NAME").strip('\'"').split(";")[0]

OPA_DATA = [("not_existing_system", "not_existing_addr", 401), (SYSTEM_NAME, SYSTEM_ADDR, 200)]

# Test get a certificate
@skipif_uses_gateway
def test_receive(headers):
	# url = f"{CERTIFICATOR_URL}/?command=" + base64.urlsafe_b64encode("ls".encode()).decode()
	params = {"command": base64.urlsafe_b64encode("ls".encode()).decode(),
			  "cluster": SYSTEM_NAME, "addr": SYSTEM_ADDR }
	print(f"CERTIFICATOR_URL: {CERTIFICATOR_URL}")
	resp = requests.get(CERTIFICATOR_URL, headers=headers, params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == 200

@skipif_uses_gateway
@pytest.mark.parametrize("machine, addr, expected_response_code", OPA_DATA)
def test_opa(machine,addr,expected_response_code,headers):
	# url = f"{CERTIFICATOR_URL}/?command=" + base64.urlsafe_b64encode("ls".encode()).decode()
	params = {"command": base64.urlsafe_b64encode("ls".encode()).decode(),
			  "cluster": machine, "addr": addr }
	resp = requests.get(CERTIFICATOR_URL, headers=headers, params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test get a certificate
@skipif_uses_gateway
def test_forbidden_chars(headers):
	# test forbidden char
	fc = chr(0) + chr(9) + "(;"
	for c in fc:
		params = {"command": base64.urlsafe_b64encode(f"ls {c}".encode()).decode(),
			  "cluster": SYSTEM_NAME, "addr": SYSTEM_ADDR }
		resp = requests.get(CERTIFICATOR_URL, headers=headers, params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
		print(resp.content)
		assert resp.status_code == 400


# Test get status of certificator microservice
@skipif_uses_gateway
def test_status(headers):
	url = f"{CERTIFICATOR_URL}/status"
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()
