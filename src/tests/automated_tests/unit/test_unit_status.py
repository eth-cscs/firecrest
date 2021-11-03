#
#  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import requests
import os
from markers import skipif_not_uses_gateway


FIRECREST_URL = os.environ.get("FIRECREST_URL")
USE_GATEWAY  = (os.environ.get("USE_GATEWAY","false").lower() == "true")

if FIRECREST_URL and USE_GATEWAY:
	STATUS_URL = os.environ.get("FIRECREST_URL") + "/status"
else:
    STATUS_URL = os.environ.get("F7T_STATUS_URL")

SYSTEMS = os.environ.get("F7T_SYSTEMS_PUBLIC").strip('\'"').split(";")

### SSL parameters
USE_SSL = os.environ.get("F7T_USE_SSL", False)
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"

@skipif_not_uses_gateway
@pytest.mark.parametrize("system",SYSTEMS)
def test_status_system(system, headers):
    url = f"{STATUS_URL}/systems/{system}"

STATUS_CODES_SYSTEMS = []

for system in SYSTEMS:
	STATUS_CODES_SYSTEMS.append((system,200))

STATUS_CODES_SYSTEMS.append(("not-a-system",404))

SERVICES = ["certificator", "utilities", "compute", "tasks", "storage","reservations"]

STATUS_CODES_SERVICES = []

for service in SERVICES:
	STATUS_CODES_SERVICES.append((service,200))

STATUS_CODES_SERVICES.append(("not-a-service",404))


@skipif_not_uses_gateway
@pytest.mark.parametrize("system,status_code", STATUS_CODES_SYSTEMS)
def test_status_system(system, status_code, headers):
	url = f"{STATUS_URL}/systems/{system}"
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	# assert 'description' in resp.json()
	assert status_code == resp.status_code

@skipif_not_uses_gateway
def test_status_systems(headers):
	url = f"{STATUS_URL}/systems"
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert 'description' in resp.json()


@skipif_not_uses_gateway
@pytest.mark.parametrize("service,status_code", STATUS_CODES_SERVICES)
def test_status_service(service, status_code, headers):
	url = f"{STATUS_URL}/services/{service}"
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	# assert 'description' in resp.json()
	assert status_code == resp.status_code

@skipif_not_uses_gateway
def test_status_services(headers):
	url = f"{STATUS_URL}/services"
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	print(resp.json())
	assert 'description' in resp.json()

@skipif_not_uses_gateway
def test_parameters(headers):
	print(STATUS_URL)
	url = f"{STATUS_URL}/parameters"
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()
