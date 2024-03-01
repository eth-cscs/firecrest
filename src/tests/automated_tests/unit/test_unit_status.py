#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import requests
import os
from markers import skipif_not_uses_gateway

### SSL parameters
USE_SSL = (os.environ.get("F7T_SSL_USE","false").lower() == "true")
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"

FIRECREST_URL = os.environ.get("FIRECREST_URL")
USE_GATEWAY  = (os.environ.get("USE_GATEWAY","false").lower() == "true")

if FIRECREST_URL and USE_GATEWAY:
	STATUS_URL = os.environ.get("FIRECREST_URL") + "/status"
else:
	F7T_SCHEME_PROTOCOL = ("https" if USE_SSL else "http")
	STATUS_HOST = os.environ.get("F7T_STATUS_HOST","127.0.0.1") 
	STATUS_PORT = os.environ.get("F7T_STATUS_PORT","5001")
	STATUS_URL = f"{F7T_SCHEME_PROTOCOL}://{STATUS_HOST}:{STATUS_PORT}"

SYSTEMS = os.environ.get("F7T_SYSTEMS_PUBLIC_NAME").strip('\'"').split(";")

print(f"STATUS_URL: {STATUS_URL}")

@skipif_not_uses_gateway
@pytest.mark.parametrize("system",SYSTEMS)
def test_status_system(system, headers):
    url = f"{STATUS_URL}/systems/{system}"

STATUS_CODES_SYSTEMS = []
STATUS_CODES_FS = []
for system in SYSTEMS:
	STATUS_CODES_SYSTEMS.append((system,200))
	STATUS_CODES_FS.append((system,"HOME",200))
	STATUS_CODES_FS.append((system,"SCRATCH",400))

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
	resp = requests.get(url, headers=headers, verify=False)
	print(resp.content)
	# assert 'description' in resp.json()
	assert status_code == resp.status_code

@skipif_not_uses_gateway
def test_status_systems(headers):
	url = f"{STATUS_URL}/systems"
	resp = requests.get(url, headers=headers, verify=False)
	print(resp.content)
	assert 'description' in resp.json()

@skipif_not_uses_gateway
@pytest.mark.parametrize("system,fs_name,status_code", STATUS_CODES_FS)
def test_status_filesystems(system,fs_name,status_code,headers):
	url = f"{STATUS_URL}/filesystems/{system}"
	resp = requests.get(url, headers=headers, verify=False)
	# /home is OK, and /scratch is wrong
	print(resp.content)

	assert "out" in resp.json()

	fs_list = resp.json()["out"]

	for fs in fs_list:
		if fs["name"] == fs_name:
			assert fs["status_code"] == status_code
			break
	
@skipif_not_uses_gateway
@pytest.mark.parametrize("system,fs_name,status_code", STATUS_CODES_FS)
def test_status_all_filesystems(system,fs_name,status_code,headers):
	url = f"{STATUS_URL}/filesystems"
	resp = requests.get(url, headers=headers, verify=False)
	# /home is OK, and /scratch is wrong
	print(resp.content)
	assert "out" in resp.json()

	system_list = resp.json()["out"]

	assert system in system_list


	for fs in system_list[system]:
		if fs["name"] == fs_name:
			assert fs["status_code"] == status_code
			break


@skipif_not_uses_gateway
@pytest.mark.parametrize("service,status_code", STATUS_CODES_SERVICES)
def test_status_service(service, status_code, headers):
	url = f"{STATUS_URL}/services/{service}"
	resp = requests.get(url, headers=headers, verify=False)
	print(resp.json())
	# assert 'description' in resp.json()
	assert status_code == resp.json()["status_code"]

@skipif_not_uses_gateway
def test_status_services(headers):
	url = f"{STATUS_URL}/services"
	resp = requests.get(url, headers=headers, verify=False)
	print(resp.content)
	# print(resp.json())
	assert 'description' in resp.json()

@skipif_not_uses_gateway
def test_parameters(headers):
	print(STATUS_URL)
	url = f"{STATUS_URL}/parameters"
	resp = requests.get(url, headers=headers, verify=False)
	print(resp.content)
	assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()
