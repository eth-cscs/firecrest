#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import requests

STATUS_URL = "http://0.0.0.0:5001"

@pytest.mark.parametrize("system",["daunt", "pollux"])
def test_status_system(system, headers):
	url = "{}/systems/{}".format(STATUS_URL, system)
	resp = requests.get(url, headers=headers)
	print(resp.json())
	assert 'description' in resp.json()
	 

def test_status_systems(headers):
	url = "{}/systems".format(STATUS_URL)
	resp = requests.get(url, headers=headers)
	print(resp.json())
	assert 'description' in resp.json()


@pytest.mark.parametrize("service",["certificator", "utilities", "compute", "tasks", "storage"])
def test_status_service(service, headers):
	url = "{}/services/{}".format(STATUS_URL, service)
	resp = requests.get(url, headers=headers)
	print(resp.json())
	assert 'description' in resp.json()


def test_status_services(headers):
	url = "{}/services".format(STATUS_URL)
	resp = requests.get(url, headers=headers)
	print(resp.json())
	assert 'description' in resp.json()


def test_parameters(headers):
	url = "{}/parameters".format(STATUS_URL)
	resp = requests.get(url, headers=headers)
	print(resp.json())
	assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()
