#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import requests

CERTIFICATOR_URL = "http://0.0.0.0:5010"

# Test get a certificate
def test_receive(headers):
	url = "{}/".format(CERTIFICATOR_URL)
	resp = requests.get(url, headers=headers)
	print(resp.json())
	assert resp.status_code == 200  
	 

# Test get status of certificator microservice
def test_status(headers):
	url = "{}/status".format(CERTIFICATOR_URL)
	resp = requests.get(url, headers=headers)
	print(resp.json())
	assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()
