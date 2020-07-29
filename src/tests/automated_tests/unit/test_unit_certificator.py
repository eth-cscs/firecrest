import pytest
import requests
import os
from markers import host_environment_test
import base64

FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
	CERTIFICATOR_URL = os.environ.get("FIRECREST_URL") + "/certificator"
else:
    CERTIFICATOR_URL = os.environ.get("F7T_CERTIFICATOR_URL")	

SERVER_COMPUTE = os.environ.get("F7T_SYSTEMS_INTERNAL_UTILITIES").split(";")[0]


OPA_DATA = [("not_existing_system", 401), (SERVER_COMPUTE, 200)]

# Test get a certificate
@host_environment_test
def test_receive(headers):
	# url = f"{CERTIFICATOR_URL}/?command=" + base64.urlsafe_b64encode("ls".encode()).decode()
	params = {"command": base64.urlsafe_b64encode("ls".encode()).decode(),
			  "cluster": SERVER_COMPUTE }
	resp = requests.get(CERTIFICATOR_URL, headers=headers, params=params)
	print(resp.content)
	assert resp.status_code == 200

@host_environment_test
@pytest.mark.parametrize("machine, expected_response_code", OPA_DATA)
def test_opa(machine,expected_response_code,headers):
	# url = f"{CERTIFICATOR_URL}/?command=" + base64.urlsafe_b64encode("ls".encode()).decode()
	params = {"command": base64.urlsafe_b64encode("ls".encode()).decode(),
			  "cluster": machine }
	resp = requests.get(CERTIFICATOR_URL, headers=headers, params=params)
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test get status of certificator microservice
@host_environment_test
def test_status(headers):
	url = f"{CERTIFICATOR_URL}/status"
	resp = requests.get(url, headers=headers)
	print(resp.content)
	assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()
