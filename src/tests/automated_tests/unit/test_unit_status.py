import pytest
import requests
import os


FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
	STATUS_URL = os.environ.get("FIRECREST_URL") + "/status"
else:
    STATUS_URL = os.environ.get("F7T_STATUS_URL")

SYSTEMS = os.environ.get("F7T_SYSTEMS_PUBLIC").split(";")

### SSL parameters
USE_SSL = os.environ.get("F7T_USE_SSL", False)
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"


@pytest.mark.parametrize("system",SYSTEMS)
def test_status_system(system, headers):
	url = "{}/systems/{}".format(STATUS_URL, system)
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert 'description' in resp.json()
	 

def test_status_systems(headers):
	url = "{}/systems".format(STATUS_URL)
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert 'description' in resp.json()


@pytest.mark.parametrize("service",["certificator", "utilities", "compute", "tasks", "storage"])
def test_status_service(service, headers):
	url = "{}/services/{}".format(STATUS_URL, service)
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert 'description' in resp.json()


def test_status_services(headers):
	url = "{}/services".format(STATUS_URL)
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	print(resp.json())
	assert 'description' in resp.json()


def test_parameters(headers):
	print(STATUS_URL)
	url = "{}/parameters".format(STATUS_URL)
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()
