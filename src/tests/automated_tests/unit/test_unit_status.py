import pytest
import requests
import os


FIRECREST_IP = os.environ.get("FIRECREST_IP")
if FIRECREST_IP:
	STATUS_URL = os.environ.get("FIRECREST_IP") + "/status"
else:
    STATUS_URL = os.environ.get("STATUS_URL")

SYSTEMS = os.environ.get("SYSTEMS_PUBLIC").split(";")



@pytest.mark.parametrize("system",SYSTEMS)
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
