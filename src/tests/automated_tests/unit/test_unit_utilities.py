import pytest
import requests
import os
from test_globals import *
from markers import host_environment_test
import json


FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
	UTILITIES_URL = os.environ.get("FIRECREST_URL") + "/utilities"
else:
    UTILITIES_URL = os.environ.get("F7T_UTILITIES_URL")

SERVER_UTILITIES = os.environ.get("F7T_SYSTEMS_PUBLIC").split(";")[0]

### SSL parameters
USE_SSL = os.environ.get("F7T_USE_SSL", False)
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"


# test data for rename, chmod,chown, file, download,upload
DATA = [ (SERVER_UTILITIES, 200) , ("someservernotavailable", 400)]  

# test data for #mkdir, symlink
DATA_201 = [ (SERVER_UTILITIES, 201) , ("someservernotavailable", 400)]  

# test data for ls command
DATA_LS = [ (SERVER_UTILITIES, "/srv/f7t/test_sbatch.sh", 200), 
(SERVER_UTILITIES, USER_HOME + "/dontexist/", 400),
(SERVER_UTILITIES, "/etc/binfmt.d/", 200), # empty folder
(SERVER_UTILITIES, USER_HOME + "/", 200),
("someservernotavailable", USER_HOME + "/" ,400)]  

# test data for checksum API
DATA_CK = [ (SERVER_UTILITIES, "/srv/f7t/test_sbatch.sh", 200), 
(SERVER_UTILITIES, "/srv/f7t/test_sbatch_forbidden.sh", 400), 
(SERVER_UTILITIES, USER_HOME + "/dontexist/", 400),
(SERVER_UTILITIES, "/etc/binfmt.d/", 400), # empty folder
(SERVER_UTILITIES, USER_HOME + "/", 400),
("someservernotavailable", USER_HOME + "/" ,400)]  

# test data for checksum API
DATA_VIEW = [ (SERVER_UTILITIES, "/srv/f7t/test_sbatch.sh", 200), 
(SERVER_UTILITIES, "/bin/wc", 400), # non ASCII file
(SERVER_UTILITIES, "/lib64/libz.so", 400), # non ASCII file
(SERVER_UTILITIES, "/srv/f7t/test_sbatch_forbidden.sh", 400), 
(SERVER_UTILITIES, USER_HOME + "/dontexist/", 400),
(SERVER_UTILITIES, "/slurm-19.05.4.tar.bz2", 400), # > MAX_SIZE file
(SERVER_UTILITIES, USER_HOME + "/", 400),
("someservernotavailable", USER_HOME + "/" ,400)]

@pytest.mark.parametrize("machine, targetPath, expected_response_code", DATA_VIEW)
def test_view(machine, targetPath, expected_response_code, headers):
	params = {"targetPath": targetPath}
	url = f"{UTILITIES_URL}/view"

	headers.update({ "X-Machine-Name": machine })

	resp = requests.get(url=url, headers=headers, params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))

	print(resp.json())
	print(resp.headers)

	assert expected_response_code == resp.status_code

@pytest.mark.parametrize("machine, targetPath, expected_response_code", DATA_CK)
def test_checksum(machine, targetPath, expected_response_code, headers):
	params = {"targetPath": targetPath}
	url = f"{UTILITIES_URL}/checksum"

	headers.update({ "X-Machine-Name": machine })

	resp = requests.get(url=url, headers=headers, params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))

	print(resp.json())
	print(resp.headers)

	assert expected_response_code == resp.status_code



# Test upload command
@pytest.mark.parametrize("machine, expected_response_code", DATA_201)
def test_upload(machine, expected_response_code, headers):
	data = {"targetPath": USER_HOME + "/"}
	files = {'file': ('testsbatch.sh', open('testsbatch.sh', 'rb'))}
	url = "{}/upload".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	print(machine)
	resp = requests.post(url, headers=headers, data=data, files=files, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == expected_response_code 


# Test exec file command on remote system
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_file_type(machine, expected_response_code, headers):
	url = "{}/file".format(UTILITIES_URL)
	params = {"targetPath": ".bashrc"}
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code  
	 

# Helper function to exec chmod
def exec_chmod(machine, headers, data):
	url = "{}/chmod".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.put(url, headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	return resp


# Test chmod with valid arguments 
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_chmod_valid_args(machine, expected_response_code, headers):
	data = {"targetPath": "testsbatch.sh", "mode" : "777"}
	resp = exec_chmod(machine, headers, data)
	print(resp.content)
	assert resp.status_code == expected_response_code  


# Test chmod with invalid arguments 
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_chmod_invalid_args(machine, expected_response_code, headers):
	data = {"targetPath": "testsbatch.sh", "mode" : "999"}
	resp = exec_chmod(machine, headers, data)
	print(resp.content)
	assert resp.status_code != 200



# Test chown method 
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_chown(machine, expected_response_code, headers):
	data = {"targetPath": USER_HOME + "/testsbatch.sh", "owner" : CURRENT_USER , "group": CURRENT_USER}
	url = "{}/chown".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.put(url, headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code  

# Test ls command
@pytest.mark.parametrize("machine, targetPath, expected_response_code", DATA_LS)
def test_list_directory(machine, targetPath, expected_response_code, headers):
	params = {"targetPath": targetPath, "showhidden" : "true"}
	url = "{}/ls".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(json.dumps(resp.json(),indent=2))
	print(resp.headers)
	assert resp.status_code == expected_response_code


# Test mkdir command
@pytest.mark.parametrize("machine, expected_response_code", DATA_201)
def test_make_directory(machine, expected_response_code, headers):
	data = {"targetPath": USER_HOME + "/samplefolder/samplesubfolder", "p" : "true"}
	url = "{}/mkdir".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(url, headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code  


# Test rename command
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_rename(machine, expected_response_code, headers):
	data = {"sourcePath": USER_HOME + "/samplefolder/", "targetPath" : USER_HOME + "/sampleFolder/"}
	url = "{}/rename".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.put(url, headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code  



# Test cp command
@pytest.mark.parametrize("machine, expected_response_code", DATA_201)
def test_copy(machine, expected_response_code, headers):
	data = {"sourcePath": USER_HOME + "/sampleFolder", "targetPath" : USER_HOME + "/sampleFoldercopy"}
	url = "{}/copy".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(url, headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code  


# Test symlink command
@pytest.mark.parametrize("machine, expected_response_code", DATA_201)
def test_symlink(machine, expected_response_code, headers):
	data = {"targetPath": USER_HOME + "/testsbatch.sh", "linkPath" : USER_HOME + "/sampleFolder/testlink"}
	url = "{}/symlink".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(url, headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	print(machine)
	assert resp.status_code == expected_response_code


#  Test rm command: remove sampleFolder
# TODO: test file which doesn't exist (must return 400)
@pytest.mark.parametrize("machine, expected_response_code", [ (SERVER_UTILITIES, 204) , ("someservernotavailable", 400)])
def test_rm(machine, expected_response_code, headers):
	data = {"targetPath": USER_HOME + "/sampleFolder/"}
	url = "{}/rm".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.delete(url, headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code 


# Test download command
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_download(machine, expected_response_code, headers):
	params = {"sourcePath": USER_HOME + "/testsbatch.sh"}
	url = "{}/download".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	assert resp.status_code == expected_response_code


# Test utilities microservice status
@host_environment_test
def test_status():
	url = "{}/status".format(UTILITIES_URL)
	resp = requests.get(url, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == 200



if __name__ == '__main__':
	pytest.main()
