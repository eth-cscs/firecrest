#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import requests
import os
from test_globals import *
from markers import skipif_not_uses_gateway, skipif_uses_gateway
import json

### SSL parameters
SSL_ENABLED = (os.environ.get("F7T_SSL_ENABLED","false").lower() == "true")
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"

FIRECREST_URL = os.environ.get("FIRECREST_URL","")
USE_GATEWAY  = (os.environ.get("USE_GATEWAY","false").lower() == "true")

if FIRECREST_URL and USE_GATEWAY:
	UTILITIES_URL = os.environ.get("FIRECREST_URL") + "/utilities"
else:
	F7T_SCHEME_PROTOCOL = ("https" if SSL_ENABLED else "http")
	UTILITIES_HOST = os.environ.get("F7T_UTILITIES_HOST","127.0.0.1") 
	UTILITIES_PORT = os.environ.get("F7T_UTILITIES_PORT","5004")
	UTILITIES_URL = f"{F7T_SCHEME_PROTOCOL}://{UTILITIES_HOST}:{UTILITIES_PORT}"

SERVER_UTILITIES = os.environ.get("F7T_SYSTEMS_PUBLIC_NAME").strip('\'"').split(";")[0]

print(f"UTILITIES_URL: {UTILITIES_URL}")


# test data for rename, chmod,chown, download,upload
DATA = [ (SERVER_UTILITIES, 200) , ("someservernotavailable", 400)]

# test data for file
DATA_FILE = [ (SERVER_UTILITIES, 200, ".bashrc") ,
         ("someservernotavailable", 400, ".bashrc"),
		 (SERVER_UTILITIES, 400, "nofile") ,
		 (SERVER_UTILITIES, 400, "/var/log/messages") ,
		 (SERVER_UTILITIES, 400, "/\\") ,
		 (SERVER_UTILITIES, 400, "a>b"),
		 (SERVER_UTILITIES, 400, "a<b"),
		 (SERVER_UTILITIES, 400, "(a"),
		 (SERVER_UTILITIES, 400, "`hostname`") ]

# test data for 'stat'
DATA_STAT = [ (SERVER_UTILITIES, 200, ".bashrc") ,
		 (SERVER_UTILITIES, 200, "/var/log/messages") ,
         ("someservernotavailable", 400, ".bashrc"),
		 (SERVER_UTILITIES, 400, "nofile") ]

# test data for 'mkdir' using forbidden chars
DATA_CHARS = [ (SERVER_UTILITIES, 201, "/tmp/f7t-$UID") ,
	(SERVER_UTILITIES, 201, "/tmp/f7t-$F7T_UTILITIES_TIMEOUT") ,
	(SERVER_UTILITIES, 400, "/tmp/a\\") ,
	(SERVER_UTILITIES, 400, "/tmp/a>b"),
	(SERVER_UTILITIES, 400, "/tmp/a<b"),
	(SERVER_UTILITIES, 400, "/tmp/(a"),
	(SERVER_UTILITIES, 400, "/tmp/a" + chr(0)),
	(SERVER_UTILITIES, 400, "/tmp/a" + chr(0) + "a"),
	(SERVER_UTILITIES, 400, "/tmp/a" + chr(13) + "a"),
	(SERVER_UTILITIES, 400, "/tmp/`hostname`") ]

# test data for #mkdir, symlink
DATA_201 = [ (SERVER_UTILITIES, 201) , ("someservernotavailable", 400)]

# test data for ls command
DATA_LS = [ (SERVER_UTILITIES, "/srv/f7t/test_sbatch.sh", 200),
(SERVER_UTILITIES, USER_HOME + "/dontexist/", 400),
(SERVER_UTILITIES, "/etc/binfmt.d/", 200), # empty folder
(SERVER_UTILITIES, USER_HOME + "/", 200),
("someservernotavailable", USER_HOME + "/" ,400)]

FORBIDDEN_INPUT_CHARS = '<>|;"\'&\\()\x00\x0D\x1F'
for c in FORBIDDEN_INPUT_CHARS:
    DATA_LS.append((SERVER_UTILITIES, "/bin/*" + c, 400))

# test data for checksum API
DATA_CK = [ (SERVER_UTILITIES, "/srv/f7t/test_sbatch.sh", 200),
(SERVER_UTILITIES, "/srv/f7t/test_sbatch_forbidden.sh", 400),
(SERVER_UTILITIES, USER_HOME + "/dontexist/", 400),
(SERVER_UTILITIES, "/etc/binfmt.d/", 400), # empty folder
(SERVER_UTILITIES, USER_HOME + "/", 400),
("someservernotavailable", USER_HOME + "/" ,400)]

# test data for head and tail: needs to match content from /srv/f7t/test_sbatch.sh
DATA_HEAD_TAIL = [ ("head", SERVER_UTILITIES, "/srv/f7t/test_sbatch.sh", "12", None, 200, "#!/bin/bash\n"),
("head", SERVER_UTILITIES, "/etc/hosts", "10", "20", 400, ""),
("head", "someservernotavailable", USER_HOME, None, None, 400, ""),
("tail", SERVER_UTILITIES, "/srv/f7t/test_sbatch.sh", "10", None, 200, "sleep 60s\n"),
("tail", SERVER_UTILITIES, "/bin/ls", "10", "20", 400, ""),
("tail", "someservernotavailable", USER_HOME, None, None, 400, "")]

# test data for checksum API
DATA_VIEW = [ (SERVER_UTILITIES, "/srv/f7t/test_sbatch.sh", 200),
(SERVER_UTILITIES, "/bin/wc", 400), # non ASCII file
(SERVER_UTILITIES, "/lib64/libz.so", 400), # non ASCII file
(SERVER_UTILITIES, "/srv/f7t/test_sbatch_forbidden.sh", 400),
(SERVER_UTILITIES, USER_HOME + "/dontexist/", 400),
(SERVER_UTILITIES, "/slurm-20.11.7.tar.bz2", 400), # > MAX_SIZE file
(SERVER_UTILITIES, USER_HOME + "/", 400),
("someservernotavailable", USER_HOME + "/" ,400)]

@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, targetPath, expected_response_code", DATA_VIEW)
def test_view(machine, targetPath, expected_response_code, headers):
	params = {"targetPath": targetPath}
	url = f"{UTILITIES_URL}/view"

	headers.update({ "X-Machine-Name": machine })

	resp = requests.get(url=url, headers=headers, params=params, verify=False)

	print(resp.json())
	print(resp.headers)

	assert expected_response_code == resp.status_code

@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, targetPath, expected_response_code", DATA_CK)
def test_checksum(machine, targetPath, expected_response_code, headers):
	params = {"targetPath": targetPath}
	url = f"{UTILITIES_URL}/checksum"

	headers.update({ "X-Machine-Name": machine })

	resp = requests.get(url=url, headers=headers, params=params, verify=False)

	print(resp.json())
	print(resp.headers)

	assert expected_response_code == resp.status_code

@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA_201)
def test_upload(machine, expected_response_code, headers):
	data = {"targetPath": USER_HOME + "/"}
	files = {'file': ('testsbatch.sh', open('testsbatch.sh', 'rb'))}
	url = f"{UTILITIES_URL}/upload"
	headers.update({"X-Machine-Name": machine})
	print(machine)
	resp = requests.post(url, headers=headers, data=data, files=files, verify=False)
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == expected_response_code


@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code,file_name", DATA_FILE)
def test_file_type(machine, expected_response_code, file_name, headers):
	url = f"{UTILITIES_URL}/file"
	params = {"targetPath": file_name}
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, params=params, verify=False)
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == expected_response_code


@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code,file_name", DATA_STAT)
def test_stat(machine, expected_response_code, file_name, headers):
	url = f"{UTILITIES_URL}/stat"
	params = {"targetPath": file_name}
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, params=params, verify=False)
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == expected_response_code


@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_file_type_error(machine, expected_response_code, headers):
	url = f"{UTILITIES_URL}/file"
	params = {"targetPath": ".bashrc"}
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, params=params, verify=False)
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == expected_response_code


# Helper function to exec chmod
def exec_chmod(machine, headers, data):
	url = f"{UTILITIES_URL}/chmod"
	headers.update({"X-Machine-Name": machine})
	resp = requests.put(url, headers=headers, data=data, verify=False)
	return resp


@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_chmod_valid_args(machine, expected_response_code, headers):
	data = {"targetPath": "testsbatch.sh", "mode" : "777"}
	resp = exec_chmod(machine, headers, data)
	print(resp.content)
	assert resp.status_code == expected_response_code


@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_chmod_invalid_args(machine, expected_response_code, headers):
	data = {"targetPath": "testsbatch.sh", "mode" : "999"}
	resp = exec_chmod(machine, headers, data)
	print(resp.content)
	assert resp.status_code != 200



@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_chown(machine, expected_response_code, headers):
	data = {"targetPath": USER_HOME + "/testsbatch.sh", "owner" : CURRENT_USER , "group": CURRENT_USER}
	url = f"{UTILITIES_URL}/chown"
	headers.update({"X-Machine-Name": machine})
	resp = requests.put(url, headers=headers, data=data, verify=False)
	print(resp.content)
	assert resp.status_code == expected_response_code

@skipif_not_uses_gateway
@pytest.mark.parametrize("command, machine, filename, bytes, lines, expected_response_code, output", DATA_HEAD_TAIL)
def test_head_tail(command, machine, filename, bytes, lines, expected_response_code, output, headers):
	params = {"targetPath": filename}
	if bytes:
		params.update({"bytes": bytes})
	if lines:
		params.update({"lines": lines})

	url = f"{UTILITIES_URL}/{command}"
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, params=params, verify=False)
	assert resp.status_code == expected_response_code
	if expected_response_code == 200:
		assert json.loads(resp.content)["output"] == output


@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, targetPath, expected_response_code", DATA_LS)
def test_list_directory(machine, targetPath, expected_response_code, headers):
	params = {"targetPath": targetPath, "showhidden" : "true"}
	url = f"{UTILITIES_URL}/ls"
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, params=params, verify=False)
	print(json.dumps(resp.json(),indent=2))
	print(resp.headers)
	assert resp.status_code == expected_response_code


@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA_201)
def test_make_directory(machine, expected_response_code, headers):
	data = {"targetPath": USER_HOME + "/samplefolder/samplesubfolder", "p" : "true"}
	url = f"{UTILITIES_URL}/mkdir"
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(url, headers=headers, data=data, verify=False)
	print(resp.content)
	assert resp.status_code == expected_response_code


@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_rename(machine, expected_response_code, headers):
	data = {"sourcePath": USER_HOME + "/samplefolder/", "targetPath" : USER_HOME + "/sampleFolder/"}
	url = f"{UTILITIES_URL}/rename"
	headers.update({"X-Machine-Name": machine})
	resp = requests.put(url, headers=headers, data=data, verify=False)
	print(resp.content)
	assert resp.status_code == expected_response_code



@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA_201)
def test_copy(machine, expected_response_code, headers):
	data = {"sourcePath": USER_HOME + "/sampleFolder", "targetPath" : USER_HOME + "/sampleFoldercopy"}
	url = f"{UTILITIES_URL}/copy"
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(url, headers=headers, data=data, verify=False)
	print(resp.content)
	assert resp.status_code == expected_response_code


@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA_201)
def test_symlink(machine, expected_response_code, headers):
	data = {"targetPath": USER_HOME + "/testsbatch.sh", "linkPath" : USER_HOME + "/sampleFolder/testlink"}
	url = f"{UTILITIES_URL}/symlink"
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(url, headers=headers, data=data, verify=False)
	print(resp.content)
	print(machine)
	assert resp.status_code == expected_response_code


#  Test rm command: remove sampleFolder
# TODO: test file which doesn't exist (must return 400)
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", [ (SERVER_UTILITIES, 204) , ("someservernotavailable", 400)])
def test_rm(machine, expected_response_code, headers):
	data = {"targetPath": USER_HOME + "/sampleFolder/"}
	url = f"{UTILITIES_URL}/rm"
	headers.update({"X-Machine-Name": machine})
	resp = requests.delete(url, headers=headers, data=data, verify=False)
	print(resp.content)
	assert resp.status_code == expected_response_code


@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_download(machine, expected_response_code, headers):
	params = {"sourcePath": USER_HOME + "/testsbatch.sh"}
	url = f"{UTILITIES_URL}/download"
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, params=params, verify=False)
	assert resp.status_code == expected_response_code


@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_whoami(machine, expected_response_code, headers):
	url = f"{UTILITIES_URL}/whoami"
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, params={}, verify=False)
	if resp.ok:
		assert resp.json()["output"] == CURRENT_USER

	assert resp.status_code == expected_response_code


@pytest.mark.parametrize("machine, expected_response_code, file_name", DATA_CHARS)
def test_forbidden_chars(machine, expected_response_code, file_name, headers):
	data = {"targetPath": file_name, "p" : "true"}
	url = f"{UTILITIES_URL}/mkdir"
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(url, headers=headers, data=data, verify=False)
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == expected_response_code


# Test utilities microservice status
@skipif_uses_gateway
def test_status(headers):
	url = f"{UTILITIES_URL}/status"
	resp = requests.get(url, headers=headers, verify=False)
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == 200



if __name__ == '__main__':
	pytest.main()
