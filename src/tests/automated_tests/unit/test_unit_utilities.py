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



# Test exec file command on remote system
@pytest.mark.parametrize("machine, targetPath, expected_response_code",  [ 

# 1- server that exists
(SERVER_UTILITIES, ".bashrc", 200),

# 2 - server that not exists 
("someservernotavailable", ".bashrc", 400),

# 3 - server name: empty string
("", ".bashrc", 400),

# 4 - server name not specified
(None, ".bashrc", 400),

# 5 - file that not exists 
(SERVER_UTILITIES, "notexists", 400),

# 6 - file name: empty string
(SERVER_UTILITIES, "", 400),

# 7 - file name not specified
(SERVER_UTILITIES, None, 400)
])
def test_file_type(machine, targetPath, expected_response_code, headers):
	url = "{}/file".format(UTILITIES_URL)
	params = {"targetPath": targetPath}
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, params=params)
	print(resp.content)
	assert resp.status_code == expected_response_code  




# Test upload command
@pytest.mark.parametrize("machine, filepath, targetPath, expected_response_code", [

# 1 - valid upload
(SERVER_UTILITIES, "testsbatch.sh", USER_HOME + "/", 201), 

# 2 - server that not exists
("someservernotavailable","testsbatch.sh", USER_HOME + "/", 400),

# 3 - server name: empty string
("","testsbatch.sh", USER_HOME + "/", 400),

# 4 - server name not specified
(None,"testsbatch.sh", USER_HOME + "/", 400),

# 5 - filepath invalid
(SERVER_UTILITIES, "notexists", USER_HOME + "/", 400), 

# 6 - filepath invalid empty string
(SERVER_UTILITIES, "", USER_HOME + "/", 400), 

# 7 - filepath not specified
(SERVER_UTILITIES, None, USER_HOME + "/", 400),

# 8 - targetPath invalid
(SERVER_UTILITIES, "testsbatch.sh", "/notvalid", 400), 

# 8 - targetPath empty string
(SERVER_UTILITIES, "testsbatch.sh", "", 400), 

# 9 - targetPath not specified
(SERVER_UTILITIES, "testsbatch.sh", None, 400), 
])
def test_upload(machine, filepath, targetPath, expected_response_code, headers):
	data = {"targetPath": targetPath}
	files = {}
	try:
		files = {'file': ('file', open(filepath, 'rb'))}
	except Exception as e:
		pass
	url = "{}/upload".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(url, headers=headers, data=data, files=files)
	print(resp.content)
	assert resp.status_code == expected_response_code 


# Helper function to exec chmod
def exec_chmod(machine, headers, data):
	url = "{}/chmod".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.put(url, headers=headers, data=data)
	return resp





# Test chmod
@pytest.mark.parametrize("machine, targetPath, mode, expected_response_code", [ 
(SERVER_UTILITIES, "testsbatch.sh", "999", 200), 

("someservernotavailable", "testsbatch.sh", "999", 400),
("", "testsbatch.sh", "999", 400),
(None, "testsbatch.sh", "999", 400),

(SERVER_UTILITIES, "notexists", "999", 400),
(SERVER_UTILITIES, "", "999", 400),
(SERVER_UTILITIES, None, "999", 400),

(SERVER_UTILITIES, "testsbatch.sh", "", 400), 
(SERVER_UTILITIES, "testsbatch.sh", None, 400), 
(SERVER_UTILITIES, "testsbatch.sh", "55555", 400)

])
def test_chmod(machine, targetPath, mode, expected_response_code, headers):
	data = {"targetPath": targetPath, "mode" : mode}
	resp = exec_chmod(machine, headers, data)
	print(resp.content)
	assert resp.status_code != 200



# Test chown method 
@pytest.mark.parametrize("machine, targetPath, owner, group, expected_response_code", [ 
(SERVER_UTILITIES, USER_HOME + "/testsbatch.sh", CURRENT_USER, CURRENT_USER, 200), 

("someservernotavailable", USER_HOME + "/testsbatch.sh", CURRENT_USER, CURRENT_USER, 400),
("", USER_HOME + "/testsbatch.sh", CURRENT_USER, CURRENT_USER, 400),
(None, USER_HOME + "/testsbatch.sh", CURRENT_USER, CURRENT_USER, 400),

(SERVER_UTILITIES, "/notvalid", CURRENT_USER, CURRENT_USER, 400), 
(SERVER_UTILITIES, "", CURRENT_USER, CURRENT_USER, 400), 
(SERVER_UTILITIES, None, CURRENT_USER, CURRENT_USER, 400), 

(SERVER_UTILITIES, USER_HOME + "/testsbatch.sh", "usernotexists", CURRENT_USER, 400), 
(SERVER_UTILITIES, USER_HOME + "/testsbatch.sh", "", CURRENT_USER, 200) , 
(SERVER_UTILITIES, USER_HOME + "/testsbatch.sh", None, CURRENT_USER, 200) , 

(SERVER_UTILITIES, USER_HOME + "/testsbatch.sh", CURRENT_USER, "groupnotexists", 400), 
(SERVER_UTILITIES, USER_HOME + "/testsbatch.sh", CURRENT_USER, "", 200), 
(SERVER_UTILITIES, USER_HOME + "/testsbatch.sh", CURRENT_USER, None, 200)
])
def test_chown(machine, targetPath, owner, group, expected_response_code, headers):
	data = {"targetPath": targetPath, "owner" : owner, "group": group}
	url = "{}/chown".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.put(url, headers=headers, data=data)
	print(resp.content)
	assert resp.status_code == expected_response_code




# Test ls command
@pytest.mark.parametrize("machine, targetPath, showhidden, expected_response_code", [ 
(SERVER_UTILITIES, USER_HOME + "/testsbatch.sh", "true", 200),
(SERVER_UTILITIES, USER_HOME + "/testsbatch.sh", "false", 200),
(SERVER_UTILITIES, USER_HOME + "/", "true", 200),
(SERVER_UTILITIES, USER_HOME + "/", "false", 200),
(SERVER_UTILITIES, "", "true", 200),
(SERVER_UTILITIES, "", "false", 200),

("someservernotavailable", USER_HOME + "/", "true", 400),
("", USER_HOME + "/testsbatch.sh", "true", 400),
(None, USER_HOME + "/testsbatch.sh", "true", 400),

(SERVER_UTILITIES, USER_HOME + "/dontexist/", "true", 400),
(SERVER_UTILITIES, "/notexists", "true", 400),
(SERVER_UTILITIES, "/etc/binfmt.d/", "true", 200), # empty folder
(SERVER_UTILITIES, None, "true", 400),
]  )
def test_list_directory(machine, targetPath, showhidden, expected_response_code, headers):
	params = {"targetPath": targetPath, "showhidden" : showhidden}
	url = "{}/ls".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, params=params)
	print(json.dumps(resp.json(),indent=2))
	print(resp.headers)
	assert resp.status_code == expected_response_code


# Test mkdir command
@pytest.mark.parametrize("machine, targetPath, p, expected_response_code", [ 
(SERVER_UTILITIES, USER_HOME + "/samplefolder1", None, 201),
(SERVER_UTILITIES, USER_HOME + "/samplefolder2", "true", 201),
(SERVER_UTILITIES, USER_HOME + "/samplefolder3", "false", 201),

(SERVER_UTILITIES, USER_HOME + "/d1/d2", "true", 201),
(SERVER_UTILITIES, USER_HOME + "/d3/d4", None, 400),
(SERVER_UTILITIES, USER_HOME + "/d5/d6", "false", 201),
(SERVER_UTILITIES, USER_HOME + "/d7/d8", "", 201),

("someservernotavailable", USER_HOME + "/samplefolder1", "true", 400),
("", USER_HOME + "/samplefolder1", "true", 400),
(None, USER_HOME + "/samplefolder1", "true", 400),

(SERVER_UTILITIES, "/createme", "true", 400), #forbidden
#(SERVER_UTILITIES, USER_HOME + "/\\0", "true", 400), #not admitted folder name
(SERVER_UTILITIES, "", "true", 400),
(SERVER_UTILITIES, None, "true", 400),

])
def test_make_directory(machine, targetPath, p, expected_response_code, headers):
	data = {"targetPath": targetPath, "p" : p}
	url = "{}/mkdir".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(url, headers=headers, data=data)
	print(resp.content)
	assert resp.status_code == expected_response_code  


# Test rename command
@pytest.mark.parametrize("machine, sourcePath, targetPath, expected_response_code", [
(SERVER_UTILITIES, USER_HOME + "/samplefolder1", USER_HOME + "/samplefolder1", 200), 
(SERVER_UTILITIES, USER_HOME + "/samplefolder1", USER_HOME + "/renFolder1", 200), 

("someservernotavailable", USER_HOME + "/samplefolder1", USER_HOME + "/samplefolder1", 400),
("", USER_HOME + "/samplefolder1", USER_HOME + "/samplefolder1", 400),
(None, USER_HOME + "/samplefolder1", USER_HOME + "/samplefolder1", 400),

(SERVER_UTILITIES, "notexists", USER_HOME + "/samplefolder1", 400),
(SERVER_UTILITIES, "", USER_HOME + "/samplefolder1", 400),
(SERVER_UTILITIES, None, USER_HOME + "/samplefolder1", 400),

(SERVER_UTILITIES, USER_HOME + "/samplefolder1", "", 400), 
(SERVER_UTILITIES, USER_HOME + "/samplefolder2", None, 400),
])
def test_rename(machine, sourcePath, targetPath, expected_response_code, headers):
	data = {"sourcePath": sourcePath, "targetPath" : targetPath}
	url = "{}/rename".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.put(url, headers=headers, data=data)
	print(resp.content)
	assert resp.status_code == expected_response_code  



# Test cp command
@pytest.mark.parametrize("machine, sourcePath, targetPath, expected_response_code", [ 
(SERVER_UTILITIES, USER_HOME + "/samplefolder1", USER_HOME + "/samplefolder1copy", 201),

("someservernotavailable", USER_HOME + "/sampleFolder", USER_HOME + "/samplefolder1copy", 400),
("", USER_HOME + "/samplefolder1", USER_HOME + "/samplefolder1copy", 400),
(None, USER_HOME + "/samplefolder1", USER_HOME + "/samplefolder1copy", 400),

(SERVER_UTILITIES, "", USER_HOME + "/sampleFolder1copy", 400),
(SERVER_UTILITIES, None, USER_HOME + "/sampleFolder1copy", 400),
(SERVER_UTILITIES, USER_HOME + "/sampleFolder1/notexists", USER_HOME + "/samplefolder1copy", 400),

(SERVER_UTILITIES, USER_HOME + "/samplefolder1", "", 400),
(SERVER_UTILITIES, USER_HOME + "/samplefolder1", None, 400),
(SERVER_UTILITIES, USER_HOME + "/samplefolder1", "/notvalid", 400),
(SERVER_UTILITIES, USER_HOME + "/samplefolder1", "/samplefolder1/d1/d2", 400),
] )
def test_copy(machine, sourcePath, targetPath, expected_response_code, headers):
	data = {"sourcePath": sourcePath, "targetPath" : targetPath}
	url = "{}/copy".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(url, headers=headers, data=data)
	print(resp.content)
	assert resp.status_code == expected_response_code  


# Test symlink command
@pytest.mark.parametrize("machine, targetPath, linkPath, expected_response_code", [
(SERVER_UTILITIES,  USER_HOME + "/testsbatch.sh", USER_HOME + "/samplefolder1/testlink", 201), 

("someservernotavailable",  USER_HOME + "/testsbatch.sh", USER_HOME + "/samplefolder1/testlink", 400),
("",  USER_HOME + "/testsbatch.sh", USER_HOME + "/samplefolder1/testlink", 400),
(None,  USER_HOME + "/testsbatch.sh", USER_HOME + "/samplefolder1/testlink", 400),

(SERVER_UTILITIES,  USER_HOME + "/notexists.txt", USER_HOME + "/samplefolder1/testlink", 400), 
(SERVER_UTILITIES,  "", USER_HOME + "/samplefolder1/testlink", 400), 
(SERVER_UTILITIES,  None, USER_HOME + "/samplefolder1/testlink", 400),

(SERVER_UTILITIES,  USER_HOME + "/testsbatch.sh", USER_HOME + "/foldernotexists/testlink", 400), 
(SERVER_UTILITIES,  USER_HOME + "/testsbatch.sh", "", 400), 
(SERVER_UTILITIES,  USER_HOME + "/testsbatch.sh", None, 400), 
])
def test_symlink(machine, targetPath, linkPath, expected_response_code, headers):
	data = {"targetPath": targetPath, "linkPath" : linkPath}
	url = "{}/symlink".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(url, headers=headers, data=data)
	print(resp.content)
	print(machine)
	assert resp.status_code == expected_response_code


#  Test rm command
@pytest.mark.parametrize("machine, targetPath, expected_response_code", [ 
(SERVER_UTILITIES, USER_HOME + "/samplefolder1/", 204),

("someservernotavailable", USER_HOME + "/sampleFolder/", 400),
("", USER_HOME + "/sampleFolder/", 400),
(None, USER_HOME + "/sampleFolder/", 400),

(SERVER_UTILITIES, USER_HOME + "/notexistingfolder/", 400),
(SERVER_UTILITIES, "", 400),
(SERVER_UTILITIES, None, 400),

])
def test_rm(machine, targetPath, expected_response_code, headers):
	data = {"targetPath": targetPath}
	url = "{}/rm".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.delete(url, headers=headers, data=data)
	print(resp.content)
	assert resp.status_code == expected_response_code 


# Test download command
@pytest.mark.parametrize("machine, sourcePath, expected_response_code", [ 
(SERVER_UTILITIES, USER_HOME + "/testsbatch.sh", 200), 

("someservernotavailable", USER_HOME + "/testsbatch.sh", 400),
("", USER_HOME + "/testsbatch.sh", 400),
(None, USER_HOME + "/testsbatch.sh", 400),

(SERVER_UTILITIES, USER_HOME + "/notexists.txt", 400), 
(SERVER_UTILITIES, "", 400),
(SERVER_UTILITIES, None, 400)
])
def test_download(machine, sourcePath, expected_response_code, headers):
	params = {"sourcePath": sourcePath}
	url = "{}/download".format(UTILITIES_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, params=params)
	assert resp.status_code == expected_response_code


# Test utilities microservice status
@host_environment_test
def test_status():
	url = "{}/status".format(UTILITIES_URL)
	resp = requests.get(url)
	assert resp.status_code == 200



if __name__ == '__main__':
	pytest.main()
