#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import logging
import os
import jwt
import stat
import datetime
import hashlib
import tempfile
import json
import functools
from flask import request, jsonify
import requests
import urllib
import base64
import io
import time

debug = os.environ.get("F7T_DEBUG_MODE", None)

AUTH_HEADER_NAME = 'Authorization'

realm_pubkey=os.environ.get("F7T_REALM_RSA_PUBLIC_KEY", '')
if realm_pubkey != '':
    # headers are inserted here, must not be present
    realm_pubkey = realm_pubkey.strip('\'"')   # remove '"'
    realm_pubkey = '-----BEGIN PUBLIC KEY-----\n' + realm_pubkey + '\n-----END PUBLIC KEY-----'
    realm_pubkey_type = os.environ.get("F7T_REALM_RSA_TYPE").strip('\'"')

AUTH_AUDIENCE = os.environ.get("F7T_AUTH_TOKEN_AUD", '').strip('\'"')
ALLOWED_USERS = os.environ.get("F7T_AUTH_ALLOWED_USERS", '').strip('\'"').split(";")
AUTH_REQUIRED_SCOPE = os.environ.get("F7T_AUTH_REQUIRED_SCOPE", '').strip('\'"')

AUTH_ROLE = os.environ.get("F7T_AUTH_ROLE", '').strip('\'"')


CERTIFICATOR_URL = os.environ.get("F7T_CERTIFICATOR_URL")
TASKS_URL = os.environ.get("F7T_TASKS_URL")

F7T_SSH_CERTIFICATE_WRAPPER = os.environ.get("F7T_SSH_CERTIFICATE_WRAPPER", None)

# OPA endpoint
OPA_USE = os.environ.get("F7T_OPA_USE",False)
OPA_URL = os.environ.get("F7T_OPA_URL","http://localhost:8181").strip('\'"')
POLICY_PATH = os.environ.get("F7T_POLICY_PATH","v1/data/f7t/authz").strip('\'"')

logging.getLogger().setLevel(logging.INFO)
logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',datefmt='%Y-%m-%d:%H:%M:%S',level=logging.INFO)


# checks JWT from Keycloak, optionally validates signature. It only receives the content of header's auth pair (not key:content)
def check_header(header):
    if debug:
        logging.info('debug: cscs_api_common: check_header: ' + header)

    # header = "Bearer ey...", remove first 7 chars
    try:
        if realm_pubkey == '':
            if not debug:
                logging.warning("WARNING: cscs_api_common: check_header: REALM_RSA_PUBLIC_KEY is empty, JWT tokens are NOT verified, setup is not set to debug.")
            decoded = jwt.decode(header[7:], verify=False)
        else:
            if AUTH_AUDIENCE == '':
                decoded = jwt.decode(header[7:], realm_pubkey, algorithms=realm_pubkey_type, options={'verify_aud': False})
            else:
                decoded = jwt.decode(header[7:], realm_pubkey, algorithms=realm_pubkey_type, audience=AUTH_AUDIENCE)
       
        if AUTH_REQUIRED_SCOPE != "":
            if AUTH_REQUIRED_SCOPE not in decoded["scope"].split():
                return False
        
        return True

    except jwt.exceptions.InvalidSignatureError:
        logging.error("JWT invalid signature", exc_info=True)
    except jwt.ExpiredSignatureError:
        logging.error("JWT token has expired", exc_info=True)
    except jwt.InvalidAudienceError:
        logging.error("JWT token invalid audience", exc_info=True)
    except jwt.exceptions.InvalidAlgorithmError:
        logging.error("JWT invalid signature algorithm", exc_info=True)
    except Exception:
        logging.error("Bad header or JWT, general exception raised", exc_info=True)

    return False

# returns username
def get_username(header):
    if debug:
        logging.info('debug: cscs_api_common: get_username: ' + header)
    # header = "Bearer ey...", remove first 7 chars
    try:
        if realm_pubkey == '':
            decoded = jwt.decode(header[7:], verify=False)
        else:
            decoded = jwt.decode(header[7:], realm_pubkey, algorithms=realm_pubkey_type, options={'verify_aud': False})
        # check if it's a service account token
        try:
            if AUTH_ROLE in decoded["realm_access"]["roles"]: 

                clientId = decoded["clientId"]
                username = decoded["resource_access"][clientId]["roles"][0]
                return username
            return decoded['preferred_username']
        except Exception:
            return decoded['preferred_username']

    except jwt.exceptions.InvalidSignatureError:
        logging.error("JWT invalid signature", exc_info=True)
    except jwt.ExpiredSignatureError:
        logging.error("JWT token has expired", exc_info=True)
    except jwt.InvalidAudienceError:
        logging.error("JWT token invalid audience", exc_info=True)
    except jwt.exceptions.InvalidAlgorithmError:
        logging.error("JWT invalid signature algorithm", exc_info=True)
    except Exception:
        logging.error("Bad header or JWT, general exception raised", exc_info=True)

    return None

# function to check if pattern is in string
def in_str(stringval,words):
    try:
        stringval.index(words)
        return True
    except ValueError:
        return False


# SSH certificates creation
# returns pub key certificate name
def create_certificate(auth_header, cluster_name, cluster_addr,  command=None, options=None, exp_time=None):
    """
    Args:
      cluster_name = public name of system to be executed
      cluster_addr = private DNS or IP of the system
      command = command to be executed with the certificate (required)
      option = parameters and options to be executed with {command}
      exp_time = expiration time for SSH certificate
    """

    if debug:
        username = get_username(auth_header)
        logging.info(f"Create certificate for user {username}")

    reqURL = f"{CERTIFICATOR_URL}/?cluster={cluster_name}&addr={cluster_addr}"

    if command:
        logging.info(f"\tCommand: {command}")
        reqURL += "&command=" + base64.urlsafe_b64encode(command.encode()).decode()
        if options:
            logging.info(f"\tOptions: {options}")
            reqURL += "&option=" + base64.urlsafe_b64encode(options.encode()).decode()
            if exp_time:
                logging.info(f"\tExpiration: {exp_time} [s]")
                reqURL += f"&exptime={exp_time}"
    else:
        logging.error('Tried to create certificate without command')
        return [None, 1, 'Internal error']

    logging.info(f"Request: {reqURL}")

    try:
        resp = requests.get(reqURL, headers={AUTH_HEADER_NAME: auth_header})

        if not resp.ok:
            return [None, resp.status_code, resp.json()["description"]]

        jcert = resp.json()

        # create temp dir to store certificate for this request
        td = tempfile.mkdtemp(prefix="dummy")

        os.symlink(os.getcwd() + "/user-key.pub", td + "/user-key.pub")  # link on temp dir
        os.symlink(os.getcwd() + "/user-key", td + "/user-key")  # link on temp dir
        certf = open(td + "/user-key-cert.pub", 'w')
        certf.write(jcert["certificate"])
        certf.close()
        # stat.S_IRUSR -> owner has read permission
        os.chmod(td + "/user-key-cert.pub", stat.S_IRUSR)

        # keys: [pub_cert, pub_key, priv_key, temp_dir]
        return [td + "/user-key-cert.pub", td + "/user-key.pub", td + "/user-key", td]
    except URLError as ue:
        logging.error(f"({ue.errno}) -> {ue.strerror}", exc_info=True)
        return [None, ue.errno, ue.strerror]
    except IOError as ioe:
        logging.error(f"({ioe.errno}) -> {ioe.strerror}", exc_info=True)
        return [None, ioe.errno, ioe.strerror]
    except Exception as e:
        logging.error(f"({type(e)}) -> {e}", exc_info=True)
        return [None, -1, e]



# execute remote commands with Paramiko:
def exec_remote_command(auth_header, system_name, system_addr, action, file_transfer=None, file_content=None):

    import paramiko, socket

    logging.info('debug: cscs_common_api: exec_remote_command: system name: ' + system_name + '  -  action: ' + action)

    if file_transfer == "storage_cert":
        # storage is using a previously generated cert, save cert list from content
        # cert_list: list of 4 elements that contains
        #   [0] path to the public certificate
        #   [1] path to the public key for user
        #   [2] path to the priv key for user
        #   [3] path to the dir containing 3 previous files
        cert_list = file_content
        username = auth_header
    else:
        # get certificate:
        # if OK returns: [pub_cert, pub_key, priv_key, temp_dir]
        # if FAILED returns: [None, errno, strerror]
        cert_list = create_certificate(auth_header, system_name, system_addr, command=action)

        if cert_list[0] == None:
            result = {"error": cert_list[1], "msg": cert_list[2]}
            return result

        username = get_username(auth_header)


    [pub_cert, pub_key, priv_key, temp_dir] = cert_list

    # -------------------
    # remote exec with paramiko
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ipaddr = system_addr.split(':')
        host = ipaddr[0]
        if len(ipaddr) == 1:
            port = 22
        else:
            port = int(ipaddr[1])

        client.connect(hostname=host, port=port,
                       username=username,
                       key_filename=pub_cert,
                       allow_agent=False,
                       look_for_keys=False,
                       timeout=10)
        logging.info(f"F7T_SSH_CERTIFICATE_WRAPPER: {F7T_SSH_CERTIFICATE_WRAPPER}")
        if F7T_SSH_CERTIFICATE_WRAPPER:
            # read cert to send it as a command to the server
            with open(pub_cert, 'r') as cert_file:
               cert = cert_file.read().rstrip("\n")  # remove newline at the end
            action = cert

        stdin, stdout, stderr = client.exec_command(action)

        if file_transfer == "upload":
            # uploads use "cat", so write to stdin
            stdin.channel.sendall(file_content)
            stdin.channel.shutdown_write()
            #stdin.channel.close()

        output = ""
        error = ""
        finished = 0

        stderr_errno = -2
        stdout_errno = -2
        stderr_errda = ""
        stdout_errda = ""

        
	# poll process status since directly using recv_exit_status() could result
        # in a permanent hang when remote output is larger than the current Transport or session’s window_size 
        while True:
            if stderr.channel.exit_status_ready():
                logging.info("stderr channel exit status ready") 
                stderr_errno = stderr.channel.recv_exit_status()
                endtime = time.time() + 30
                eof_received = True
                while not stderr.channel.eof_received:
                    # time.sleep(0.5)
                    if time.time() > endtime:
                        stderr.channel.close()
                        eof_received = False
                        break
                if eof_received:
                    error = "".join(stderr.readlines())
                    # error = stderr.read()
                    # clean "tput: No ..." lines at error output
                    stderr_errda = clean_err_output(error)
                break
            # else:
            #     time.sleep(5)

        #for i in range(0,10):
        while True:
            if stdout.channel.exit_status_ready():
                logging.info("stdout channel exit status ready") 
                stdout_errno = stdout.channel.recv_exit_status()
                endtime = time.time() + 30
                eof_received = True
                while not stdout.channel.eof_received:
                    # time.sleep(0.5)
                    if time.time() > endtime:
                        stdout.channel.close()
                        eof_received = False
                        break
                if eof_received:                    
                    output = "".join(stdout.readlines())
                    # error = stderr.read() it hangs
                    # clean "tput: No ..." lines at error output
                    stdout_errda = clean_err_output(output)
                break
            # else:
            #     time.sleep(5)


        if file_transfer == "download":
            outlines = output
        else:
            # replace newlines with $ for parsing
            outlines = output.replace('\n', '$')[:-1]

        logging.info(f"sdterr: ({stderr_errno}) --> {stderr_errda}")
        logging.info(f"stdout: ({stdout_errno}) --> {stdout_errda}")
        logging.info(f"sdtout: ({stdout_errno}) --> {outlines}")

        # TODO: change precedence of error, because in /xfer-external/download this gives error and it s not an error
        if stderr_errno == 0:
            if stderr_errda and not in_str(stderr_errda,"Could not chdir to home directory"):
                result = {"error": 0, "msg": stderr_errda}
            else:
                result = {"error": 0, "msg": outlines}
        elif stderr_errno > 0:
            result = {"error": stderr_errno, "msg": stderr_errda}
        elif len(stderr_errda) > 0:
            result = {"error": 1, "msg": stderr_errda}
        elif stdout_errno == -2:
            result = {"error": -2, "msg": "Receive ready timeout exceeded"}
        elif stderr_errno == -1:
            result = {"error": -1, "msg": "No exit status was provided by the server"}

    # first if paramiko exception raise
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        logging.error(type(e), exc_info=True)
        if e.errors:
            for k, v in e.errors.items():
                logging.error(f"errorno: {v.errno}")
                logging.error(f"strerr: {v.strerror}")
                result = {"error": v.errno, "msg": v.strerror}

    except socket.gaierror as e:
        logging.error(type(e), exc_info=True)
        logging.error(e.errno)
        logging.error(e.strerror)
        result = {"error": e.errno, "msg": e.strerror}

    except paramiko.ssh_exception.SSHException as e:
        logging.error(type(e), exc_info=True)
        logging.error(e)
        result = {"error": 1, "msg": str(e)}

    # second: time out
    except socket.timeout as e:
        logging.error(type(e), exc_info=True)
        # timeout has not errno
        logging.error(e)
        result = {"error": 1, "msg": e.strerror}

    except Exception as e:
        logging.error(type(e), exc_info=True)
        result = {"error": 1, "msg": str(e)}

    finally:
        client.close()
        os.remove(pub_cert)
        os.remove(pub_key)
        os.remove(priv_key)
        os.rmdir(temp_dir)

    logging.info(f"Result returned: {result['msg']}")
    return result


# clean TERM errors on stderr
# resaon: some servers produces this error becuase don't set a TERM
def clean_err_output(tex):
    lines = ""

    # python3 tex comes as a byte object, needs to be decoded to a str
    #tex = tex.decode('utf-8')

    for t in tex.split('\n'):
        if t != 'tput: No value for $TERM and no -T specified':
            lines += t

    return lines


def parse_io_error(retval, operation, path):
    """
    As command ended with error, create message to return to user
    Args: retval (from exec_remote_command)
          operation, path:
    return:
        jsonify('error message'), error_code (4xx), optional_header
    """
    header = ''
    if retval["error"] == 13:
        # IOError 13: Permission denied
        header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
    elif retval["error"] == 2:
        # IOError 2: no such file
        header = {"X-Invalid-Path": f"{path} is invalid."}
    elif retval["error"] == -2:
        # IOError -2: name or service not known
        header = {"X-Machine-Not-Available": "Machine is not available"}
    elif retval["error"] == 118:
        header = {"X-Permission-Denied": "Internal SSH error"}
    elif in_str(retval["msg"],"Permission") or in_str(retval["msg"],"OPENSSH"):
        header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}

    return jsonify(description = f"Failed to {operation}"), 400, header



# function to call create task entry API in Queue FS, returns task_id for new task
def create_task(auth_header,service=None):

    # returns {"task_id":task_id}
    # first try to get up task microservice:
    try:
        # X-Firecrest-Service: service that created the task
        req = requests.post(f"{TASKS_URL}/",
                           headers={AUTH_HEADER_NAME: auth_header, "X-Firecrest-Service":service})

    except requests.exceptions.ConnectionError as e:
        logging.error(type(e), exc_info=True)
        logging.error(e)
        return -1

    if req.status_code != 201:
        return -1

    logging.info(json.loads(req.content))
    resp = json.loads(req.content)
    task_id = resp["hash_id"]

    return task_id


# function to call update task entry API in Queue FS
def update_task(task_id, auth_header, status, msg = None, is_json=False):

    logging.info(f"Update {TASKS_URL}/{task_id} -> status: {status}")    

    if is_json:
        data = {"status": status, "msg": msg}
        req = requests.put(f"{TASKS_URL}/{task_id}",
                            json=data, headers={AUTH_HEADER_NAME: auth_header})
    else:
        data = {"status": status, "msg": msg}
        req = requests.put(f"{TASKS_URL}/{task_id}",
                            data=data, headers={AUTH_HEADER_NAME: auth_header})

    resp = json.loads(req.content)

    return resp

# function to call update task entry API in Queue FS
def expire_task(task_id,auth_header,service):

    logging.info(f"{TASKS_URL}/expire/{task_id}")


    req = requests.post(f"{TASKS_URL}/expire/{task_id}",
                            headers={AUTH_HEADER_NAME: auth_header, "X-Firecrest-Service": service})

    # resp = json.loads(req.content)

    if not req.ok:
        logging.info(req.json())
        return False

    return True

    
    

# function to check task status:
def get_task_status(task_id,auth_header):

    logging.info(f"{TASKS_URL}/{task_id}")

    try:
        retval = requests.get(f"{TASKS_URL}/{task_id}",
                           headers={AUTH_HEADER_NAME: auth_header})

        if retval.status_code != 200:
            return -1

        data = retval.json()
        logging.info(data["task"]["status"])

        try:
            return data["task"]["status"]
        except KeyError as e:
            logging.error(e)
            return -1

    except requests.exceptions.ConnectionError as e:
        logging.error(type(e), exc_info=True)
        logging.error(e)
        return -1


# checks if {path} is a valid file (exists and user in {auth_header} has read permissions)
def is_valid_file(path, auth_header, system_name, system_addr):

    # checks user accessibility to path using head command with 0 bytes
    action = f"head -c 1 -- {path} > /dev/null"

    retval = exec_remote_command(auth_header,system_name, system_addr,action)

    logging.info(retval)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            return {"result":False, "headers":{"X-Machine-Not-Available":"Machine is not available"} }
            

        if retval["error"] == 124:
            return {"result":False, "headers":{"X-Timeout": "Command has finished with timeout signal"}}
            

        # error no such file
        if in_str(error_str,"No such file"):
            return {"result":False, "headers":{"X-Invalid-Path": "{path} is an invalid path.".format(path=path)}}
                

        # permission denied
        if in_str(error_str,"Permission denied") or in_str(error_str,"OPENSSH"):
            return {"result":False, "headers":{"X-Permission-Denied": "User does not have permissions to access machine or path"}}

        if in_str(error_str, "directory"):
            return {"result":False, "headers":{"X-A-Directory": "{path} is a directory".format(path=path)}}  

        return {"result":False, "headers":{"X-Error": retval["msg"]}}

    return {"result":True}


    
# checks if {path} is a valid directory
# 'path' should exists and be accesible to the user (write permissions)
#
def is_valid_dir(path, auth_header, system_name, system_addr):

    # create an empty file for testing path accesibility
    # test file is a hidden file and has a timestamp in order to not overwrite other files created by user
    # after this, file should be deleted

    
    timestamp = datetime.datetime.today().strftime("%Y-%m-%dT%H:%M:%S.%f")
    # using a hash 
    hashedTS  =  hashlib.md5()
    hashedTS.update(timestamp.encode("utf-8"))

    tempFileName = f".firecrest.{hashedTS.hexdigest()}"

    action = f"touch -- {path}/{tempFileName}"

    retval = exec_remote_command(auth_header,system_name, system_addr,action)

    logging.info(retval)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            return {"result":False, "headers":{"X-Machine-Not-Available":"Machine is not available"} }

        if retval["error"] == 124:
            return {"result":False, "headers":{"X-Timeout": "Command has finished with timeout signal"}}

        # error no such file
        if in_str(error_str,"No such file"):
            return {"result":False, "headers":{"X-Invalid-Path": "{path} is an invalid path.".format(path=path)}}

        # permission denied
        if in_str(error_str,"Permission denied") or in_str(error_str,"OPENSSH"):
            return {"result":False, "headers":{"X-Permission-Denied": "User does not have permissions to access machine or path"}}

        # not a directory
        if in_str(error_str,"Not a directory"):
            return {"result":False, "headers":{"X-Not-A-Directory": "{path} is not a directory".format(path=path)}}

        return {"result":False, "headers":{"X-Error": retval["msg"]}}    

    # delete test file created
    action = f"rm -- {path}/{tempFileName}"
    retval = exec_remote_command(auth_header,system_name, system_addr,action)


    return {"result":True}


# wrapper to check if AUTH header is correct
# decorator use:
#
# @app.route("/endpoint", methods=["GET","..."])
# @check_auth_header
# def function_that_check_header():
# .....
def check_auth_header(func):
    @functools.wraps(func)
    def wrapper_check_auth_header(*args, **kwargs):
        try:
            auth_header = request.headers[AUTH_HEADER_NAME]
        except KeyError:
            logging.error("No Auth Header given")
            return jsonify(description="No Auth Header given"), 401
        if not check_header(auth_header):
            return jsonify(description="Invalid header"), 401

        return func(*args, **kwargs)
    return wrapper_check_auth_header


# check user authorization on endpoint
# using Open Policy Agent
# 
# use:
# check_user_auth(username,system)
def check_user_auth(username,system):

    # check if OPA is active
    if OPA_USE:
        try: 
            input = {"input":{"user": f"{username}", "system": f"{system}"}}
            #resp_opa = requests.post(f"{OPA_URL}/{POLICY_PATH}", json=input)
            logging.info(f"{OPA_URL}/{POLICY_PATH}")

            resp_opa = requests.post(f"{OPA_URL}/{POLICY_PATH}", json=input)

            logging.info(resp_opa.content)

            if resp_opa.json()["result"]["allow"]:
                logging.info(f"User {username} authorized by OPA")
                return {"allow": True, "description":f"User {username} authorized", "status_code": 200 }
            else:
                logging.error(f"User {username} NOT authorized by OPA")
                return {"allow": False, "description":f"User {username} not authorized in {system}", "status_code": 401}                
        except requests.exceptions.RequestException as e:
            logging.error(e.args)
            return {"allow": False, "description":"Authorization server error", "status_code": 404} 
    
    return {"allow": True, "description":"Authorization method not active", "status_code": 200 }


# Checks each paramiko command output on a error execution
# error_str: strerr (or strout) of the command
# error_code: errno of the command
# service_msg: service output in the "description" json response
def check_command_error(error_str, error_code, service_msg):

    if error_code == -2:
        header = {"X-Machine-Not-Available": "Machine is not available"}
        return {"description": service_msg, "status_code": 400, "header": header}

    if error_code == 113:
        header = {"X-Machine-Not-Available":"Machine is not available"}
        return {"description": service_msg, "status_code": 400, "header": header}

    if error_code == 124:
        header = {"X-Timeout": "Command has finished with timeout signal"}
        return {"description": service_msg, "status_code": 400, "header": header}

    # When certificate doesn't match SSH configuration
    if in_str(error_str,"OPENSSH"):
        header = {"X-Permission-Denied": "User does not have permissions to access machine"}
        return {"description": service_msg, "status_code": 400, "header": header}

    if in_str(error_str,"cannot access"):
        header={"X-Invalid-Path":"path is an invalid path"}
        return {"description": service_msg, "status_code": 400, "header": header}

    if in_str(error_str,"cannot open"):
        header = {"X-Permission-Denied": "User does not have permissions to access path"}
        return {"description":service_msg, "status_code": 400, "header": header}

    if in_str(error_str,"No such file"):
        if in_str(error_str,"cannot stat"):
            header={"X-Not-Found":"sourcePath not found"}
            return {"description": service_msg, "status_code": 400, "header": header}

        # copy: cannot create, rename: cannot move
        if in_str(error_str, "cannot create") or in_str(error_str,"cannot move"):
            header = {"X-Invalid-Path": "sourcePath and/or targetPath are invalid paths"}
            return {"description": service_msg, "status_code": 400, "header": header}

        if in_str(error_str,"cannot remove"):
            header = {"X-Invalid-Path": "path is an invalid path."}
            return {"description": service_msg, "status_code": 400, "header": header}

        header={"X-Invalid-Path":"path is an invalid path"}
        return {"description": service_msg, "status_code": 400, "header": header}

    if in_str(error_str,"Permission denied"):
        header = {"X-Permission-Denied": "User does not have permissions to access path"}
        return {"description": service_msg, "status_code": 400, "header": header}

    if in_str(error_str,"directory"):
        header = {"X-A-Directory": "path is a directory, can't checksum directories"}
        return {"description": service_msg, "status_code": 400, "header": header}
    
    # if already exists, not overwrite (-i)
    if in_str(error_str,"overwrite"):
        header = {"X-Exists": "targetPath already exists"}
        return {"description": service_msg, "status_code": 400, "header": header}

    if in_str(error_str,"not permitted"):
        header = {"X-Permission-Denied": "User does not have permissions to access path"}
        return {"description": service_msg, "status_code": 400, "header": header}

    if in_str(error_str,"invalid group"):
        header = {"X-Invalid-Group": "group is an invalid group"}
        return {"description": service_msg, "status_code": 400, "header": header}

    if in_str(error_str,"invalid user"):
        header = {"X-Invalid-Owner": "owner is an invalid user"}
        return {"description": service_msg, "status_code": 400, "header": header}
    
    if in_str(error_str, "invalid mode"):
        header = {"X-Invalid-Mode": "mode is an invalid mode"}
        return {"description": service_msg, "status_code": 400, "header": header}

    if in_str(error_str, "read permission"):
        header = {"X-Permission-Denied": "User does not have permissions to access path"}
        return {"description": service_msg, "status_code": 400, "header": header}
    header = {"X-Error": error_str}
    return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}