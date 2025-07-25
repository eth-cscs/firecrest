#
#  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import logging
import logging.config
from logging import Logger
from logging.handlers import TimedRotatingFileHandler
from pythonjsonlogger import jsonlogger
import os
import jwt
import stat
import datetime
import hashlib
import tempfile
import json
import functools
from flask import request, jsonify, g
import requests
import base64
import re
import time
import threading
import sys
from time import sleep

from typing import Union


# Checks if an environment variable injected to F7T is a valid True value
# var <- object
# returns -> boolean
def get_boolean_var(var):
    # ensure variable to be a string
    var = str(var)
    # True, true or TRUE
    # Yes, yes or YES
    # 1

    return var.upper() == "TRUE" or var.upper() == "YES" or var == "1"


# Checks if an environment variable injected to F7T is a valid True value
# var <- object
# returns -> value | None
def get_null_var(var):
    _var = str(var).upper()

    return None if (len(_var) == 0 or _var == "NONE" or _var == "NULL") else var


DEBUG_MODE = get_boolean_var(os.environ.get("F7T_DEBUG_MODE", False))

ENABLE_LOG_KIBANA = get_boolean_var(os.environ.get("F7T_LOG_KIBANA", False))

LOG_TYPE = os.environ.get("F7T_LOG_TYPE", "file").strip('\'"')

LOG_PATH = os.environ.get("F7T_LOG_PATH", '/var/log').strip('\'"')

AUTH_HEADER_NAME = os.environ.get("F7T_AUTH_HEADER_NAME", "Authorization")

AUTH_PUBLIC_KEYS = os.environ.get("F7T_AUTH_PUBLIC_KEYS",
                                       "").strip('\'"').split(";")
AUTH_ALGORITHMS = os.environ.get("F7T_AUTH_ALGORITHMS",
                                "RS256").strip('\'"').split(";")

is_public_key_set = False

if len(AUTH_PUBLIC_KEYS) != 0:
    auth_pubkeys = []
    is_public_key_set = True
    # headers are inserted here, must not be present
    for i in range(len(AUTH_PUBLIC_KEYS)):

        auth_pubkey = {}

        auth_pubkey["pubkey"] = f"-----BEGIN PUBLIC KEY-----\n{AUTH_PUBLIC_KEYS[i]}\n-----END PUBLIC KEY-----"
        auth_pubkey["alg"] = AUTH_ALGORITHMS[i]

        auth_pubkeys.append(auth_pubkey)

AUTH_AUDIENCE = os.environ.get("F7T_AUTH_TOKEN_AUD", '').strip('\'"')
AUTH_REQUIRED_SCOPE = os.environ.get("F7T_AUTH_REQUIRED_SCOPE", '').strip('\'"')

AUTH_ROLE = os.environ.get("F7T_AUTH_ROLE", '').strip('\'"')

### SSL parameters
SSL_ENABLED = get_boolean_var(os.environ.get("F7T_SSL_ENABLED", True))
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_KEY = os.environ.get("F7T_SSL_KEY", "")

F7T_SCHEME_PROTOCOL = ("https" if SSL_ENABLED else "http")

# Internal microservices communication
## certificator
CERTIFICATOR_HOST = os.environ.get("F7T_CERTIFICATOR_HOST","127.0.0.1")
CERTIFICATOR_PORT = os.environ.get("F7T_CERTIFICATOR_PORT","5000")
CERTIFICATOR_URL = f"{F7T_SCHEME_PROTOCOL}://{CERTIFICATOR_HOST}:{CERTIFICATOR_PORT}"
## tasks
TASKS_HOST = os.environ.get("F7T_TASKS_HOST","127.0.0.1")
TASKS_PORT = os.environ.get("F7T_TASKS_PORT","5003")
TASKS_URL = f"{F7T_SCHEME_PROTOCOL}://{TASKS_HOST}:{TASKS_PORT}"

SSH_CERTIFICATE_WRAPPER_ENABLED = get_boolean_var(os.environ.get("F7T_SSH_CERTIFICATE_WRAPPER_ENABLED", False))

# Fobidden chars on user path/parameters: wihtout scapes: < > | ; " ' & \ ( ) x00-x1F \x60
#   r'...' specifies it's a regular expression with special treatment for \
FORBIDDEN_INPUT_CHARS = r'[\<\>\|\;\"\'\&\\\(\)\x00-\x1F\x60]'


#max file size for upload/download in MB, internally used in bytes
UTILITIES_MAX_FILE_SIZE_BYTES = int(os.environ.get("F7T_UTILITIES_MAX_FILE_SIZE", "5")) * 1024 * 1024

# OPA endpoint
OPA_ENABLED = get_boolean_var(os.environ.get("F7T_OPA_ENABLED",False))
OPA_URL = os.environ.get("F7T_OPA_URL","http://localhost:8181").strip('\'"')
OPA_POLICY_PATH = os.environ.get("F7T_OPA_POLICY_PATH","v1/data/f7t/authz").strip('\'"')

HOME_ENABLED = get_boolean_var(
    os.environ.get("F7T_HOME_ENABLED", True))

### SSH key paths
PUB_USER_KEY_PATH = os.environ.get("F7T_PUB_USER_KEY_PATH", "/user-key.pub")
PRIV_USER_KEY_PATH = os.environ.get("F7T_PRIV_USER_KEY_PATH", "/user-key")

TRACER_HEADER = "uber-trace-id"


# checks JWT from Keycloak, optionally validates signature. It only receives the content of header's auth pair (not key:content)
def check_header(header):

    # header = remove the "Bearer " string
    token = header.replace("Bearer ", "")
    decoding_result = False
    decoding_reason = ""

    if not is_public_key_set:
        if not DEBUG_MODE:
            logging.warning("REALM_RSA_PUBLIC_KEY is empty, JWT tokens " +
                            " are NOT verified, setup is not set to debug.")

        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            decoding_result = True

            # only check for expired signature or exceptions for this case
        except jwt.exceptions.ExpiredSignatureError:
            decoding_reason = "JWT token has expired"
            logging.error(decoding_reason, exc_info=True)
        except Exception:
            decoding_reason = "Bad header or JWT, general exception raised"
            logging.error(decoding_reason, exc_info=True)
    else:
        # iterates over the list of public keys
        for auth_pubkey in auth_pubkeys:
            if DEBUG_MODE:
                logging.debug(f"Trying decoding with Public Key ({i})" +
                              f"[...{auth_pubkey['pubkey'][71:81]}...] ...")
            try:
                if AUTH_AUDIENCE == '':
                    decoded = jwt.decode(token, auth_pubkey["pubkey"],
                                         algorithms=[auth_pubkey["alg"]],
                                         options={'verify_aud': False})
                else:
                    decoded = jwt.decode(token, auth_pubkey["pubkey"],
                                         algorithms=[auth_pubkey["alg"]],
                                         audience=AUTH_AUDIENCE)
                if DEBUG_MODE:
                    logging.info("Correctly decoded")

                # if all passes, it means the signature is valid
                decoding_result = True
                decoding_reason = ""

            except jwt.exceptions.InvalidSignatureError:
                decoding_reason = "JWT token has invalid signature"
                if DEBUG_MODE:
                    logging.debug(decoding_reason, exc_info=False)
                # try next key
                continue
            except jwt.exceptions.ExpiredSignatureError:
                decoding_reason = "JWT token has expired"
                logging.error(decoding_reason, exc_info=True)
            except jwt.exceptions.InvalidAudienceError:
                decoding_reason = "Invalid audience in JWT token"
                logging.error(decoding_reason, exc_info=True)
            except jwt.exceptions.InvalidAlgorithmError:
                decoding_reason = "JWT token has invalid signature algorithm"
                logging.error(decoding_reason, exc_info=True)
            except Exception:
                decoding_reason = "Bad header or JWT, general exception raised"
                logging.error(decoding_reason, exc_info=True)

            # either token is valid or exception indicates a problem
            break

    if DEBUG_MODE:
        logging.debug(f"Result: {decoding_result}. Reason: {decoding_reason}")

    # if token was decoded, then check if required scope is present
    if AUTH_REQUIRED_SCOPE != "" and decoding_result:
        if AUTH_REQUIRED_SCOPE not in decoded["scope"].split():
            decoding_result = False
            decoding_reason = f"Scope '{AUTH_REQUIRED_SCOPE}' wasn't found in JWT"
            logging.error(decoding_reason, exc_info=True)

    return {"result": decoding_result, "reason": decoding_reason}


def get_username(header):
    # receive the header, and extract the username from the token
    # returns username
    # header = remove the "Bearer " string
    token = header.replace("Bearer ", "")
    decoding_result = False
    decoding_reason = ""

    # does FirecREST check the signature of the token?
    if not is_public_key_set:
        if not DEBUG_MODE:
            logging.warning("REALM_RSA_PUBLIC_KEY is empty, JWT tokens are " +
                            "NOT verified, setup is not set to debug.")

        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            decoding_result = True

            # only check for expired signature or exception for this case
        except jwt.exceptions.ExpiredSignatureError:
            logging.error("JWT token has expired", exc_info=True)
            return {"result": False, "reason": "JWT token has expired",
                    "username": None}
        except Exception:
            logging.error("Bad header or JWT, general exception raised",
                          exc_info=True)
            return {"result": False,
                    "reason": "Bad header or JWT, general exception raised",
                    "username": None}

    else:
        # iterates over the list of public keys
        for auth_pubkey in auth_pubkeys:
            if DEBUG_MODE:
                logging.debug(f"Trying decoding with Public Key ({i})" +
                              f"[...{auth_pubkey['pubkey'][71:81]}...] ...")
            try:
                if AUTH_AUDIENCE == '':
                    decoded = jwt.decode(token, auth_pubkey["pubkey"],
                                         algorithms=[auth_pubkey["alg"]],
                                         options={'verify_aud': False})
                else:
                    decoded = jwt.decode(token, auth_pubkey["pubkey"],
                                         algorithms=[auth_pubkey["alg"]],
                                         audience=AUTH_AUDIENCE)
                if DEBUG_MODE:
                    logging.debug("Correctly decoded")

                # if token is correctly decoded, exit the loop
                decoding_result = True
                decoding_reason = ""

            except jwt.exceptions.InvalidSignatureError:
                decoding_reason = "JWT token has invalid signature"
                if DEBUG_MODE:
                    logging.debug(decoding_reason, exc_info=False)
                # try next key
                continue
            except jwt.exceptions.ExpiredSignatureError:
                decoding_reason = "JWT token has expired"
                logging.error(decoding_reason, exc_info=True)
            except jwt.exceptions.InvalidAudienceError:
                decoding_reason = "Invalid audience in JWT token"
                logging.error(decoding_reason, exc_info=True)
            except jwt.exceptions.InvalidAlgorithmError:
                decoding_reason = "JWT token has invalid signature algorithm"
                logging.error(decoding_reason, exc_info=True)
            except Exception:
                decoding_reason = "Bad header or JWT, general exception raised"
                logging.error(decoding_reason, exc_info=True)

            # either token is valid or exception indicates a problem
            break

    if not decoding_result:
        return {"result": decoding_result, "reason": decoding_reason, "username": None}

    # with decoded token, checks if it belongs to a client_credentials token structure
    try:
        if AUTH_ROLE in decoded["realm_access"]["roles"]:
            clientId = decoded["clientId"]
            username = decoded["resource_access"][clientId]["roles"][0]
            return {"result": True, "reason":"", "username": username}
        return {"result": True, "reason":"", "username": decoded['preferred_username']}
    except Exception:
        return {"result": True, "reason":"", "username": decoded['preferred_username']}

def in_str(stringval, substring):
    if isinstance(stringval, str):
        return substring in stringval
    else:
        return False


# SSH certificates creation
# returns pub key certificate name
def create_certificate(headers, cluster_name, cluster_addr, command=None, options=None, exp_time=None):
    """
    Args:
      cluster_name = public name of system to be executed
      cluster_addr = private DNS or IP of the system
      command = command to be executed with the certificate (required)
      option = parameters and options to be executed with {command}
      exp_time = expiration time for SSH certificate
    """

    reqURL = f"{CERTIFICATOR_URL}/?cluster={cluster_name}&addr={cluster_addr}"

    if command:
        logging.info(f"\tCommand: {command}")
        reqURL += "&command=" + base64.urlsafe_b64encode(command.encode()).decode()
        if options:
            logging.info(f"\tOptions (truncated): {options:80}")
            reqURL += "&option=" + base64.urlsafe_b64encode(options.encode()).decode()
            if exp_time:
                logging.info(f"\tExpiration: {exp_time} [s]")
                reqURL += f"&exptime={exp_time}"
    else:
        logging.error('Tried to create certificate without command')
        return [None, 1, 'Internal error']

    if DEBUG_MODE:
        is_username_ok = get_username(headers[AUTH_HEADER_NAME])
        if is_username_ok["result"] == False:
            logging.error(f"Cannot create certificate. Reason: {is_username_ok['reason']}")
            return [None, 401, is_username_ok["reason"] ]
        if options:
            # may contain Storage URL
            logging.debug(f"\tOptions (complete): {options}")
        logging.debug(f"Request URL: {reqURL}")

    try:
        resp = requests.get(reqURL, headers=headers, verify= (SSL_CRT if SSL_ENABLED else False) )

        if resp.status_code != 200:
            return [None, resp.status_code, resp.json()["description"]]

        jcert = resp.json()

        # create temp dir to store certificate for this request
        td = tempfile.mkdtemp(prefix="dummy")

        os.symlink(PUB_USER_KEY_PATH, f"{td}/user-key.pub")  # link on temp dir
        os.symlink(PRIV_USER_KEY_PATH, f"{td}/user-key")  # link on temp dir
        certf = open(f"{td}/user-key-cert.pub", 'w')
        certf.write(jcert["certificate"])
        certf.close()
        # stat.S_IRUSR -> owner has read permission
        os.chmod(f"{td}/user-key-cert.pub", stat.S_IRUSR)

        # keys: [pub_cert, pub_key, priv_key, temp_dir]
        return [f"{td}/user-key-cert.pub", f"{td}/user-key.pub", f"{td}/user-key", td]
    except requests.exceptions.SSLError as ssle:
        logging.error(f"(-2) -> {ssle}")
        logging.error(f"(-2) -> {ssle.strerror}")
        return [None, -2, ssle]
    except IOError as ioe:
        logging.error(f"({ioe.errno}) -> {ioe.strerror}", exc_info=True)
        return [None, ioe.errno, ioe.strerror]
    except Exception as e:
        logging.error(f"({type(e)}) -> {e}", exc_info=True)
        return [None, -1, e]


# execute remote commands with Paramiko:
def exec_remote_command(headers, system_name, system_addr, command, file_transfer=None, file_content=None, log_command="", trace_id=""):

    import paramiko, socket

    # Append trace ID if any
    if trace_id == "":
        action = command
    else:
        action = f"ID={trace_id} {command}"

    if file_transfer == "storage_cert":
        # storage is using a previously generated cert, save cert list from content
        # cert_list: list of 4 elements that contains
        #   [0] path to the public certificate
        #   [1] path to the public key for user
        #   [2] path to the priv key for user
        #   [3] path to the dir containing 3 previous files
        cert_list = file_content
        username = headers
    else:
        # get certificate:
        # if OK returns: [pub_cert, pub_key, priv_key, temp_dir]
        # if FAILED returns: [None, errno, strerror]
        cert_list = create_certificate(headers, system_name, system_addr, command=action)

        if cert_list[0] == None:
            result = {"error": cert_list[1], "msg": cert_list[2]}
            return result

        is_username_ok = get_username(headers[AUTH_HEADER_NAME])
        if not is_username_ok["result"]:
            return {"error": 1, "msg": is_username_ok["reason"]}

        username = is_username_ok["username"]

    [pub_cert, pub_key, priv_key, temp_dir] = cert_list
    # JSON FORMAT
    if ENABLE_LOG_KIBANA:
        KibanaLogger.get_logger().info({"machinename": system_name, "microservice": KibanaLogger.get_service(), "username": username, "command": log_command, "trace_id": trace_id, "message": command})
    else:
        logging.info(f'System name: {system_name} - username: {username} - action: {action}')
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
                       timeout=10,
                       disabled_algorithms={'keys': ['rsa-sha2-256', 'rsa-sha2-512']})

        tr = client.get_transport()
        tr.default_window_size= UTILITIES_MAX_FILE_SIZE_BYTES

        if SSH_CERTIFICATE_WRAPPER_ENABLED:
            if DEBUG_MODE:
                logging.debug("Using F7T_SSH_CERTIFICATE_WRAPPER_ENABLED option")

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
                logging.info(f"stderr channel exit status ready")
                stderr_errno = stderr.channel.recv_exit_status()
                endtime = time.time() + 30
                eof_received = True
                while not stderr.channel.eof_received:
                    # time.sleep(0.5)
                    if len(stderr.channel.in_buffer) >= stderr.channel.in_window_size:
                        return {"error": 1, "msg": f"Command output exceeded buffer limit ({tr.default_window_size})"}
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
                logging.info(f"stdout channel exit status ready")
                stdout_errno = stdout.channel.recv_exit_status()
                endtime = time.time() + 30
                eof_received = True
                while not stdout.channel.eof_received:
                    # time.sleep(0.5)
                    if len(stdout.channel.in_buffer) >= stdout.channel.in_window_size:
                        return {"error": 1, "msg": f"Command output exceeded buffer limit ({tr.default_window_size})"}
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
            outlines = output[:-1]

        # hiding success results from utilities/download, since output is the content of the file
        if file_transfer == "download":
            if stderr_errno !=0:
                logging.error(f"stderr: ({stderr_errno}) --> {stderr_errda}")
                logging.error(f"stdout: ({stdout_errno}) --> {stdout_errda}")
                logging.error(f"stdout: ({stdout_errno}) --> {outlines}")
            else:
                logging.info(f"stderr: ({stderr_errno}) --> Download OK (content hidden)")
                logging.info(f"stdout: ({stdout_errno}) --> Download OK (content hidden)")
        else:
            logging.info(f"stderr: ({stderr_errno}) --> {stderr_errda}")
            if DEBUG_MODE:
                logging.info(f"stdout: ({stdout_errno}) --> {stdout_errda}")
                logging.info(f"stdout: ({stdout_errno}) --> {outlines}")

        if stderr_errno == 0:
            if file_transfer == "download":
                result = {"error": 0, "msg": outlines}
            elif stderr_errda and not (in_str(stderr_errda, "Could not chdir to home directory") or
                                       in_str(stderr_errda, "scancel: Terminating job") or
                                       in_str(stderr_errda, "Use of the \"--environment\" option for \"sbatch\" is still considered")):
                result = {"error": 1, "msg": stderr_errda}
            elif in_str(stdout_errda, "No such file"): # in case that error is 0 and the msg is on the stdout (like with some file)
                result = {"error": 1, "msg": stdout_errda}
            elif in_str(stdout_errda, "no read permission"): # in case that error is 0 and the msg is on the stdout (like with some file)
                result = {"error": 1, "msg": stdout_errda}
            elif in_str(stdout_errda, "cannot open"): # in case that error is 0 and the msg is on the stdout (like with some file)
                result = {"error": 1, "msg": stdout_errda}
            # only in case of SLURM scheduler: stderr_errno == 0 always, and output (error or not) in stderr_errda
            elif in_str(stderr_errda, "scancel: Terminating job"):
                if in_str(stderr_errda, "error"):
                    result = {"error": 1, "msg": stderr_errda}
                else:
                    result = {"error": 0, "msg": stderr_errda}

            else:
                result = {"error": 0, "msg": outlines}
        elif stderr_errno != 0:
            # First solving specific errors
            if stderr_errno == 7:
                result = {"error": 7, "msg": "Failed to connect to staging area server"}
            elif stderr_errno == 124:
                result = {"error": 124, "msg": "Command has finished with timeout signal"}
            elif stdout_errno == -2:
                result = {"error": -2, "msg": "Receive ready timeout exceeded"}
            elif stderr_errno == -1:
                result = {"error": -1, "msg": "No exit status was provided by the server"}
            # solving error of $HOME not present
            # stderr_errda = "Could not chdir to home directory /users/eirinik: No such file or directory
            # ERROR: you must specify a project account (-A <account>)sbatch: error: cli_filter plugin terminated with error"
            if not HOME_ENABLED and in_str(stderr_errda, "Could not chdir to home directory"):
                # checking for 2nd 'directory' string (first is at index 33)
                # 2nd comes after username
                if DEBUG_MODE:
                    logging.debug(f"$HOME directory is not enabled"
                                  f" (F7T_HOME_ENABLED={HOME_ENABLED})")
                idx = stderr_errda.index("directory", 33)
                # len(directory) = 9
                result = {"error": stderr_errno, "msg": stderr_errda[idx+9:]}
            else:
                result = {"error": stderr_errno, "msg": stderr_errda or stdout_errda}
        elif len(stderr_errda) > 0:
            result = {"error": 1, "msg": stderr_errda}

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

    # hiding results from utilities/download, since output is the content of the file
    if file_transfer == "download" and stderr_errno == 0:
        logging.info(f"Result: status_code {result['error']} -> Utilities download")
    elif file_transfer == "download" and stderr_errno != 0:
        logging.error(f"Result: status_code {result['error']} -> {result['msg']}")
    else:
        if DEBUG_MODE:
            logging.debug(f"Result: status_code {result['error']} -> {result['msg']}")
        else:
            logging.info(f"Result: status_code {result['error']}")
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
    elif retval["error"] == -2 or retval["error"] == 113:
        # IOError -2: name or service not known
        header = {"X-Machine-Not-Available": "Machine is not available"}
    elif retval["error"] == 118:
        header = {"X-Permission-Denied": "Internal SSH error"}
    elif in_str(retval["msg"],"Permission") or in_str(retval["msg"],"OPENSSH"):
        header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}

    return jsonify(description = f"Failed to {operation}"), 400, header



# function to call create task entry API in Queue FS, returns task_id for new task
def create_task(headers, service=None, system=None, init_data=None) -> Union[str,int]:
    '''
    Creates an asynchronous task and returns the new task_id, if task creation fails returns -1

    Parameters:
    - headers (dict): HTTP headers from the initial call of the user (user identity data is taken from here)
    - service (Union[str,None]): name of the service where the task creation was started ("compute" or "storage")
    - system (Union[str,None]): name of the system which the task was started for
    - init_data (Union[dict,None]): initial data for the task creation

    Returns:
    - Union[str,int]: task ID of the newly created task, in case of fail returns -1
    '''

    # returns {"task_id":task_id}
    # first try to create a task:
    # this might fail due to server error,
    # here we're setting a retry policy before sending an error
    # due to ChunkedEncodingError exception
    retries = 5
    delay = 3
    for n in range(1, retries+1):
        try:
            # X-Firecrest-Service: service that created the task
            headers["X-Firecrest-Service"] = service
            headers["X-Machine-Name"] = system
            req = requests.post(f"{TASKS_URL}/", data={"init_data": init_data},
                                headers=headers,
                                verify=(SSL_CRT if SSL_ENABLED else False))
            break
        except requests.exceptions.ChunkedEncodingError as cee:
            if retries > n:
                logging.warning(f"Task creation warning: '{service}' is not "
                                "able to reach 'tasks'")
                logging.warning(type(cee), exc_info=True)
                logging.warning(f"We'll try {retries-n} more times.")
                logging.warning(f"Attempting in {delay} seconds...")
                sleep(delay)
                continue
            else:
                logging.error(f"Task creation error: '{service}' was not able "
                              "to reach 'tasks'")
                logging.error("All attempts have been exhausted. "
                              "Sending error message to user")
                logging.error(type(cee), exc_info=True)
                return -1

        except requests.exceptions.ConnectionError as ce:
            logging.error(f"Task creation error: '{service}' was not able "
                          "to reach 'tasks'")
            logging.error(type(ce), exc_info=True)
            logging.error(ce)
            return -1

        except Exception as e:
            logging.error(f"Task creation error")
            logging.error(type(e), exc_info=True)
            logging.error(e)
            return -1

    if req.status_code != 201:
        return -1

    if DEBUG_MODE:
        logging.info(json.loads(req.content))
    resp = json.loads(req.content)
    task_id = resp["hash_id"]

    return task_id


# function to call update task entry API in Queue FS
def update_task(task_id: str, headers: dict, status: str, msg:Union[str,dict,None]=None, is_json:bool=False) -> dict:
    '''
    Updates an asynchronous task information

    Parameters:
    - task_id (str): unique identifier of the async task
    - headers (dict): HTTP headers from the initial call of the user (user identity data is taken from here)
    - status (str): new status of the task
    - msg (Union[str,dict,None]): new data of the task
    - is_json (bool): True if the msg is coded as JSON

    Returns:
    - dict: response of the task microservice with the outcome of updating the task
    '''

    logging.info(f"Update {TASKS_URL}/{task_id} -> status: {status}")

    data = {"status": status, "msg": msg}
    if is_json:
        req = requests.put(f"{TASKS_URL}/{task_id}",
                            json=data, headers=headers, verify=(SSL_CRT if SSL_ENABLED else False))
    else:
        req = requests.put(f"{TASKS_URL}/{task_id}",
                            data=data, headers=headers, verify=(SSL_CRT if SSL_ENABLED else False))

    resp = json.loads(req.content)
    return resp


def expire_task(task_id, headers, service) -> bool:
    '''
    Set an expiration time to a task to be deleted in the persistence backend (expiration time will depend on the /tasks microservice)

    Parameters:
    - task_id (str): unique identifier of the async task
    - headers (dict): HTTP headers from the initial call of the user (user identity data is taken from here)
    - service (Union[str,None]): name of the service where the task creation was started ("compute" or "storage")

    Returns:
    - bool: True if the task has been expired correctly
    '''

    logging.info(f"{TASKS_URL}/expire/{task_id}")
    try:
        headers["X-Firecrest-Service"] = service
        req = requests.post(f"{TASKS_URL}/expire/{task_id}",
                            headers=headers, verify=(SSL_CRT if SSL_ENABLED else False))
    except Exception as e:
        logging.error(type(e))
        logging.error(e.args)

    if not req.ok:
        logging.info(req.json())
        return False

    return True

# Delete task (used only in /xfer-external/invalidate)
def delete_task(task_id, headers) -> bool:
    '''
    Mark a task to be deleted in the persistence backend immediatelly

    Parameters:
    - task_id (str): unique identifier of the async task
    - headers (dict): HTTP headers from the initial call of the user (user identity data is taken from here)

    Returns:
    - bool: True if the task has been deleted correctly
    '''

    logging.info(f"DELETE {TASKS_URL}/{task_id}")
    try:
        req = requests.delete(f"{TASKS_URL}/{task_id}",
                            headers=headers, verify=(SSL_CRT if SSL_ENABLED else False))
    except Exception as e:
        logging.error(type(e))
        logging.error(e.args)
        return False

    if not req.ok:
        logging.error(req.text)
        return False

    return True


# function to check task status:
def get_task_status(task_id, headers) -> Union[dict,int]:
    '''
    Return task status

    Parameters:
    - task_id (str): unique identifier of the async task
    - headers (dict): HTTP headers from the initial call of the user (user identity data is taken from here)

    Returns:
    - dict: with status information. If there is an error on the Tasks microservice, then returns -1
    '''

    logging.info(f"{TASKS_URL}/{task_id}")
    try:
        retval = requests.get(f"{TASKS_URL}/{task_id}",
                           headers=headers, verify=(SSL_CRT if SSL_ENABLED else False))
        if retval.status_code != 200:
            return -1

        data = retval.json()
        logging.info(data["task"]["status"])
        return data["task"]["status"]
    except Exception as e:
        logging.error(type(e), exc_info=True)
        logging.error(e)

    return -1


# checks if {path} is a valid file (exists and user in {auth_header} has read permissions)
def is_valid_file(path, headers, system_name, system_addr):

    ID = headers.get(TRACER_HEADER, '')
    # checks user accessibility to path using head command with 0 bytes
    action = f"head -c 1 -- '{path}' > /dev/null"
    retval = exec_remote_command(headers, system_name, system_addr, action, trace_id=ID, log_command="head")

    logging.info(retval)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            return {"result":False, "headers":{"X-Machine-Not-Available":"Machine is not available"} }


        if retval["error"] == 124:
            return {"result":False, "headers":{"X-Timeout": "Command has finished with timeout signal"}}


        # error no such file
        if in_str(error_str,"No such file"):
            return {"result":False, "headers":{"X-Invalid-Path": f"{path} is an invalid path."}}


        # permission denied
        if in_str(error_str,"Permission denied") or in_str(error_str,"OPENSSH"):
            return {"result":False, "headers":{"X-Permission-Denied": "User does not have permissions to access machine or path"}}

        if in_str(error_str, "directory"):
            return {"result":False, "headers":{"X-A-Directory": f"{path} is a directory"}}

        return {"result":False, "headers":{"X-Error": retval["msg"]}}

    return {"result":True}



# checks if {path} is a valid directory
# 'path' should exists and be accesible to the user (write permissions)
#
def is_valid_dir(path, headers, system_name, system_addr):

    # create an empty file for testing path accesibility
    # test file is a hidden file and has a timestamp in order to not overwrite other files created by user
    # after this, file should be deleted

    timestamp = datetime.datetime.today().strftime("%Y-%m-%dT%H:%M:%S.%f")
    # using a hash
    hashedTS  =  hashlib.md5()
    hashedTS.update(timestamp.encode("utf-8"))

    tempFileName = f".firecrest.{hashedTS.hexdigest()}"
    ID = headers.get(TRACER_HEADER, '')
    action = f"touch -- '{path}/{tempFileName}'"
    retval = exec_remote_command(headers, system_name, system_addr, action, trace_id=ID, log_command="touch")

    logging.info(retval)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            return {"result":False, "headers":{"X-Machine-Not-Available":"Machine is not available"} }

        if retval["error"] == 124:
            return {"result":False, "headers":{"X-Timeout": "Command has finished with timeout signal"}}

        # error no such file
        if in_str(error_str,"No such file"):
            return {"result":False, "headers":{"X-Invalid-Path": f"{path} is an invalid path."}}

        # permission denied
        if in_str(error_str,"Permission denied") or in_str(error_str,"OPENSSH"):
            return {"result":False, "headers":{"X-Permission-Denied": "User does not have permissions to access machine or path"}}

        # not a directory
        if in_str(error_str,"Not a directory"):
            return {"result":False, "headers":{"X-Not-A-Directory": f"{path} is not a directory"}}

        return {"result":False, "headers":{"X-Error": retval["msg"]}}

    # delete test file created
    action = f"rm -- '{path}/{tempFileName}'"
    retval = exec_remote_command(headers, system_name, system_addr, action, trace_id=ID, log_command="rm")

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
        is_header_ok = check_header(auth_header)
        if not is_header_ok["result"]:
            return jsonify(description=is_header_ok["reason"]), 401

        return func(*args, **kwargs)
    return wrapper_check_auth_header


# check user authorization on endpoint
# using Open Policy Agent
#
# use:
# check_user_auth(username,system)
def check_user_auth(username,system):

    # check if OPA is active
    if OPA_ENABLED:
        try:
            input = {"input":{"user": f"{username}", "system": f"{system}"}}
            if DEBUG_MODE:
                logging.debug(f"OPA: enabled, using {OPA_URL}/{OPA_POLICY_PATH}")

            resp_opa = requests.post(f"{OPA_URL}/{OPA_POLICY_PATH}", json=input)

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
        return {"description": service_msg, "error": "Machine is not available", "status_code": 400, "header": header}

    if error_code == 113:
        header = {"X-Machine-Not-Available":"Machine is not available"}
        return {"description": service_msg, "error":  "Machine is not available", "status_code": 400, "header": header}

    if error_code == 124:
        header = {"X-Timeout": "Command has finished with timeout signal"}
        return {"description": service_msg, "error":"Command has finished with timeout signal", "status_code": 400, "header": header}

    if error_code == 118:
        header = {"X-Error": "Command execution is not allowed in machine"}
        return {"description": service_msg, "error":"Command execution is not allowed in machine", "status_code": 400, "header": header}

    # When certificate doesn't match SSH configuration
    if in_str(error_str,"OPENSSH"):
        header = {"X-Permission-Denied": "User does not have permissions to access machine"}
        return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

    if in_str(error_str,"cannot access"):
        header={"X-Invalid-Path":"path is an invalid path"}
        return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

    if in_str(error_str,"No such file"):
        if in_str(error_str,"cannot stat"):
            header={"X-Not-Found":"sourcePath not found"}
            return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

        # copy: cannot create, rename: cannot move
        if in_str(error_str, "cannot create") or in_str(error_str,"cannot move"):
            header = {"X-Invalid-Path": "sourcePath and/or targetPath are invalid paths"}
            return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

        if in_str(error_str,"cannot remove"):
            header = {"X-Invalid-Path": "path is an invalid path."}
            return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

        header={"X-Invalid-Path":"path is an invalid path"}
        return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

    if in_str(error_str,"cannot open"):
        header = {"X-Permission-Denied": "User does not have permissions to access path"}
        return {"description":service_msg, "error": error_str, "status_code": 400, "header": header}

    if in_str(error_str,"Permission denied"):
        header = {"X-Permission-Denied": "User does not have permissions to access path"}
        return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

    if in_str(error_str,"File exists") and (in_str(error_str,"mkdir: cannot create directory") or in_str(error_str,"ln: failed to create symbolic link")):
        header = {"X-Exists": "targetPath already exists"}
        return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

    if in_str(error_str,"Not a directory"):
        header = {"X-Not-A-Directory": "targetPath is not a directory"}
        return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

    if in_str(error_str,"directory"):
        header = {"X-A-Directory": "path is a directory, can't checksum directories"}
        return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

    # if already exists, not overwrite (-i)
    if in_str(error_str,"overwrite"):
        header = {"X-Exists": "targetPath already exists"}
        return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

    if in_str(error_str,"not permitted"):
        header = {"X-Permission-Denied": "User does not have permissions to access path"}
        return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

    if in_str(error_str,"invalid group"):
        header = {"X-Invalid-Group": "group is an invalid group"}
        return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

    if in_str(error_str,"invalid user"):
        header = {"X-Invalid-Owner": "owner is an invalid user"}
        return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

    if in_str(error_str, "invalid mode"):
        header = {"X-Invalid-Mode": "mode is an invalid mode"}
        return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

    if in_str(error_str, "read permission"):
        header = {"X-Permission-Denied": "User does not have permissions to access path"}
        return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}

    if service_msg in ["Error on head operation with grep", "Error on tail operation with grep"] and error_code==1 and error_str=="":
        header = {"X-Not-Found":"pattern not found"}
        return {"description": service_msg, "error": "pattern not found", "status_code": 404, "header": header}

    header = {"X-Error": error_str}
    return {"description": service_msg, "error": error_str, "status_code": 400, "header": header}



## Test if user provided text is not empty and has no invalid chars
def validate_input(text):
    if text == None:
        return "not specified"
    if text == "":
        return "is empty"
    if re.search(FORBIDDEN_INPUT_CHARS, text) != None:
        logging.warning(f'Forbidden char on: {base64.urlsafe_b64encode(text.encode()).decode()}')
        return "has invalid char"
    return ""

# formatter is executed for every log
class LogRequestFormatter(logging.Formatter):
    def format(self, record):
        try:
            # try to get TID from Flask g object, it's set on @app.before_request on each microservice
            record.TID = g.TID
        except:
            try:
                record.TID = threading.current_thread().name
            except:
                record.TID = 'notid'
        return super().format(record)

# Log formatter for Kibana
class KibanaLogger:
    instance = None
    def __new__(cls, service):
        if cls.instance is None:
            cls.instance = super(KibanaLogger, cls).__new__(cls)
        return cls.instance

    def __init__(self, service):
        self.kibana_logger = logging.getLogger("f7t_kibana_log")
        self.kibana_logger.propagate = False
        self.service = service

        log_formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
        if LOG_TYPE == "file":
            log_handler = TimedRotatingFileHandler(f'{LOG_PATH}/{service}.log', when='D', interval=1)
        else:
            log_handler = logging.StreamHandler(stream=sys.stdout)
        log_handler.setFormatter(log_formatter)
        self.kibana_logger.addHandler(log_handler)

        if DEBUG_MODE:
            self.kibana_logger.setLevel(logging.DEBUG)
            logging.info("Kibana Log DEBUG_MODE: True")
        else:
            self.kibana_logger.setLevel(logging.INFO)
            logging.info("Kibana Log DEBUG_MODE: False")

    @staticmethod
    def get_logger(service = ""):
        if KibanaLogger.instance is None:
            KibanaLogger(service)
        return KibanaLogger.instance.kibana_logger

    @staticmethod
    def get_service():
        if KibanaLogger.instance is None:
            return ""
        return KibanaLogger.instance.service


def setup_logging(logging, service):
    logger = logging.getLogger()

    if LOG_TYPE == "file":
        # timed rotation: 1 (interval) rotation per day (when="D")
        logHandler = TimedRotatingFileHandler(f'{LOG_PATH}/{service}.log', when='D', interval=1)
    elif LOG_TYPE == "stdout":
        logHandler = logging.StreamHandler(stream=sys.stdout)
    else:
        msg = f"Unknown F7T_LOG_TYPE: {LOG_TYPE}"
        logger.error(msg)
        sys.exit(msg)

    logFormatter = LogRequestFormatter('%(asctime)s,%(msecs)d %(thread)s [%(TID)s] %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                                     '%Y-%m-%dT%H:%M:%S')
    logHandler.setFormatter(logFormatter)
    # Set handler to logger
    logger.addHandler(logHandler)
    # Set logging level
    if DEBUG_MODE:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.info("DEBUG_MODE: True")
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.info("DEBUG_MODE: False")

    # Initialize Kibana logger
    KibanaLogger(service)
    return logger


def extract_command(file_path, output_directory, type="auto"):
    '''Return the appropriate command based on the file extension, or None if not supported
    '''
    # Map extension to command
    command_map = {
        ".zip": f"unzip -o '{file_path}' -d '{output_directory}'",
        ".tar": f"tar -xf '{file_path}' -C '{output_directory}'",
        ".bz2": f"tar -xjf '{file_path}' -C '{output_directory}'",
        ".gz": f"tar -xzf '{file_path}' -C '{output_directory}'",
        ".tgz": f"tar -xzf '{file_path}' -C '{output_directory}'",
    }

    if type == "auto":
        # Extract the file extension
        _, extension = os.path.splitext(file_path)
    else:
        extension = type

    return command_map.get(extension, None)
