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

debug = os.environ.get("DEBUG_MODE", None)

AUTH_HEADER_NAME = 'Authorization' # os.environ.get("AUTH_HEADER_NAME").strip('\'"')
#if AUTH_HEADER_NAME == "Authorization":
realm_pubkey=os.environ.get("REALM_RSA_PUBLIC_KEY", '')
if realm_pubkey != '':
    # headers are inserted here, must not be present
    realm_pubkey = realm_pubkey.strip('\'"')   # remove '"'
    realm_pubkey = '-----BEGIN PUBLIC KEY-----\n' + realm_pubkey + '\n-----END PUBLIC KEY-----'
    realm_pubkey_type = os.environ.get("REALM_RSA_TYPE").strip('\'"')

AUTH_AUDIENCE = os.environ.get("AUTH_TOKEN_AUD", '').strip('\'"')
ALLOWED_USERS = os.environ.get("AUTH_ALLOWED_USERS", '').strip('\'"').split(";")
AUTH_REQUIRED_SCOPE = os.environ.get("AUTH_REQUIRED_SCOPE", '').strip('\'"')


CERTIFICATOR_URL = os.environ.get("CERTIFICATOR_URL")
TASKS_URL = os.environ.get("TASKS_URL")

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

        if AUTH_REQUIRED_SCOPE != '':
            if not (AUTH_REQUIRED_SCOPE in decoded['realm_access']['roles']):
                return False

        #if not (decoded['preferred_username'] in ALLOWED_USERS):
        #    return False

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
#            if AUTH_AUDIENCE == '':
            decoded = jwt.decode(header[7:], realm_pubkey, algorithms=realm_pubkey_type, options={'verify_aud': False})
#            else:
#                decoded = jwt.decode(header[7:], realm_pubkey, algorithms=realm_pubkey_type, audience=AUTH_AUDIENCE)

#        if ALLOWED_USERS != '':
#            if not (decoded['preferred_username'] in ALLOWED_USERS):
#                return None

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


# SSH certificates creation
# returns pub key certificate name
def create_certificates(auth_header, cluster):

    import tempfile, json
    from urllib.request import urlopen, Request


    reqURL = "{cert_url}/?cluster={cluster}". \
        format(cert_url=CERTIFICATOR_URL, cluster=cluster)

    # getting request method:
    req = Request(reqURL)
    req.add_header(AUTH_HEADER_NAME, auth_header)

    try:
        jcert = json.loads(urlopen(req).read())

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
    except IOError as e:
        logging.error("({errno}) -> {message}".format(errno=e.errno, message=e.strerror), exc_info=True)
        return [None, e.errno, e.strerror]


# formats output for std buffer of paramiko
def get_buffer_lines(buffer):

    lines = ""
    while True:
        line = buffer.readline()
        if line == "":
            break

        if line[-1] == "\n":
            line = line.rstrip()

        lines += line
    return lines

# formats output for std buffer of paramiko when squeue is executed
def get_squeue_buffer_lines(buffer):

    lines = ""
    while True:
        line = buffer.readline()
        if line == "":
            break

        if line[-1] == "\n":
            line = line[:-1]

        lines += line + "$"
    return lines[:-1]


# execute remote commands with Paramiko:
def exec_remote_command(auth_header, system, action):

    import paramiko, socket

    logging.info('debug: cscs_common_api: exec_remote_command: system: ' + system + '  -  action: ' + action)

    # get certificate:
    # if OK returns: [pub_cert, pub_key, priv_key, temp_dir]
    # if FAILED returns: [None, errno, strerror]
    cert_list = create_certificates(auth_header, system)

    if cert_list[0] == None:
        result = {"error": 1, "msg": "Cannot create certificates"}
        return result

    [pub_cert, pub_key, priv_key, temp_dir] = cert_list

    #getting username from auth_header
    username = get_username(auth_header)

    # -------------------
    # remote exec with paramiko
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ipaddr = system.split(':')
        host = ipaddr[0]
        if len(ipaddr) == 1:
            port = 22
        else:
            port = int(ipaddr[1])

        client.connect(hostname=host, port=port,
                       username=username,
                       key_filename="{cert_name}".format(cert_name=pub_cert),
                       allow_agent=False,
                       look_for_keys=False,
                       timeout=10)

        stdin , stdout, stderr = client.exec_command(action)
        logging.info("action: {}".format(action))

        stderr_errno = stderr.channel.recv_exit_status()
        stdout_errno = stdout.channel.recv_exit_status()
        #errdadirt = stderr.channel.recv_stderr(1024)
        # clean "tput: No ..." lines at error output
        stderr_errda = clean_err_output(stderr.channel.recv_stderr(1024))
        stdout_errda = clean_err_output(stdout.channel.recv_stderr(1024))

        outlines = get_squeue_buffer_lines(stdout)

        if outlines:
            logging.info("sdterr: ({errno}) --> {stdout}".format(errno=stderr_errno, stdout=outlines))
            logging.info("stdout: ({errno}) --> {stdout}".format(errno=stdout_errno, stdout=outlines))
        if stdout_errda or stdout_errno != 0:
            logging.error("(stdout: {errno}) --> {stderr}".format(errno=stdout_errno, stderr=stdout_errda))
        if stderr_errda or stderr_errno != 0:
            logging.error("(stderr: {errno}) --> {stderr}".format(errno=stderr_errno, stderr=stderr_errda))

        # TODO: change precedence of error, because in /xfer-external/download this gives error and it s not an error
        if stderr_errno == 0:
            if stderr_errda:
                result = {"error": 0, "msg": stderr_errda}
            else:
                result = {"error": 0, "msg": outlines}
        elif stderr_errno > 0:
            result = {"error": stderr_errno, "msg": stderr_errda}
        elif len(stderr_errda) > 0:
            result = {"error": 1, "msg": stderr_errda}


    # first if paramiko exception raise
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        logging.error(type(e), exc_info=True)
        if e.errors:
            for k, v in e.errors.items():
                logging.error("errorno: {errno}".format(errno=v.errno))
                logging.error("strerr: {strerr}".format(strerr=v.strerror))

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
        logging.info(result["msg"])
        os.remove(pub_cert)
        os.remove(pub_key)
        os.remove(priv_key)
        os.rmdir(temp_dir)

    logging.info("Result returned {}".format(result["msg"]))
    return result


# clean TERM errors on stderr
# resaon: some servers produces this error becuase don't set a TERM
def clean_err_output(tex):
    lines = ""

    # python3 tex comes as a byte object, needs to be decoded to a str
    tex = tex.decode('latin-1')

    for t in tex.split('\n'):
        if t != 'tput: No value for $TERM and no -T specified':
            lines += t

    return lines


# function to call create task entry API in Queue FS, returns task_id for new task
def create_task(auth_header,service=None):
    import json, requests

    logging.info("{tasks_url}/".format(tasks_url=TASKS_URL))

    # returns {"task_id":task_id}
    # first try to get up task microservice:
    try:
        # X-Firecrest-Service: service that created the task
        req = requests.post("{tasks_url}/".format(tasks_url=TASKS_URL),
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

    import json, requests

    logging.info("{tasks_url}/{task_id}".
                        format(tasks_url=TASKS_URL,task_id=task_id))

    if is_json:
        data = {"status": status, "msg": msg}
        req = requests.put("{tasks_url}/{task_id}".
                            format(tasks_url=TASKS_URL, task_id=task_id),
                            json=data, headers={AUTH_HEADER_NAME: auth_header})
    else:
        data = {"status": status, "msg": msg}
        req = requests.put("{tasks_url}/{task_id}".
                            format(tasks_url=TASKS_URL,task_id=task_id),
                            data=data, headers={AUTH_HEADER_NAME: auth_header})

    resp = json.loads(req.content)

    return resp

# function to call update task entry API in Queue FS
def expire_task(task_id,auth_header):

    import json, requests

    logging.info("{tasks_url}/task-expire/{task_id}".
                        format(tasks_url=TASKS_URL,task_id=task_id))


    req = requests.post("{tasks_url}/task-expire/{task_id}".
                            format(tasks_url=TASKS_URL,task_id=task_id),
                            headers={AUTH_HEADER_NAME: auth_header})

    resp = json.loads(req.content)

    return resp

# function to check task status:
def get_task_status(task_id,auth_header):
    import requests

    logging.info("{tasks_url}/{task_id}".
                 format(tasks_url=TASKS_URL, task_id=task_id))

    try:
        retval = requests.get("{tasks_url}/{task_id}".
                           format(tasks_url=TASKS_URL, task_id=task_id),
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

