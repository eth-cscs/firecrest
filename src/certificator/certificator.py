#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import subprocess, os, tempfile
from flask import Flask, request, jsonify, g
from werkzeug.middleware.profiler import ProfilerMiddleware
import functools
import jwt

import logging
from logging.handlers import TimedRotatingFileHandler
import base64
from flask_opentracing import FlaskTracing
from jaeger_client import Config
import requests
import re
import threading
import sys

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

AUTH_HEADER_NAME = os.environ.get("F7T_AUTH_HEADER_NAME","Authorization")

AUTH_AUDIENCE = os.environ.get("F7T_AUTH_TOKEN_AUD", '').strip('\'"')
ALLOWED_USERS = os.environ.get("F7T_AUTH_ALLOWED_USERS", '').strip('\'"').split(";")
AUTH_REQUIRED_SCOPE = os.environ.get("F7T_AUTH_REQUIRED_SCOPE", '').strip('\'"')

AUTH_ROLE = os.environ.get("F7T_AUTH_ROLE", '').strip('\'"')

CERTIFICATOR_PORT = os.environ.get("F7T_CERTIFICATOR_PORT", 5000)

# Fobidden chars on command certificate: avoid shell special chars
#   Difference to other microservices: allow '>' for 'cat' and 'head', '&' for Storage URLs, single quotes (') for arguments
#   Commands must only use single quotes
#   r'...' specifies it's a regular expression with special treatment for \
FORBIDDEN_COMMAND_CHARS = r'[\|\<\;\"\\\(\)\x00-\x1F\x60]'

# The pipe "|" chars is only allowed if emmediatelly followed by "grep "
FORBIDDEN_COMMAND_CHARS_EXCEPTION = [r'\| grep',r'\|\| true']


# OPA endpoint
OPA_USE = get_boolean_var(os.environ.get("F7T_OPA_USE",False))
OPA_URL = os.environ.get("F7T_OPA_URL","http://localhost:8181").strip('\'"')
POLICY_PATH = os.environ.get("F7T_POLICY_PATH","v1/data/f7t/authz").strip('\'"')

### SSL parameters
USE_SSL = get_boolean_var(os.environ.get("F7T_USE_SSL", False))
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_KEY = os.environ.get("F7T_SSL_KEY", "")

### ca-key and user-key.pub keys path
CA_KEY_PATH = os.environ.get("F7T_CA_KEY_PATH", "/ca-key")
PUB_USER_KEY_PATH = os.environ.get("F7T_PUB_USER_KEY_PATH", "/user-key.pub")

TRACER_HEADER = "uber-trace-id"

REALM_RSA_PUBLIC_KEYS=os.environ.get("F7T_REALM_RSA_PUBLIC_KEY", '').strip('\'"').split(";")

is_public_key_set = False

if len(REALM_RSA_PUBLIC_KEYS) != 0:
    realm_pubkey_list = []
    is_public_key_set = True
    # headers are inserted here, must not be present

    for pubkey in REALM_RSA_PUBLIC_KEYS:
        realm_pubkey = f"-----BEGIN PUBLIC KEY-----\n{pubkey}\n-----END PUBLIC KEY-----"
        realm_pubkey_list.append(realm_pubkey)

    realm_pubkey_type = os.environ.get("F7T_REALM_RSA_TYPE").strip('\'"')

DEBUG_MODE = get_boolean_var(os.environ.get("F7T_DEBUG_MODE", False))

app = Flask(__name__)
profiling_middle_ware = ProfilerMiddleware(app.wsgi_app,
                                           restrictions=[15],
                                           filename_format="certificator.{method}.{path}.{elapsed:.0f}ms.{time:.0f}.prof",
                                           profile_dir='/var/log/profs')

JAEGER_AGENT = os.environ.get("F7T_JAEGER_AGENT", "").strip('\'"')
if JAEGER_AGENT != "":
    config = Config(
        config={'sampler': {'type': 'const', 'param': 1 },
            'local_agent': {'reporting_host': JAEGER_AGENT, 'reporting_port': 6831 },
            'logging': True,
            'reporter_batch_size': 1},
            service_name = "certificator")
    jaeger_tracer = config.initialize_tracer()
    tracing = FlaskTracing(jaeger_tracer, True, app)
else:
    jaeger_tracer = None
    tracing = None

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

def setup_logging(logging, service):
    logger = logging.getLogger()
    LOG_TYPE = os.environ.get("F7T_LOG_TYPE", "file").strip('\'"')
    if LOG_TYPE == "file":
        LOG_PATH = os.environ.get("F7T_LOG_PATH", '/var/log').strip('\'"')
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

    # set handler to logger
    logger.addHandler(logHandler)
    if DEBUG_MODE:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.info("DEBUG_MODE: True")
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.info("DEBUG_MODE: False")
    # disable Flask internal logging to avoid full url exposure
    logging.getLogger('werkzeug').disabled = True

    if OPA_USE:
        logging.info(f"OPA: enabled, using {OPA_URL}/{POLICY_PATH}")
    else:
        logging.info(f"OPA: disabled")

    return logger

def check_key_permission():
    # check that CA private key has proper permissions: 400 (no user write, and no access for group and others)
    import stat, sys
    try:
        cas = os.stat(CA_KEY_PATH).st_mode
        if oct(cas & 0o477) != '0o400':
            msg = f"ERROR: wrong '{CA_KEY_PATH}' permissions, please set to 400. Exiting."
            app.logger.error(msg)
            sys.exit(msg)
    except OSError as e:
        msg = f"ERROR: couldn't stat '{CA_KEY_PATH}', message: {e.strerror} - Exiting."
        app.logger.error(msg)
        sys.exit(msg)


logger = setup_logging(logging, 'certificator')

check_key_permission()


# check user authorization on endpoint
# using Open Policy Agent
#
# use:
# check_user_auth(username,system)
def check_user_auth(username,system):

    # check if OPA is active
    if OPA_USE:
        input = {"input":{"user": f"{username}", "system": f"{system}"}}

        try:
            resp_opa = requests.post(f"{OPA_URL}/{POLICY_PATH}", json=input, verify= (SSL_CRT if USE_SSL else False))
            msg = f"{resp_opa.status_code} {resp_opa.text}"
            logging.info(f"resp_opa: {msg}")

            if not resp_opa.ok:
                return  {"allow": False, "description":f"Server error: {msg}", "status_code": resp_opa.status_code}

            if resp_opa.json()["result"]["allow"]:
                logging.info(f"User {username} authorized by OPA")
                return {"allow": True, "description":f"User {username} authorized", "status_code": 200 }
            else:
                logging.error(f"User {username} NOT authorized by OPA")
                return {"allow": False, "description":f"Permission denied for user {username} in {system}", "status_code": 401}

        except requests.exceptions.SSLError as e:
            logging.error(f"Exception: {e}")
            return {"allow": False, "description":"Authorization server error: SSL error.", "status_code": 404}

        except requests.exceptions.RequestException as e:
            logging.error(f"Exception: {e}")
            return {"allow": False, "description":"Authorization server error: RequestException", "status_code": 404}

        except Exception as e:
            logging.error(f"Exception: {e}")
            return {"allow": False, "description":"Authorization server error: Unexpected", "status_code": 404}

    return {"allow": True, "description":"Authorization method not active", "status_code": 200 }

# checks JWT from Keycloak, optionally validates signature. It only receives the content of header's auth pair (not key:content)
def check_header(header):

    # header = remove the "Bearer " string
    token = header.replace("Bearer ","")
    decoding_result = False
    decoding_reason = ""

    if not is_public_key_set:
        if not DEBUG_MODE:
            logging.debug("WARNING: REALM_RSA_PUBLIC_KEY is empty, JWT tokens are NOT verified, setup is not set to debug.")

        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            decoding_result = True

            # only check for expired signature or general exception for this case
        except jwt.exceptions.ExpiredSignatureError:
            decoding_reason = "JWT token has expired"
            logging.error(decoding_reason, exc_info=True)
        except Exception:
            decoding_reason = "Bad header or JWT, general exception raised"
            logging.error(decoding_reason, exc_info=True)
    else:
        # iterates over the list of public keys
        for realm_pubkey in realm_pubkey_list:
            if DEBUG_MODE:
                logging.debug(f"Trying decoding with [...{realm_pubkey[71:81]}...] public key...")
            try:
                if AUTH_AUDIENCE == '':
                    decoded = jwt.decode(token, realm_pubkey, algorithms=[realm_pubkey_type], options={'verify_aud': False})
                else:
                    decoded = jwt.decode(token, realm_pubkey, algorithms=[realm_pubkey_type], audience=AUTH_AUDIENCE)
                if DEBUG_MODE:
                    logging.info(f"Correctly decoded")

                # if all passes, it means the signature is valid
                decoding_result = True
                decoding_reason = ""

            except jwt.exceptions.InvalidSignatureError:
                decoding_reason = "JWT token has invalid signature"
                logging.error(decoding_reason, exc_info=False)
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

    # if token was successfully decoded, then check if required scope is present
    if AUTH_REQUIRED_SCOPE != "" and decoding_result:
        if AUTH_REQUIRED_SCOPE not in decoded["scope"].split():
            decoding_result = False
            decoding_reason = f"Scope '{AUTH_REQUIRED_SCOPE}' wasn't found in JWT"
            logging.error(decoding_reason, exc_info=True)

    return {"result": decoding_result, "reason": decoding_reason}




# receive the header, and extract the username from the token
# returns username
def get_username(header):

    # header = remove the "Bearer " string
    token = header.replace("Bearer ","")
    decoding_result = False
    decoding_reason = ""

    # does FirecREST check the signature of the token?
    if not is_public_key_set:
        if not DEBUG_MODE:
            logging.debug("WARNING: REALM_RSA_PUBLIC_KEY is empty, JWT tokens are NOT verified, setup is not set to debug.")

        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            decoding_result = True

            # only check for expired signature or general exception for this case
        except jwt.exceptions.ExpiredSignatureError:
            logging.error("JWT token has expired", exc_info=True)
            return {"result": False, "reason":"JWT token has expired", "username": None}
        except Exception:
            logging.error("Bad header or JWT, general exception raised", exc_info=True)
            return {"result": False, "reason":"Bad header or JWT, general exception raised", "username": None}

    else:
        # iterates over the list of public keys
        for realm_pubkey in realm_pubkey_list:
            if DEBUG_MODE:
                logging.debug(f"Trying decoding with [...{realm_pubkey[71:81]}...] public key...")
            try:
                if AUTH_AUDIENCE == '':
                    decoded = jwt.decode(token, realm_pubkey, algorithms=[realm_pubkey_type], options={'verify_aud': False})
                else:
                    decoded = jwt.decode(token, realm_pubkey, algorithms=[realm_pubkey_type], audience=AUTH_AUDIENCE)
                if DEBUG_MODE:
                    logging.info(f"Correctly decoded")

                # if token is correctly decoded, exit the loop
                decoding_result = True
                decoding_reason = ""

            except jwt.exceptions.InvalidSignatureError:
                decoding_reason = "JWT token has invalid signature"
                logging.error(decoding_reason, exc_info=False)
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

# returns an SSH certificate, username is got from token
@app.route("/", methods=["GET"])
@check_auth_header
def receive():
    """
    Input:
    - command (required): generates certificate for this specific command
    - option (optional): options for command
    - exptime (optional): expiration time given to the certificate in seconds (default +5m)
    - cluster (required): public name of the system where to exec the command
    Returns:
    - certificate (json)
    """

    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
        is_username_ok = get_username(auth_header)
        if is_username_ok["result"] == False:
            app.logger.error(f"Error getting username: {is_username_ok['reason']}")
            return jsonify(description=f"Invalid username. Reason: {is_username_ok['reason']}"), 401

        username = is_username_ok["username"]

        # Check if user is authorized in OPA
        cluster = request.args.get("cluster","")
        if not cluster:
            return jsonify(description='No cluster specified'), 400

        auth_result = check_user_auth(username,cluster)
        if not auth_result["allow"]:
            return jsonify(description=auth_result["description"]), auth_result["status_code"]

        app.logger.info(f"Generating cert for user: {username}")

        # default expiration time for certificates
        ssh_expire = '+5m'

        # if command is provided, parse to use force-command
        force_command = base64.urlsafe_b64decode(request.args.get("command", '')).decode("utf-8")
        force_opt = ''
        if force_command:
            force_opt = base64.urlsafe_b64decode(request.args.get("option", '')).decode("utf-8")
            # find first space and take substring to check command. If there isn't a space, .find() returns -1
            i = force_command.find(' ') + 1
            tc = force_command[i:i + 4]
            if tc == 'curl':
                exp_time = request.args.get("exptime", '')
                if exp_time:
                    ssh_expire = f"+{exp_time}s"
                # don't log full URL
                app.logger.info(f"Command (truncated): {force_command} {force_opt[:200]}")
            else:
                app.logger.info(f"Command: {force_command} {force_opt}")
        else:
            return jsonify(description='No command specified'), 400

        command_chars = force_command + force_opt
        for exc in FORBIDDEN_COMMAND_CHARS_EXCEPTION:
            command_chars = re.sub(exc,'',command_chars,1)
        if re.search(FORBIDDEN_COMMAND_CHARS, command_chars) != None:
            app.logger.error(f"Forbidden char on command or option: {force_command} {force_opt}")
            return jsonify(description='Invalid command'), 400


        # create temp dir to store certificate for this request
        td = tempfile.mkdtemp(prefix = "cert")
        os.symlink(PUB_USER_KEY_PATH, f"{td}/user-key.pub")  # link on temp dir

        command = ["ssh-keygen",
                    "-s",
                    f"{CA_KEY_PATH}",
                    "-n",
                    f"{username}",
                    "-V",
                    f"{ssh_expire}",
                    "-I",
                    f"{CA_KEY_PATH}",
                    "-O",
                    f"force-command={force_command} {force_opt}",
                    f"{td}/user-key.pub"
                    ]
 
    except Exception as e:
        logging.error(e)
        return jsonify(description=f"Error creating certificate: {e}", error=-1), 400

        
    try:
        #To prvent shell hijacking don't run commands with shell=True
        result = subprocess.run(command, shell=False, check=True)
        with open(td + '/user-key-cert.pub', 'r') as cert_file:
            cert = cert_file.read()

        os.remove(td + "/user-key-cert.pub")
        os.remove(td + "/user-key.pub")
        os.rmdir(td)

        # return certificate
        return jsonify(certificate=cert), 200
    except subprocess.CalledProcessError as e:
        return jsonify(description=e.output, error=e.returncode), 400
    except Exception as e:
        return jsonify(description=f"Error creating certificate. {e}", error=-1), 400


# get status for status microservice
@app.route("/status", methods=["GET"])
@check_auth_header
def status():
    app.logger.info("Test status of service")
    if("X-F7T-PROFILE" in request.headers):
        app.wsgi_app = profiling_middle_ware
        return jsonify(success="profiling activated!"), 200
    else:
        return jsonify(success="ack"), 200

@app.before_request
def f_before_request():
    g.TID = request.headers.get(TRACER_HEADER, '')

@app.after_request
def after_request(response):
    # LogRequestFormatetter is used, this messages will get time, thread, etc
    # don't use request.full_path here
    logger.info('%s %s %s %s %s', request.remote_addr, request.method, request.scheme, request.path, response.status)
    return response


if __name__ == "__main__":
    if USE_SSL:
        app.run(debug=DEBUG_MODE, host='0.0.0.0', port=CERTIFICATOR_PORT, ssl_context=(SSL_CRT, SSL_KEY))
    else:
        app.run(debug=DEBUG_MODE, host='0.0.0.0', port=CERTIFICATOR_PORT)
