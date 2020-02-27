#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import subprocess, os, tempfile
from flask import Flask, request, jsonify
# from cscs_api_common import check_header, get_username
import jwt

import logging
from logging.handlers import TimedRotatingFileHandler

STATUS_IP = os.environ.get("STATUS_IP")
AUTH_HEADER_NAME = 'Authorization'

AUTH_AUDIENCE = os.environ.get("AUTH_TOKEN_AUD", '').strip('\'"')
ALLOWED_USERS = os.environ.get("AUTH_ALLOWED_USERS", '').strip('\'"').split(";")
AUTH_REQUIRED_SCOPE = os.environ.get("AUTH_REQUIRED_SCOPE", '').strip('\'"')

CERTIFICATOR_PORT = os.environ.get("CERTIFICATOR_PORT", 5000)

realm_pubkey=os.environ.get("REALM_RSA_PUBLIC_KEY", '')
if realm_pubkey != '':
    # headers are inserted here, must not be present
    realm_pubkey = realm_pubkey.strip('\'"')   # remove '"'
    realm_pubkey = '-----BEGIN PUBLIC KEY-----\n' + realm_pubkey + '\n-----END PUBLIC KEY-----'
    realm_pubkey_type = os.environ.get("REALM_RSA_TYPE").strip('\'"')

debug = os.environ.get("DEBUG_MODE", False)

app = Flask(__name__)

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

# receive the header, and extract the username from the token
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



# returns an SSH certificate, username is got from token
@app.route("/", methods=["GET"])
def receive():
    """
    Input:
    - command (optional): generates certificate for this specific command
    - option (optional): options for command
    Returns:
    - certificate (json)
    """

    if debug:
        logging.getLogger().setLevel(logging.INFO)
        logging.info('debug: certificator: request.headers[AUTH_HEADER_NAME]: ' + request.headers[AUTH_HEADER_NAME])

    try:
        try:
            auth_header = request.headers[AUTH_HEADER_NAME]
        except KeyError as e:
            app.logger.error("No Auth Header given")
            return jsonify(description="No Auth Header given"), 401

        if not check_header(auth_header):
            app.logger.error("Bad header")
            return jsonify(description="Invalid header"), 401

        username = get_username(auth_header)
        if username == None:
            app.logger.error("No username")
            return jsonify(description="Invalid user"), 401

        # default expiration time for certificates
        ssh_expire = '+5m'

        # if command is provided, parse to use force-command
        force_command = request.args.get("command", '')
        if force_command:
            force_opt = request.args.get("option", '')
            if force_command == 'wget':
                force_command = '/usr/bin/wget'
                ssh_expire = '+10d'
            else:
                return jsonify(msg='Invalid command'), 404

            force_command = '-O force_command=' + force_command + force_opt

        app.logger.info("Generating cert for user: {user}".format(user=username))

        # create temp dir to store certificate for this request
        td = tempfile.mkdtemp(prefix = "cert")
        os.symlink(os.getcwd() + "/user-key.pub", td + "/user-key.pub")  # link on temp dir

        command = "ssh-keygen -s ca-key -n {user} -V {ssh_expire} -I ca-key {tempdir}/user-key.pub {fc}".format(user=username, ssh_expire=ssh_expire, tempdir=td, fc=force_command)

    except Exception as e:
        logging.error(e)
        return jsonify(msg='cert error'), 404

    try:
        result = subprocess.check_output([command], shell=True)
        with open(td + '/user-key-cert.pub', 'r') as cert_file:
            cert = cert_file.read()

        os.remove(td + "/user-key-cert.pub")
        os.remove(td + "/user-key.pub")
        os.rmdir(td)

        # return certificate
        return jsonify(certificate=cert), 200
    except subprocess.CalledProcessError as e:
        return jsonify(description=e.output, error=e.returncode), 404


# get status for status microservice
# only used by STATUS_IP otherwise forbidden
@app.route("/status", methods=["GET"])
def status():
    app.logger.info("Test status of service")

    if request.remote_addr != STATUS_IP:
        app.logger.warning("Invalid remote address: {addr}".format(addr=request.remote_addr))
        return jsonify(error="Invalid access"), 403

    return jsonify(success="ack"), 200


if __name__ == "__main__":
    # log handler definition
    # timed rotation: 1 (interval) rotation per day (when="D")
    logHandler = TimedRotatingFileHandler('/var/log/certificator.log', when='D', interval=1)

    logFormatter = logging.Formatter('%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                                     '%Y-%m-%d:%H:%M:%S')
    logHandler.setFormatter(logFormatter)
    logHandler.setLevel(logging.DEBUG)

    # get app log (Flask+werkzeug+python)
    logger = logging.getLogger()

    # set handler to logger
    logger.addHandler(logHandler)

    # check that CA private key has proper permissions: 400 (no user write, and no access for group and others)
    import stat
    try:
        cas = os.stat('ca-key').st_mode
        if oct(cas & 0o477) != '0o400':
            app.logger.error("ERROR: wrong 'ca-key' permissions, please set to 400. Exiting.")
            raise SystemExit
    except SystemExit as e:
        exit(e)
    except:
        app.logger.error("ERROR: couldn't read 'ca-key', exiting.")
        exit(1)

    # run app
    # debug = False, so output redirects to log files
    app.run(debug=debug, host='0.0.0.0', port=CERTIFICATOR_PORT)

