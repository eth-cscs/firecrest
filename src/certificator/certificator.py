#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import subprocess, os, tempfile
from flask import Flask, request, jsonify
from cscs_api_common import check_header, get_username

import logging
from logging.handlers import TimedRotatingFileHandler

STATUS_IP = os.environ.get("STATUS_IP")
AUTH_HEADER_NAME = 'Authorization'

CERTIFICATOR_PORT = os.environ.get("CERTIFICATOR_PORT", 5000)

debug = os.environ.get("DEBUG_MODE", False)

app = Flask(__name__)

# returns an SSH certificate, username is got from token
@app.route("/", methods=["GET"])
def receive():
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
            app.logger.error("bad header")
            return jsonify(description="Invalid header"), 401

        username = get_username(auth_header)
        if username == None:
            app.logger.error("no username")
            return jsonify(description="Invalid user"), 401

        app.logger.info("Generating cert for user: {user}".format(user=username))

        # create temp dir to store certificate for this request
        td = tempfile.mkdtemp(prefix = "cert")
        os.symlink(os.getcwd() + "/user-key.pub", td + "/user-key.pub")  # link on temp dir

        command = "ssh-keygen -s ca-key -n {user} -V +5m -I ca-key {tempdir}/user-key.pub".format(user=username, tempdir=td)

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

