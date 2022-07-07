#
#  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, jsonify, request, g
import requests
from logging.handlers import TimedRotatingFileHandler
import logging
import multiprocessing as mp

# common modules
from cscs_api_common import check_auth_header, get_boolean_var, LogRequestFormatter, get_username

import paramiko
import socket
import os
from flask_opentracing import FlaskTracing
from jaeger_client import Config
import opentracing


AUTH_HEADER_NAME = 'Authorization'

SYSTEMS_PUBLIC  = os.environ.get("F7T_SYSTEMS_PUBLIC").strip('\'"').split(";")
# ; separated for system (related with SYSTEMS_PUBLIC length, and for each filesystem mounted inside each system, separated with ":")
# example: let's suppose SYSTEMS_PUBLIC="cluster1;cluster2", cluster1 has "/fs-c1-1" and "/fs-c1-2", and cluster2 has mounted "/fs-c2-1":
# FILESYSTEMS = "/fs-c1-1,/fs-c1-2;fs-c2-1"
FILESYSTEMS = os.environ.get("F7T_FILESYSTEMS").strip('\'"').split(";")

SERVICES = os.environ.get("F7T_STATUS_SERVICES").strip('\'"').split(";") # ; separated service names
SYSTEMS  = os.environ.get("F7T_STATUS_SYSTEMS").strip('\'"').split(";")  # ; separated systems names

STATUS_PORT = os.environ.get("F7T_STATUS_PORT", 5000)
UTILITIES_URL = os.environ.get("F7T_UTILITIES_URL","")

SERVICES_DICT = {}

### SSL parameters
USE_SSL = get_boolean_var(os.environ.get("F7T_USE_SSL", False))
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_KEY = os.environ.get("F7T_SSL_KEY", "")


### parameters
UTILITIES_MAX_FILE_SIZE = os.environ.get("F7T_UTILITIES_MAX_FILE_SIZE")
UTILITIES_TIMEOUT = os.environ.get("F7T_UTILITIES_TIMEOUT")
STORAGE_TEMPURL_EXP_TIME = os.environ.get("F7T_STORAGE_TEMPURL_EXP_TIME")
STORAGE_MAX_FILE_SIZE = os.environ.get("F7T_STORAGE_MAX_FILE_SIZE")
OBJECT_STORAGE=os.environ.get("F7T_OBJECT_STORAGE")

TRACER_HEADER = "uber-trace-id"

# debug on console
debug = get_boolean_var(os.environ.get("F7T_DEBUG_MODE", False))


app = Flask(__name__)

JAEGER_AGENT = os.environ.get("F7T_JAEGER_AGENT", "").strip('\'"')
if JAEGER_AGENT != "":
    config = Config(
        config={'sampler': {'type': 'const', 'param': 1 },
            'local_agent': {'reporting_host': JAEGER_AGENT, 'reporting_port': 6831 },
            'logging': True,
            'reporter_batch_size': 1},
            service_name = "status")
    jaeger_tracer = config.initialize_tracer()
    tracing = FlaskTracing(jaeger_tracer, True, app)
else:
    jaeger_tracer = None
    tracing = None


def get_tracing_headers(req):
    """
    receives a requests object, returns headers suitable for RPC and ID for logging
    """
    new_headers = {}
    if JAEGER_AGENT != "":
        try:
            jaeger_tracer.inject(tracing.get_span(req), opentracing.Format.TEXT_MAP, new_headers)
        except Exception as e:
            app.logger.error(e)

    new_headers[AUTH_HEADER_NAME] = req.headers[AUTH_HEADER_NAME]
    ID = new_headers.get(TRACER_HEADER, '')
    return new_headers, ID

def set_services():
    for servicename in SERVICES:
        URL_ENV_VAR = f"F7T_{servicename.upper()}_URL"
        serviceurl = os.environ.get(URL_ENV_VAR)
        if serviceurl:
            SERVICES_DICT[servicename] = serviceurl

# test individual service function
def test_service(servicename, status_list, trace_header=None):
    app.logger.info(f"Testing {servicename} microservice status")

    try:
        serviceurl = SERVICES_DICT[servicename]
        #timeout set to 5 seconds
        req = requests.get(f"{serviceurl}/status", headers=trace_header, timeout=5, verify=(SSL_CRT if USE_SSL else False))

        # if status_code is 200 OK:
        if req.status_code == 200:
            status_list.append({"status": 0, "service": servicename})
            return

    except KeyError:
        status_list.append({"status":-1, "service":servicename})
        return
    # connection errors: server down
    except requests.ConnectionError as e:
        app.logger.error(type(e))
        app.logger.error(e)
        status_list.append( {"status": -2, "service": servicename} )
        return

    except requests.exceptions.InvalidSchema as e:
        logging.error(e, exc_info=True)
        app.logger.error(type(e))
        app.logger.error(e.errno)
        app.logger.error(e.strerror)
        app.logger.error(e)
        status_list.append( {"status": -2, "service": servicename})
        return

    # another status_code means server is reached but flask is not functional
    status_list.append( {"status":-1, "service":servicename} )


# test individual system function
def test_system(machinename, headers, status_list=[]):

    app.logger.info(f"Testing {machinename} system status")

    if machinename not in SYSTEMS_PUBLIC:
        status_list.append( {"status": -3, "system": machinename} )
        return

    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYSTEMS[i]
            filesystems = FILESYSTEMS[i]
            break

    # try to connect (unsuccesfully) with dummy user and pwd, catching SSH exception
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ipaddr = machine.split(':')
        host = ipaddr[0]
        if len(ipaddr) == 1:
            port = 22
        else:
            port = int(ipaddr[1])

        client.connect(hostname=host, port=port,
                       username="dummycscs", password="dummycscs",
                       timeout=10,
                       disabled_algorithms={'keys': ['rsa-sha2-256', 'rsa-sha2-512']})

    except paramiko.ssh_exception.AuthenticationException as e:
        # host up and SSH working, but returns (with reasons) authentication error
        app.logger.error(type(e))
        app.logger.error(e)


        ## TESTING FILESYSTEMS
        headers["X-Machine-Name"] = machinename

        is_username_ok = get_username(headers[AUTH_HEADER_NAME])

        if not is_username_ok["result"]:
            app.logger.error(f"Couldn't extract username from JWT token: {is_username_ok['reason']}")
            status_list.append({"status": -5, "system": machinename, "filesystem": fs, "reason": is_username_ok['reason']})
            return
        
        username = is_username_ok["username"]

        for fs in filesystems.split(","):

            r = requests.get(f"{UTILITIES_URL}/ls",
                                params={"targetPath":f"{fs}/{username}"},
                                headers=headers,
                                verify=(SSL_CRT if USE_SSL else False))

            if not r.ok:
                app.logger.error("Status: -4")
                status_list.append({"status": -4, "system": machinename, "filesystem": fs})
                return

        status_list.append({"status": 0, "system": machinename})

    except paramiko.ssh_exception.NoValidConnectionsError as e:
        # host up but SSH not working
        app.logger.error(type(e))
        app.logger.error(e)
        app.logger.error(e.strerror)
        app.logger.error(e.errno)
        app.logger.error(e.errors)
        status_list.append({"status": -1, "system": machinename})

    except socket.gaierror as e:
        # system down
        app.logger.error(type(e))
        app.logger.error(e)
        app.logger.error(e.strerror)
        app.logger.error(e.errno)
        status_list.append({"status": -2, "system": machinename})

    except Exception as e:
        app.logger.error(type(e))
        app.logger.error(e)
        status_list.append({"status": -2, "system": machinename})

    finally:
        client.close()

    return


# get service information about a particular servicename
@app.route("/systems/<machinename>", methods=["GET"])
@check_auth_header
def status_system(machinename):

    [headers, ID] = get_tracing_headers(request)

    status_list = []
    test_system(machinename,headers,status_list)

    # possible responses:
    # 0: host up and SSH running
    # -1: host up but no SSH running
    # -2: host down
    # -3: host not in the list (does not exist)
    # -4: host up but Filesystem not ready
    # -5: error on token verification

    status = status_list[0]["status"]

    if status == -5:
        reason = status_list[0]["reason"]
        out={"system":machinename, "status":"not available", "description": f"Error on JWT token: {reason}"}
        return jsonify(description="Filesystem is not available.", out=out), 200

    if status == -4:
        filesystem = status_list[0]["filesystem"]
        out={"system":machinename, "status":"not available", "description": f"Filesystem {filesystem} is not available"}
        return jsonify(description="Filesystem is not available.", out=out), 200

    if status == -3:
        return jsonify(description="System does not exists."), 404

    if status == -2:
        out={"system":machinename, "status":"not available", "description":"System down"}
        return jsonify(description="System information", out=out), 200

    if status == -1:
        out={"system":machinename, "status":"not available", "description":"System does not accept connections"}
        return jsonify(description="System information", out=out), 200


    out = {"system": machinename, "status": "available", "description": "System ready"}
    return jsonify(description="System information", out=out), 200


@app.route("/systems",methods=["GET"])
@check_auth_header
def status_systems():

    [headers, ID] = get_tracing_headers(request)

    # resp_list list to fill with responses from each service
    resp_list = []

    # list of processes
    process_list = []

    # memory manager
    mgr = mp.Manager()
    # create cross memory (between processes) list
    status_list = mgr.list()

    # for each servicename, creates a process
    for machinename in SYSTEMS_PUBLIC:
        p = mp.Process(target=test_system, args=(machinename, headers, status_list))
        process_list.append(p)
        p.start()

    # wait for all processes to end
    for p in process_list:
        p.join()

    for res in status_list:
        status = res["status"]
        system = res["system"]
         # possible responses:
         # 0: host up and SSH running
         # -1: host up but no SSH running
         # -2: host down
         # -4: filesystem not available
         # -5: error on token verification error
    #
        if status == -5:
            reason = status_list[0]["reason"]
            ret_dict={"system":machinename, "status":"not available", "description": f"Error on JWT token: {reason}"}            
        if status == -4:
            filesystem = status_list[0]["filesystem"]
            ret_dict={"system":machinename, "status":"not available", "description": f"Filesystem {filesystem} is not available"}
        elif status == -2:
             ret_dict = {"system": system, "status": "not available", "description": "System down"}
        elif status == -1:
             ret_dict = {"system": system, "status": "not available",
                    "description": "System does not accept connections"}
        else:
             ret_dict = {"system": system, "status": "available", "description": "System ready"}

        resp_list.append(ret_dict)
    #
    return jsonify(description="List of systems with status and description.",
                    out=resp_list), 200



# get service information about a particular servicename
@app.route("/services/<servicename>",methods=["GET"])
@check_auth_header
def status_service(servicename):
    if servicename not in SERVICES_DICT.keys():
        return jsonify(description="Service does not exists"), 404

    # needs a list to be pass as reference
    # in compatibility with test all services
    status_list = []

    [headers, ID] = get_tracing_headers(request)
    test_service(servicename, status_list, headers)

    # as it's just 1 service tested, 0 index is always valid
    serv_status = status_list[0]["status"]

    if serv_status == -2:
        status = "not available"
        description = "server down"
        return jsonify(service=servicename,status=status,description=description), 200
    elif serv_status == -1:
        status = "not available"
        description = "server up, flask down"
        return jsonify(service=servicename,status=status,description=description), 200


    status="available"
    description="server up & flask running"
    return jsonify(service=servicename,status=status,description=description), 200

# get service information about all services
@app.route("/services", methods=["GET"])
@check_auth_header
def status_services():
    # resp_list list to fill with responses from each service
    resp_list=[]

    # list of processes
    process_list = []

    # memory manager
    mgr = mp.Manager()
    # create cross memory (between processes) list
    status_list = mgr.list()

    [headers, ID] = get_tracing_headers(request)

    # for each servicename, creates a process
    for servicename,serviceurl in SERVICES_DICT.items():
        p = mp.Process(target=test_service, args=(servicename, status_list, headers))
        process_list.append(p)
        p.start()

    # wait for all processes to end
    for p in process_list:
        p.join()

    # iterate between status_list
    for res in status_list:
         retval = res["status"]
         servicename = res["service"]

         if retval == -2:
             status = "not available"
             description = "server down"
         elif retval == -1:
             status = "not available"
             description = "server up, flask down"
         else:
             status = "available"
             description = "server up & flask running"

         resp_dict={"service":servicename,
                    "status" :status,
                    "description":description}

         resp_list.append(resp_dict)

    return jsonify(description="List of services with status and description.",
                   out=resp_list), 200


# get service information about all services
@app.route("/parameters", methods=["GET"])
@check_auth_header
def parameters():
    # { <microservice>: [ "name": <parameter>,  "value": <value>, "unit": <unit> } , ... ] }

    systems = SYSTEMS_PUBLIC # list of systems
    filesystems = FILESYSTEMS # list of filesystems, position related with SYSTEMS_PUBLIC

    fs_list = []

    for i in range(len(systems)):
        mounted = filesystems[i].split(",")
        fs_list.append({"system": systems[i], "mounted": mounted})



    parameters_list = { "utilities": [
                                        {"name": "UTILITIES_MAX_FILE_SIZE", "value": UTILITIES_MAX_FILE_SIZE, "unit": "MB" },
                                        {"name" :  "UTILITIES_TIMEOUT",      "value": UTILITIES_TIMEOUT, "unit": "seconds"}
                                      ] ,
                        "storage": [
                                        {"name":"OBJECT_STORAGE" ,"value":OBJECT_STORAGE, "unit": ""},
                                        {"name":"STORAGE_TEMPURL_EXP_TIME", "value":STORAGE_TEMPURL_EXP_TIME, "unit": "seconds"},
                                        {"name":"STORAGE_MAX_FILE_SIZE", "value":STORAGE_MAX_FILE_SIZE, "unit": "MB"},
                                        {"name":"FILESYSTEMS", "value":fs_list, "unit": ""}
                                ]
                        }

    return jsonify(description="Firecrest's parameters", out=parameters_list), 200



@app.before_request
def f_before_request():
    new_headers = {}
    if JAEGER_AGENT != "":
        try:
            jaeger_tracer.inject(tracing.get_span(request), opentracing.Format.TEXT_MAP, new_headers)
        except Exception as e:
            logging.error(e)
    g.TID = new_headers.get(TRACER_HEADER, '')

@app.after_request
def after_request(response):
    # LogRequestFormatetter is used, this messages will get time, thread, etc
    logger.info('%s %s %s %s %s', request.remote_addr, request.method, request.scheme, request.full_path, response.status)
    return response


if __name__ == "__main__":
    LOG_PATH = os.environ.get("F7T_LOG_PATH", '/var/log').strip('\'"')
    # timed rotation: 1 (interval) rotation per day (when="D")
    logHandler=TimedRotatingFileHandler(f'{LOG_PATH}/status.log', when='D', interval=1)

    logFormatter = LogRequestFormatter('%(asctime)s,%(msecs)d %(thread)s [%(TID)s] %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                                     '%Y-%m-%dT%H:%M:%S')
    logHandler.setFormatter(logFormatter)

    # get app log (Flask+werkzeug+python)
    logger = logging.getLogger()

    # set handler to logger
    logger.addHandler(logHandler)
    logging.getLogger().setLevel(logging.INFO)

    # create services list
    set_services()

    if USE_SSL:
        app.run(debug=debug, host='0.0.0.0', port=STATUS_PORT, ssl_context=(SSL_CRT, SSL_KEY))
    else:
        app.run(debug=debug, host='0.0.0.0', port=STATUS_PORT)
