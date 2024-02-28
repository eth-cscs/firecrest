#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, jsonify, request, g
import requests
import logging
import multiprocessing as mp

# common modules
from cscs_api_common import check_auth_header, get_boolean_var, get_username, setup_logging
import json
import paramiko
import socket
import os, ast
from flask_opentracing import FlaskTracing
from jaeger_client import Config
import opentracing


AUTH_HEADER_NAME = os.environ.get("F7T_AUTH_HEADER_NAME","Authorization")

SYSTEMS_PUBLIC  = os.environ.get("F7T_SYSTEMS_PUBLIC_NAME","").strip('\'"').split(";")

FILESYSTEMS = ast.literal_eval(os.environ.get("F7T_FILESYSTEMS", {}))

SERVICES = os.environ.get("F7T_STATUS_SERVICES","").strip('\'"').split(";") # ; separated service names
SYSTEMS  = os.environ.get("F7T_SYSTEMS_INTERNAL_STATUS", os.environ.get("F7T_SYSTEMS_INTERNAL_NAME", "")).strip('\'"').split(";")  # ; separated systems names

### SSL parameters
USE_SSL = get_boolean_var(os.environ.get("F7T_SSL_USE", False))
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_KEY = os.environ.get("F7T_SSL_KEY", "")

STATUS_PORT = os.environ.get("F7T_STATUS_PORT", "5001")

F7T_SCHEME_PROTOCOL = ("https" if USE_SSL else "http")

UTILITIES_HOST = os.environ.get("F7T_UTILITIES_HOST","127.0.0.1") 
UTILITIES_PORT = os.environ.get("F7T_UTILITIES_PORT","5004")
UTILITIES_URL = f"{F7T_SCHEME_PROTOCOL}://{UTILITIES_HOST}:{UTILITIES_PORT}"

SERVICES_DICT = {}


### parameters
UTILITIES_MAX_FILE_SIZE = os.environ.get("F7T_UTILITIES_MAX_FILE_SIZE", '5')
UTILITIES_TIMEOUT = os.environ.get("F7T_UTILITIES_TIMEOUT", '5')
STORAGE_TEMPURL_EXP_TIME = os.environ.get("F7T_STORAGE_TEMPURL_EXP_TIME", '604800')
STORAGE_MAX_FILE_SIZE = os.environ.get("F7T_STORAGE_MAX_FILE_SIZE", '5120')
OBJECT_STORAGE = os.environ.get("F7T_OBJECT_STORAGE", 's3v4')
COMPUTE_SCHEDULER = os.environ.get("F7T_COMPUTE_SCHEDULER", "Slurm")

TRACER_HEADER = "uber-trace-id"

# debug on console
DEBUG_MODE = get_boolean_var(os.environ.get("F7T_DEBUG_MODE", False))

app = Flask(__name__)

logger = setup_logging(logging, 'status')

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

def set_services():
    for servicename in SERVICES:
        SERVICE_HOST_ENV_VAR_NAME = f"F7T_{servicename.upper()}_HOST"
        SERVICE_PORT_ENV_VAR_NAME = f"F7T_{servicename.upper()}_PORT"
        service_host = os.environ.get(SERVICE_HOST_ENV_VAR_NAME)
        service_port = os.environ.get(SERVICE_PORT_ENV_VAR_NAME)
        if service_host and service_port:
            SERVICES_DICT[servicename] = f"{F7T_SCHEME_PROTOCOL}://{service_host}:{service_port}"

# create services list
set_services()


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

# test individual service function
def test_service(servicename, status_list, trace_header=None):
    app.logger.info(f"Testing {servicename} microservice status")

    try:
        serviceurl = SERVICES_DICT[servicename]
        #timeout set to 5 seconds
        req = requests.get(f"{serviceurl}/status", headers=trace_header, timeout=5, verify=(SSL_CRT if USE_SSL else False))

        # if status_code is 200 OK:
        if req.status_code == 200:
            status_list.append({"status": 0, "service": servicename, "status_code": req.status_code})
            return

        if req.status_code == 401:
            status_list.append({"status": -6, "service": servicename, "status_code": req.status_code})
            return

    except KeyError:
        status_list.append({"status":-1, "service":servicename, "status_code": 404})
        return
    # connection errors: server down
    except requests.ConnectionError as e:
        app.logger.error(type(e))
        app.logger.error(e)
        status_list.append( {"status": -2, "service": servicename, "status_code": 400} )
        return

    except requests.exceptions.InvalidSchema as e:
        logging.error(e, exc_info=True)
        app.logger.error(type(e))
        app.logger.error(e.errno)
        app.logger.error(e.strerror)
        app.logger.error(e)
        status_list.append( {"status": -2, "service": servicename, "status_code": 400})
        return

    # another status_code means server is reached but flask is not functional
    status_list.append( {"status":-1, "service":servicename, "status_code": req.status_code} )


# test individual system function
def test_system(machinename, headers, status_list=[]):

    app.logger.info(f"Testing {machinename} system status")

    if machinename not in SYSTEMS_PUBLIC:
        status_list.append( {"status": -3, "system": machinename} )
        return

    if machinename not in FILESYSTEMS:
        status_list.append( {"status": -3, "system": machinename} )
        return
    
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYSTEMS[i]
            break

    mounted_fs = FILESYSTEMS[machinename]
                

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

        failfs = []
        for fs in mounted_fs:
            try:
                r = requests.get(f"{UTILITIES_URL}/ls",
                                params={"targetPath": fs["path"], "numericUid": "True"},
                                headers=headers,
                                verify=(SSL_CRT if USE_SSL else False),
                                timeout=(int(UTILITIES_TIMEOUT) + 1))
                if not r.ok:
                    failfs.append(fs["path"])
                else:
                    j = json.loads(r.content)
                    if len(j['output']) == 0:
                        failfs.append(fs["path"])
            except:
                failfs.append(fs["path"])

        if len(failfs) > 0:
            app.logger.error("Status: -4")
            status_list.append({"status": -4, "system": machinename, "filesystem": ",".join(failfs)})
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

def check_fs(system,filesystem, headers):

    headers["X-Machine-Name"] = system
    
    try:
        r = requests.get(f"{UTILITIES_URL}/ls",
                        params={"targetPath": filesystem, "numericUid": "True"},
                        headers=headers,
                        verify=(SSL_CRT if USE_SSL else False),
                        timeout=(int(UTILITIES_TIMEOUT) + 1))
        if not r.ok:
            return 400
        else:
            j = json.loads(r.content)
            if len(j['output']) == 0:
                return 400
    except:
        return 400
    
    return 200


def check_filesystem(system, filesystems,headers):
    
    resp_json = []
    try:
        
        for fs in filesystems:
            resp_fs = {}

            resp_fs["name"] = fs["name"]
            resp_fs["path"] = fs["path"]
            resp_fs["description"] = fs["description"]
        

            status_code = check_fs(system, fs["path"], headers)
            resp_fs["status_code"] = status_code
            if status_code == 200:
                resp_fs["status"] = "available"
            elif status_code == 400:
                resp_fs["status"] = "not available"

            resp_json.append(resp_fs)
    except KeyError as ke:
        app.logger.error(ke)
        return {"out":"Error in filesystem configuration", "status_code": 400}    
        
    return {"out": resp_json, "status_code": 200}


# get information about of all filesystems
@app.route("/filesystems", methods=["GET"])
@check_auth_header
def get_all_filesystems():

    [headers, ID] = get_tracing_headers(request)

    # resp_json json to fill with responses from each system
    resp_json = {}

    
    for system in FILESYSTEMS:

        if system not in SYSTEMS_PUBLIC:
            return jsonify(description="Filesystem information", out=f"System '{system}' doesn't exist"), 404

        if DEBUG_MODE:
            app.logger.debug(f"Checking filesystems in {system}")
        
        resp_json[system] = []
        try:
            
            filesystems = FILESYSTEMS[system]

            if DEBUG_MODE:
                app.logger.debug(f"Checking filesystems in {system}")

            resp_system = check_filesystem(system,filesystems,headers)

            resp_json[system] = resp_system["out"]

        except KeyError as ke:
            app.logger.error(ke.args)
            return jsonify(description="Filesystem information", out=f"Machine {system} doesn't exist"), 404

    return jsonify(description="Filesystem information", out=resp_json), 200
    

    



# get information about a specific system
@app.route("/filesystems/<system>", methods=["GET"])
@check_auth_header
def get_system_filesystems(system):

    [headers, ID] = get_tracing_headers(request)

    # resp_json json to fill with responses from each system
    resp_json = {}

    if system not in SYSTEMS_PUBLIC:
        return jsonify(description=f"Filesystem information for system {system}", out=f"System '{system}' doesn't exist"), 404

    try:
        filesystems = FILESYSTEMS[system]
        if DEBUG_MODE:
            app.logger.debug(f"Checking filesystems in {system}")

        resp_system = check_filesystem(system,filesystems,headers)

        resp_json = resp_system["out"]

    except KeyError as ke:
        app.logger.error(ke.args)
        return jsonify(description=f"Filesystem information for system {system}", out=f"System '{system}' doesn't exist"), 404

    return jsonify(description=f"Filesystem information for system {system}", out=resp_json), 200


# get service information about a particular system
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


# return information of all systems configured
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

    app.logger.debug(status_list)

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
            reason = res["reason"]
            ret_dict={"system":system, "status":"not available", "description": f"Error on JWT token: {reason}"}
        if status == -4:
            filesystem = res["filesystem"]
            ret_dict={"system":system, "status":"not available", "description": f"Filesystem {filesystem} is not available"}
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
        return jsonify(description="Service does not exists", status_code=404), 404

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
        return jsonify(service=servicename,status=status,status_code=400, description=description), 200
    elif serv_status == -1:
        status = "not available"
        description = "server up, flask down"
        return jsonify(service=servicename,status=status,status_code=400,description=description), 200
    elif serv_status == -6:
        status = "not available"
        description = "unauthorized"
        return jsonify(service=servicename,status=status,status_code=401,description=description), 200


    status="available"
    description="server up & flask running"
    return jsonify(service=servicename,status=status,status_code=200,description=description), 200

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
        status_code = res["status_code"]

        if retval == -2:
            status = "not available"
            description = "server down"
        elif retval == -1:
            status = "not available"
            description = "server up, flask down"
        elif retval == -6:
            status = "not available"
            description = "unathorized"
        else:
            status = "available"
            description = "server up & flask running"

        resp_dict={"service":servicename,
                "status" :status,
                "status_code": status_code,
                "description":description}

        resp_list.append(resp_dict)

    return jsonify(description="List of services with status and description.",
                   out=resp_list), 200


# get service information about all services
@app.route("/parameters", methods=["GET"])
@check_auth_header
def parameters():
    # { <microservice>: [ "name": <parameter>,  "value": <value>, "unit": <unit> } , ... ] }

    fs_list = []
    for system_fs in FILESYSTEMS:
        mounted_fs = []
        if system_fs not in SYSTEMS_PUBLIC:
            continue

        for fs in FILESYSTEMS[system_fs]:
            mounted_fs.append(fs["path"])

        fs_list.append({"system": system_fs, "mounted": mounted_fs})



    parameters_list = {
        "compute": [
            { 
                "name" : "WORKLOAD_MANAGER",
                "value": COMPUTE_SCHEDULER,
                "unit": "",
                "description": "Type of resource and workload manager used in "
                               "compute microservice"  
            }
        ],
        "utilities": [
            {
                "name": "UTILITIES_MAX_FILE_SIZE",
                "value": UTILITIES_MAX_FILE_SIZE,
                "unit": "MB",
                "description": "The maximum allowable file size for various operations "
                               "of the utilities microservice"
            },
            {
                "name": "UTILITIES_TIMEOUT",
                "value": UTILITIES_TIMEOUT,
                "unit": "seconds",
                "description": "Maximum time duration for executing the commands in "
                               "the cluster for the utilities microservice."
            }
        ] ,
        "storage": [
            {
                "name": "OBJECT_STORAGE",
                "value": OBJECT_STORAGE,
                "unit": "",
                "description": "Type of object storage, like `swift`, `s3v2` or `s3v4`."
            },
            {
                "name": "STORAGE_TEMPURL_EXP_TIME",
                "value": STORAGE_TEMPURL_EXP_TIME,
                "unit": "seconds",
                "description": "Expiration time for temp URLs."
            },
            {
                "name": "STORAGE_MAX_FILE_SIZE",
                "value": STORAGE_MAX_FILE_SIZE,
                "unit": "MB",
                "description": "Maximum file size for temp URLs."
            },
            {
                "name": "FILESYSTEMS",
                "value": fs_list,
                "unit": "",
                "description": "Available filesystems through the API."
            }
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
    if USE_SSL:
        app.run(debug=DEBUG_MODE, host='0.0.0.0', port=STATUS_PORT, ssl_context=(SSL_CRT, SSL_KEY))
    else:
        app.run(debug=DEBUG_MODE, host='0.0.0.0', port=STATUS_PORT)
