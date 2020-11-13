#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, jsonify, request
import requests
from logging.handlers import TimedRotatingFileHandler
import logging
import multiprocessing as mp

# common modules
from cscs_api_common import check_auth_header

import paramiko
import socket
import os


AUTH_HEADER_NAME = 'Authorization'

SYSTEMS_PUBLIC  = os.environ.get("F7T_SYSTEMS_PUBLIC").strip('\'"').split(";")
# ; separated for system (related with SYSTEMS_PUBLIC length, and for each filesystem mounted inside each system, separated with ":")
# example: let's suppose SYSTEMS_PUBLIC="cluster1;cluster2", cluster1 has "/fs-c1-1" and "/fs-c1-2", and cluster2 has mounted "/fs-c2-1":
# FILESYSTEMS = "/fs-c1-1,/fs-c1-2;fs-c2-1"
FILESYSTEMS = os.environ.get("F7T_FILESYSTEMS").strip('\'"').split(";")

SERVICES = os.environ.get("F7T_STATUS_SERVICES").strip('\'"').split(";") # ; separated service names
SYSTEMS  = os.environ.get("F7T_STATUS_SYSTEMS").strip('\'"').split(";")  # ; separated systems names

STATUS_PORT = os.environ.get("F7T_STATUS_PORT", 5000)

SERVICES_DICT = {}

### SSL parameters
USE_SSL = os.environ.get("F7T_USE_SSL", False)
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_KEY = os.environ.get("F7T_SSL_KEY", "")


### parameters
UTILITIES_MAX_FILE_SIZE = os.environ.get("F7T_UTILITIES_MAX_FILE_SIZE")
UTILITIES_TIMEOUT = os.environ.get("F7T_UTILITIES_TIMEOUT")
STORAGE_TEMPURL_EXP_TIME = os.environ.get("F7T_STORAGE_TEMPURL_EXP_TIME")
STORAGE_MAX_FILE_SIZE = os.environ.get("F7T_STORAGE_MAX_FILE_SIZE")
OBJECT_STORAGE=os.environ.get("F7T_OBJECT_STORAGE")

# debug on console
debug = os.environ.get("F7T_DEBUG_MODE", None)


app = Flask(__name__)

def set_services():
    for servicename in SERVICES:

        URL_ENV_VAR = f"F7T_{servicename.upper()}_URL"


        serviceurl = os.environ.get(URL_ENV_VAR)
        if serviceurl:
            SERVICES_DICT[servicename] = serviceurl

# test individual service function
def test_service(servicename, status_list):
    app.logger.info("Testing {servicename} microservice's status".format(servicename=servicename))

    try:
        serviceurl = SERVICES_DICT[servicename]
        #timeout set to 5 seconds
        req = requests.get("{url}/status".format(url=serviceurl), timeout=5, verify= (SSL_CRT if USE_SSL else False))

        app.logger.info("Return code: {status_code}".format(status_code=req.status_code))

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
def test_system(machinename, status_list=[]):

    app.logger.info("Testing {machinename} system's status".format(machinename=machinename))

    if machinename not in SYSTEMS_PUBLIC:
        status_list.append( {"status": -3, "system": machinename} )
        return

    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYSTEMS[i]
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
                           timeout=10)

    except paramiko.ssh_exception.AuthenticationException as e:
        # host up and SSH working, but returns (with reasons) authentication error
        app.logger.error(type(e))
        app.logger.error(e)
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
    
    status_list = []
    test_system(machinename,status_list)

    # possible responses:
    # 0: host up and SSH running
    # -1: host up but no SSH running
    # -2: host down
    # -3: host not in the list (does not exist)

    status = status_list[0]["status"]

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
        p = mp.Process(target=test_system, args=(machinename, status_list))
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
    #
        if status == -2:
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

    # update services:
    set_services()
    # show services availables for query
    # list_services()

    if servicename not in SERVICES_DICT.keys():
        return jsonify(description="Service does not exists"), 404

    # needs a list to be pass as reference
    # in compatibility with test all services
    status_list = []

    test_service(servicename,status_list)

    # as it's just 1 service tested, 0 index is always valid
    serv_status = status_list[0]["status"]

    if serv_status == -2:
        status = "not available"
        description = "server down"
    elif serv_status == -1:
        status = "not available"
        description = "server up, flask down"
    else:
        status="available"
        description="server up & flask running"

    return jsonify(service=servicename,status=status,description=description), 200

# get service information about all services
@app.route("/services", methods=["GET"])
@check_auth_header
def status_services():
    
    # update services:
    set_services()

    # resp_list list to fill with responses from each service
    resp_list=[]

    # list of processes
    process_list = []

    # memory manager
    mgr = mp.Manager()
    # create cross memory (between processes) list
    status_list = mgr.list()

    # for each servicename, creates a process
    for servicename,serviceurl in SERVICES_DICT.items():
        p = mp.Process(target=test_service, args=(servicename, status_list))
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


if __name__ == "__main__":
    # log handler definition
    # timed rotation: 1 (interval) rotation per day (when="D")
    logHandler=TimedRotatingFileHandler('/var/log/status.log', when='D', interval=1)

    logFormatter = logging.Formatter('%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                                    '%Y-%m-%dT%H:%M:%S')
    logHandler.setFormatter(logFormatter)
    logHandler.setLevel(logging.DEBUG)

    # get app log (Flask+werkzeug+python)
    logger = logging.getLogger()

    # set handler to logger
    logger.addHandler(logHandler)

    # run app
    if USE_SSL:        
        app.run(debug=debug, host='0.0.0.0', port=STATUS_PORT, ssl_context=(SSL_CRT, SSL_KEY))        
    else:
        app.run(debug=debug, host='0.0.0.0', port=STATUS_PORT)
