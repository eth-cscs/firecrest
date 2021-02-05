#
#  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, request, jsonify

from werkzeug.exceptions import BadRequestKeyError, InternalServerError, MethodNotAllowed

# task states
import os
import logging
from logging.handlers import TimedRotatingFileHandler
from cscs_api_common import check_auth_header, exec_remote_command, in_str

import re
import datetime


AUTH_HEADER_NAME = 'Authorization'

RESERVATIONS_PORT    = os.environ.get("F7T_RESERVATIONS_PORT", 5050)

# SYSTEMS: list of ; separated systems allowed
SYSTEMS_PUBLIC  = os.environ.get("F7T_SYSTEMS_PUBLIC").strip('\'"').split(";")
# internal machines for file operations
SYS_INTERNALS   = os.environ.get("F7T_SYSTEMS_INTERNAL_COMPUTE").strip('\'"').split(";")

# time out for rsvmgmt command
TIMEOUT = os.environ.get("F7T_UTILITIES_TIMEOUT", 5)

### SSL parameters
USE_SSL = os.environ.get("F7T_USE_SSL", False)
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_KEY = os.environ.get("F7T_SSL_KEY", "")

RESERVATION_CMD = os.environ.get("F7T_RESERVATION_CMD", "rsvmgmt")

debug = os.environ.get("F7T_DEBUG_MODE", None)


app = Flask(__name__)

# checks if reservation/account name are valid
# accepts identifier names format and includes dash and underscore names.
def check_name(name):
    regex="^[a-z_$][-a-z_$0-9]*$"

    # can start with alphabetics letters in caps or not, or underscore,
    # can have (after first char) numbers.

    match = re.compile(regex).match(name)

    return bool(match)


# parse a string to a int, in order to check if it's valid
# positive number > 0 (also, it should be <= 1000, for number of nodes, but not checking)
def check_number(number):
    try:
        n=int(number)
        if n<1:
            return False
    except ValueError:
        return False
    return True


# checks if reservation times (endtime/starttime) are correct:
def check_dateTime(dateTime):
    try:
        # the one format that is valid is YYYY-MM-DDTHH:MM:SS
        datetime.datetime.strptime(dateTime, "%Y-%m-%dT%H:%M:%S")
        return True
    except ValueError:
        return False


# compare dates to see if d1<d2 (used on starttime < endtime)
# it's assumed that format is correct (using check_dateTime)
def check_dateDiff(start_date,end_date):
    d1=datetime.datetime.strptime(start_date,"%Y-%m-%dT%H:%M:%S")
    d2=datetime.datetime.strptime(end_date,"%Y-%m-%dT%H:%M:%S")

    return d1 < d2



# checks if actual date is less than the start date of the reservation
def check_actualDate(start_date):

    # local date from the server
    actual_date = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    return check_dateDiff(actual_date,start_date)





@app.route("/",methods=["GET"])
@check_auth_header
def get():

    auth_header = request.headers[AUTH_HEADER_NAME]

    # checks if machine name is set
    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(error="Error listing reservation", description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(error="Error listing reservation"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    # list reservations
    action = f"timeout {TIMEOUT} {RESERVATION_CMD} -l"

    #execute command
    retval = exec_remote_command(auth_header, system_name, system_addr, action)

    error_str = retval["msg"]

    if retval["error"] != 0:
        if retval["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(error="Error listing reservations"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(error="Error listing reservations"), 400, header

        #in case of permission for other user
        # sudo error returned:
        #
        # "We trust you have received the usual lecture from the local SystemAdministrator. It usually boils down to these three things:
        # #1) Respect the privacy of others.    #2) Think before you type.    #3) With great power comes great responsibility.sudo:
        # no tty present and no askpass program specified
        #
        if in_str(error_str,"Permission") or in_str(error_str,"SystemAdministrator"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(error="Error listing reservations"), 404, header


        # otherwise, generic error
        return jsonify(error="Error listing reservations", description=error_str), 400

    output = retval["msg"]
    # output should have this format:
    ## if some reservation:
    #
    #
    ## rsvmgmt: Current Reservations
    ## ---------------------------
    ## ReservationName=selvedas StartTime=2020-12-24T08:00:00 EndTime=2020-12-25T12:30:00 Duration=1-04:30:00 Nodes=nid0000[0-9] NodeCnt=10
    ## CoreCnt=640 Features=knl PartitionName=normal Flags= TRES=cpu=2560 Users=(null) Accounts=csstaff Licenses=(null) State=INACTIVE BurstBuffer=(null) Watts=n/a
    ## ---------------------------
    #
    ## if not reservation found
    #
    #
    ## rsvmgmt: Current Reservations
    ## ---------------------------
    ## ---------------------------

    reservations = []

    # selects only what is between ----- lines
    output_list = output.split("$")[2:-1]


    for _output in output_list:
        # split by space
        _output = _output.split()


        if len(_output) == 1: # then no reservations
            break

        # otherwise this is the output list:
        # ['ReservationName=selvedas', 'StartTime=2020-12-24T08:00:00', 'EndTime=2020-12-25T12:30:00', 'Duration=1-04:30:00', 'Nodes=nid0000[0-9]', 'NodeCnt=10',
        # 'CoreCnt=640', 'Features=knl', 'PartitionName=normal', 'Flags=', 'TRES=cpu=2560', 'Users=(null)', 'Accounts=csstaff', 'Licenses=(null)', 'State=INACTIVE', 'BurstBuffer=(null)', 'Watts=n/a']

        rsv_dict = {}
        for item in _output:
            try:
                key, value = item.split("=")
                rsv_dict[key.lower()] = value
            except ValueError:
                continue

        reservations.append(rsv_dict)


    # return list
    data = jsonify(success=reservations)
    return data, 200

# create a new task, response should be task_id of created task
@app.route("/",methods=["POST"])
@check_auth_header
def post():

    auth_header = request.headers[AUTH_HEADER_NAME]

    # checks if machine name is set
    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(error="Error creating reservation", description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(error="Error creating reservation"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    # checking input data
    # getting reservation name from request form
    try:
        reservation = request.form["reservation"]
        if not check_name(reservation):
            return jsonify(error="Error creating reservation", description=f"'reservation' parameter format is not valid (value entered:'{reservation}')"), 400
    except BadRequestKeyError:
        return jsonify(error="Error creating reservation", description="'reservation' form data input missing"), 400

    # getting account name from request form
    try:
        account = request.form["account"]
        if not check_name(account):
            return jsonify(error="Error creating reservation", description=f"'account' parameter format is not valid (value entered:'{account}')"), 400
    except BadRequestKeyError:
        return jsonify(error="Error creating reservation", description="'account' form data input missing"), 400

    # getting numberOfNodes from request form
    try:
        numberOfNodes = request.form["numberOfNodes"]
        if not check_number(numberOfNodes):
            return jsonify(error="Error creating reservation", description=f"'numberOfNodes' parameter is not valid. It should be an integer > 0 (value entered:'{numberOfNodes}')"), 400
    except BadRequestKeyError:
        return jsonify(error="Error creating reservation", description="'numberOfNodes' form data input missing"), 400

    # getting nodeType from request form
    try:
        nodeType = request.form["nodeType"]
        if not check_name(nodeType):
            return jsonify(error="Error creating reservation", description=f"'nodeType' parameter format is not valid (value entered:'{nodeType}')"), 400
    except BadRequestKeyError:
        return jsonify(error="Error creating reservation", description="'nodeType' form data input missing"), 400

    # getting starttime from request form
    try:
        starttime = request.form["starttime"]
        if not check_dateTime(starttime):
            return jsonify(error="Error creating reservation", description=f"'starttime' parameter format is not valid. It should be YYYY-MM-DDTHH:MM:SS (value entered:'{starttime}')"), 400
    except BadRequestKeyError:
        return jsonify(error="Error creating reservation", description="'starttime' form data input missing"), 400

    # getting endtime from request form
    try:
        endtime = request.form["endtime"]
        if not check_dateTime(endtime):
            return jsonify(error="Error creating reservation", description=f"'endtime' parameter format is not valid. It should be YYYY-MM-DDTHH:MM:SS (value entered:'{endtime}')"), 400
    except BadRequestKeyError:
        return jsonify(error="Error creating reservation", description="'endtime' form data input missing"), 400

    if not check_dateDiff(starttime,endtime):
        return jsonify(error="Error creating reservation", description=f"'endtime' occurs before 'starttime' (values entered: endtime='{endtime}' <= starttime='{starttime}')"), 400

    if not check_actualDate(starttime):
        return jsonify(error="Error creating reservation", description=f"'starttime' is in the pass (values entered: starttime='{starttime}')"), 400

    # create a reservation
    # rsvmgmt -a unixGroupName numberOfNodes NodeType startDateTime endDateTime [optional reservationName]
    action = f"timeout {TIMEOUT} {RESERVATION_CMD} -a {account} {numberOfNodes} {nodeType} {starttime} {endtime} {reservation}"

    #execute command
    retval = exec_remote_command(auth_header, system_name, system_addr, action)

    error_str = retval["msg"]

    if retval["error"] != 0:
        if retval["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(error="Error creating reservation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(error="Error creating reservation"), 400, header

        #in case of permission for other user
        if in_str(error_str,"Permission") or in_str(error_str,"SystemAdministrator"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(error="Error creating reservation"), 404, header

        # otherwise, generic error
        # First cleanup "timeout:"  error string.
        # Then if it comes from rsvmgmt this is the format
        #    rsvmgmt: Error: You are not a member of the $1 project"
        # let's extract "rsvmgmt: Error: " string so it reports "You are not a member of the $1 project"

        error_str = error_str.lstrip("timeout:")
        error_str = error_str.lstrip("rsvmgmt:")
        error_str = error_str.lstrip("Error: ")


        return jsonify(error="Error creating reservation", description=error_str), 400

    output = retval["msg"]
    # Reservation created: {reservation}

    data = jsonify(success=output)
    return data, 201





# update status of the task with task_id = id
@app.route("/<reservation>",methods=["PUT"])
@check_auth_header
def put(reservation):

    auth_header = request.headers[AUTH_HEADER_NAME]

    # checks if machine name is set
    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(error="Error updating reservation", description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(error="Error updating reservation"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    # checking input data
    if not check_name(reservation):
        return jsonify(error="Error updating reservation", description=f"'reservation' parameter format is not valid (value entered:'{reservation}')"), 400

    # getting numberOfNodes from request form
    try:
        numberOfNodes = request.form["numberOfNodes"]
        if not check_number(numberOfNodes):
            return jsonify(error="Error updating reservation", description=f"'numberOfNodes' parameter is not valid. It should be an integer > 0 (value entered:'{numberOfNodes}')"), 400
    except BadRequestKeyError:
        return jsonify(error="Error updating reservation", description="'numberOfNodes' form data input missing"), 400

    # getting nodeType from request form
    try:
        nodeType = request.form["nodeType"]
        if not check_name(nodeType):
            return jsonify(error="Error updating reservation", description=f"'nodeType' parameter format is not valid (value entered:'{nodeType}')"), 400
    except BadRequestKeyError:
        return jsonify(error="Error updating reservation", description="'nodeType' form data input missing"), 400

    # getting starttime from request form
    try:
        starttime = request.form["starttime"]
        if not check_dateTime(starttime):
            return jsonify(error="Error updating reservation", description=f"'starttime' parameter format is not valid. It should be YYYY-MM-DDTHH:MM:SS (value entered:'{starttime}')"), 400
    except BadRequestKeyError:
        return jsonify(error="Error updating reservation", description="'starttime' form data input missing"), 400

    # getting endtime from request form
    try:
        endtime = request.form["endtime"]
        if not check_dateTime(endtime):
            return jsonify(error="Error updating reservation", description=f"'endtime' parameter format is not valid. It should be YYYY-MM-DDTHH:MM:SS (value entered:'{endtime}')"), 400
    except BadRequestKeyError:
        return jsonify(error="Error updating reservation", description="'endtime' form data input missing"), 400

    if not check_dateDiff(starttime,endtime):
        return jsonify(error="Error updating reservation", description=f"'endtime' occurs before 'starttime' (values entered: endtime='{endtime}' <= starttime='{starttime}')"), 400

    if not check_actualDate(starttime):
        return jsonify(error="Error creating reservation", description=f"'starttime' is in the pass (values entered: starttime='{starttime}')"), 400

    # Update a reservation
    # rsvmgmt -u reservationName numberOfNodes NodeType StartDateTime EndDateTime
    action = f"timeout {TIMEOUT} {RESERVATION_CMD} -u {reservation} {numberOfNodes} {nodeType} {starttime} {endtime}"

    #execute command
    retval = exec_remote_command(auth_header, system_name, system_addr, action)
    error_str = retval["msg"]

    if retval["error"] != 0:
        if retval["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(error="Error updating reservation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(error="Error updating reservation"), 400, header

        #in case of permission for other user
        if in_str(error_str,"Permission") or in_str(error_str,"SystemAdministrator"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(error="Error updating reservation"), 404, header

        # otherwise, generic error
        # First cleanup "timeout:"  error string.
        # Then if it comes from rsvmgmt this is the format
        #    rsvmgmt: Error: You are not a member of the $1 project"
        # let's extract "rsvmgmt: Error: " string so it reports "You are not a member of the $1 project"

        error_str = error_str.lstrip("timeout:")
        error_str = error_str.lstrip("rsvmgmt:")
        error_str = error_str.lstrip("Error: ")

        return jsonify(error="Error updating reservation", description=error_str), 400

    output = retval["msg"]
    # Reservation updated

    data = jsonify(success=output)
    return data, 200



@app.route("/<reservation>",methods=["DELETE"])
@check_auth_header
def delete(reservation):

    auth_header = request.headers[AUTH_HEADER_NAME]

    # checks if machine name is set
    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(error="Error deleting reservation", description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(error="Error deleting reservation"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    # checking input data
    if not check_name(reservation):
        return jsonify(error="Error deleting reservation", description=f"'reservation' parameter format is not valid (value entered:'{reservation}')"), 400

    # Update a reservation
    # rsvmgmt -d reservationName
    action = f"timeout {TIMEOUT} {RESERVATION_CMD} -d {reservation}"

    #execute command
    retval = exec_remote_command(auth_header, system_name, system_addr, action)

    error_str = retval["msg"]

    if retval["error"] != 0:
        if retval["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(error="Error deleting reservation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(error="Error deleting reservation"), 400, header

        #in case of permission for other user
        if in_str(error_str,"Permission") or in_str(error_str,"SystemAdministrator"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(error="Error deleting reservation"), 404, header

        # otherwise, generic error
        # First cleanup "timeout:"  error string.
        # Then if it comes from rsvmgmt this is the format
        #    rsvmgmt: Error: You are not a member of the $1 project"
        # let's extract "rsvmgmt: Error: " string so it reports "You are not a member of the $1 project"

        error_str = error_str.lstrip("timeout:")
        error_str = error_str.lstrip("rsvmgmt:")
        error_str = error_str.lstrip("Error: ")

        return jsonify(error="Error deleting reservation", description=error_str), 400

    output = retval["msg"]
    # "rsvmgmt: Reservation csstaff_32 removed", removing "rsvmgmt: "

    output = output.lstrip("rsvmgmt: ")

    data = jsonify(success=output)
    return data, 204

@app.route("/status",methods=["GET"])
def status():
    app.logger.info("Test status of service")
    # TODO: check backend reservation binary to truthfully respond this request
    return jsonify(success="ack"), 200

@app.errorhandler(MethodNotAllowed)
def page_not_found(e):
     return jsonify (error='Method not allowed', description=e.description), 405

@app.errorhandler(InternalServerError)
def internal_error(e):
    app.logger.error(e.description)
    app.logger.error(e.original_exception)
    return jsonify(error='FirecREST Internal error', description=e.description), 500


if __name__ == "__main__":
    # log handler definition
    # timed rotation: 1 (interval) rotation per day (when="D")
    logHandler = TimedRotatingFileHandler('/var/log/reservations.log', when='D', interval=1)

    logFormatter = logging.Formatter('%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                                     '%Y-%m-%d:%H:%M:%S')
    logHandler.setFormatter(logFormatter)
    logHandler.setLevel(logging.DEBUG)

    # get app log (Flask+werkzeug+python)
    logger = logging.getLogger()

    # set handler to logger
    logger.addHandler(logHandler)

    # set to debug = False, so stderr and stdout go to log file

    # run app
    if USE_SSL:
        app.run(debug=debug, host='0.0.0.0', use_reloader=False, port=RESERVATIONS_PORT, ssl_context=(SSL_CRT, SSL_KEY))
    else:
        app.run(debug=debug, host='0.0.0.0', use_reloader=False, port=RESERVATIONS_PORT)
