#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, request, jsonify, send_file

from logging.handlers import TimedRotatingFileHandler
import tempfile, os, socket, logging
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequestKeyError

from math import ceil
from cscs_api_common import check_header, get_username,exec_remote_command
import base64
import io

CERTIFICATOR_URL = os.environ.get("F7T_CERTIFICATOR_URL")
STATUS_IP        = os.environ.get("F7T_STATUS_IP")

UTILITIES_PORT   = os.environ.get("F7T_UTILITIES_PORT", 5000)

AUTH_HEADER_NAME = 'Authorization'

UTILITIES_TIMEOUT = int(os.environ.get("F7T_UTILITIES_TIMEOUT"))

# SYSTEMS: list of ; separated systems allowed
SYSTEMS_PUBLIC  = os.environ.get("F7T_SYSTEMS_PUBLIC").strip('\'"').split(";")
# internal machines for file operations
SYS_INTERNALS   = os.environ.get("F7T_SYSTEMS_INTERNAL_UTILITIES").strip('\'"').split(";")

debug = os.environ.get("F7T_DEBUG_MODE", None)

#max file size for upload/download in MB
MAX_FILE_SIZE=int(os.environ.get("F7T_UTILITIES_MAX_FILE_SIZE"))

app = Flask(__name__)
# max content lenght for upload in bytes
app.config['MAX_CONTENT_LENGTH'] = int(MAX_FILE_SIZE) * 1024 * 1024


# function to check if pattern is in string
def in_str(stringval,words):
    try:
        stringval.index(words)
        return True
    except AttributeError: #if is not str, then is byte encoding
        stringval = stringval.decode('latin-1')
        stringval.index(words)
        return True
    except ValueError:
        return False # if words never found


## file: determines the type of file of path
## params:
##  - path: Filesystem path (Str) *required
##  - machinename: str *required

@app.route("/file", methods=["GET"])
def file_type():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error in file operation", error="Machine does not exist"), 400, header

    # iterate over SYSTEMS list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        path = request.args.get("targetPath")
    except BadRequestKeyError as e:
        return jsonify(description="Error in file operation",error="'targetPath' query string missing"), 400


    action = f"timeout {UTILITIES_TIMEOUT} file -b -- '{path}'"

    retval = exec_remote_command(auth_header, machine, action)

    error_str = retval["msg"]

    if retval["error"] != 0:
        if retval["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description="Error in file operation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error in file operation"), 400, header

        #in case of permission for other user
        if in_str(error_str,"Permission") or in_str(retval["msg"],"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Error in file operation"), 404, header

        # otherwise, generic error
        return jsonify(description="Error in file operation", error=error_str), 404

    # for file, is not an error (echo $? = 0) if the file doesn't exist or user has not permissions
    if in_str(error_str, "cannot open"):
        header = {"X-Invalid-Path": "{path} is an invalid path".format(path=path)}
        return jsonify(description="Error in file operation"), 400, header

    if in_str(error_str, "read permission"):
        header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
        return jsonify(description="Error in file operation"), 400, header

    return jsonify(description="Operation completed", out=retval["msg"]), 200


## chmod: Change Mode of path in Filesystem
## params:
##  - path: Filesystem path (Str) *required
##  - mode: numerical mode for file (e.g.: 700, 644, etc) *required
##  - machinename: str *required

@app.route("/chmod",methods=["PUT"])
def chmod():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error in chmod operation", error="Machine does not exist"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    # getting path from request form
    try:
        path = request.form["targetPath"]
    except BadRequestKeyError:
        return jsonify(description="Error in chmod operation",error="'targetPath' query string missing"), 400

    # getting chmode's mode from request form:
    try:
        mode = request.form["mode"]
    except BadRequestKeyError:
        return jsonify(description="Error in chmod operation", error="mode query string missing"), 400

    # using -c flag for verbose mode in stdout
    action = f"timeout {UTILITIES_TIMEOUT} chmod -v '{mode}' -- '{path}'"

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        if retval["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description="Error in chmod operation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error in chmod operation"), 400, header

        error_str = retval["msg"]

        if in_str(error_str, "cannot access"):
            header = {"X-Invalid-Path": "{path} is an invalid path".format(path=path)}
            return jsonify(description="Error in chmod operation"), 400, header

        if in_str(error_str, "not permitted") or in_str(retval["msg"],"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Error in chmod operation"), 400, header

        if in_str(error_str, "invalid mode"):
            header = {"X-Invalid-Mode": "{mode} is an invalid mode".format(mode=mode)}
            return jsonify(description="Error in chmod operation"), 400, header

        #otherwise, generic error
        return jsonify(description="Error in chmod operation", error=error_str), 404

    return jsonify(description="Operation completed", out=retval["msg"]), 200


## chown: Change owner of path in Filesystem
## params:
##  - path: Filesystem path (Str) *required
##  - owner: new user owner of the path file
##  - group: new group owner of the path file
##  - machinename: str *required

@app.route("/chown",methods=["PUT"])
def chown():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error in chown operation", error="Machine does not exist"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        path = request.form["targetPath"]
    except BadRequestKeyError:
        return jsonify(description="Error in chown operation",error="'targetPath' query string missing"), 400

    if path == None:
        return jsonify(description="Error in chown operation",error="'targetPath' query string missing"), 400
    try:
        owner = request.form["owner"]
    except Exception:
        owner = ""

    try:
        group = request.form["group"]
    except Exception:
        group = ""

    if owner == "" and group == "":
        return jsonify(description="Error in chown operation", error="group and/or owner should be set"), 400


    action = f"timeout {UTILITIES_TIMEOUT} chown -v '{owner}':'{group}' -- '{path}'"

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        if retval["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description="Error in chown operation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error in chown operation"), 400, header

        error_str = retval["msg"]

        if in_str(error_str,"cannot access"):
            header={"X-Invalid-Path":"{path} is an invalid path".format(path=path)}
            return jsonify(description="Error in chown operation"), 400, header

        if in_str(error_str,"not permitted") or in_str(retval["msg"],"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Error in chown operation"), 400, header

        if in_str(error_str,"invalid group"):
            header = {"X-Invalid-Group": "{group} is an invalid group".format(group=group)}
            return jsonify(description="Error in chown operation"), 400, header

        if in_str(error_str,"invalid user"):
            header = {"X-Invalid-Owner": "{owner} is an invalid user".format(owner=owner)}
            return jsonify(description="Error in chown operation"), 400, header

        return jsonify(description="Error in chown operation", error=error_str), 404


    return jsonify(description="Operation completed", out=retval["msg"]), 200


## ls: List Directory contents
## params:
##  - path: Filesystem path (Str) *required
##  - showhidden: Bool
##  - machinename: str *required

@app.route("/ls",methods=["GET"])
def list_directory():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error listing contents of path", error="Machine does not exist"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        path = request.args.get("targetPath")
    except BadRequestKeyError:
        return jsonify(description="Error in ls operation",error="'targetPath' query string missing"), 400

    if path == None:
        return jsonify(description="Error listing contents of path",error="path query string missing"), 400

    # if set shows entrys starting with . (not including . and/or .. dirs)
    try:
        showhidden = request.args.get("showhidden", None)
    except BadRequestKeyError:
        return jsonify(description="Error in ls operation", error="option error"), 400

    showall = ""
    if showhidden != None:
        showall = "-A"

    action = f"timeout {UTILITIES_TIMEOUT} ls -l {showall} --time-style=+%Y-%m-%dT%H:%M:%S -- '{path}'"

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            header = {"X-Machine-Not-Available":"Machine is not available"}
            return jsonify(description="Error listing contents of path"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error listing contents of path"), 400, header

        if in_str(error_str,"cannot access"):

            header={"X-Invalid-Path":"{path} is an invalid path".format(path=path)}
            return jsonify(description="Error listing contents of path"), 400, header

        if in_str(error_str,"cannot open") or in_str(retval["msg"],"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Error listing contents of path"), 400, header

        # generic not caught error
        return jsonify(description="Error listing contents of path",error=retval["msg"]), 400


    # file List is retorned as a string separated for a $ character
    fileList = []
    if len(retval["msg"].split("$")) == 1:
        # if only one line is returned, there are two cases:
        # 1. 'total 0': means directory was empty, so fileList is kept empty
        # 2. 'r.....   some_file.txt': means 'ls' was to only one file: 'ls /home/user/some.txt'
        if retval["msg"][0:5]!='total':
            fileList = retval["msg"].split("$")
    else:
        fileList = retval["msg"].split("$")[1:]

    totalSize = len(fileList)

    # if pageSize and number were set:
    pageSize = request.args.get("pageSize")
    pageNumber = request.args.get("pageNumber")

    app.logger.info(f"PageSize: {pageSize}. PageNumber: {pageNumber}")

    # calculate the list to retrieve
    if pageSize and pageNumber:

        pageNumber = float(pageNumber)
        pageSize   = float(pageSize)

        totalPages = int(ceil(float(totalSize) / float(pageSize)))

        app.logger.info(f"Total Size: {totalSize}")
        app.logger.info(f"Total Pages: {totalPages}")


        if pageNumber < 1 or pageNumber>totalPages:
            app.logger.warning("pageNumber ({pageNumber}) greater than total pages ({totalPages})".format(pageNumber=pageNumber, totalPages=totalPages))
            app.logger.warning("Showing all results")
        else:
            beg_reg=int((pageNumber-1)*pageSize)
            end_reg=int(pageNumber*pageSize-1)

            app.logger.info("Initial reg {beg_reg}, final reg: {end_reg}".format(beg_reg=beg_reg, end_reg=end_reg))

            fileList = fileList[beg_reg:end_reg+1]


    outLabels = ["name","type","link_target","user","group","permissions","last_modified","size"]

    # labels taken from list to dict with default value: ""
    outList = []

    logging.info("Length of file list: {}".format(len(fileList)))

    for files in fileList:

        line = files.split()

        try:
            symlink = line[8] # because of the -> which is 7
        except IndexError:
            symlink = ""

        outDict = {outLabels[0]:line[6],
                outLabels[1]:line[0][0],
                outLabels[2]:symlink,
                outLabels[3]:line[2],
                outLabels[4]:line[3],
                outLabels[5]:line[0][1:],
                outLabels[6]:line[5],
                outLabels[7]:line[4]
                }

        outList.append(outDict)

    return jsonify(descr="List of contents of path",output=outList), 200


## mkdir: Make Directory
## params:
##  - path: Filesystem path (Str) *required
##  - p: -p, --parents no error if existing, make parent directories as needed (bool)
##  - machinename: str *required

@app.route("/mkdir",methods=["POST"])
def make_directory():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error creating directory", error="Machine does not exist"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        path = request.form["targetPath"]
    except BadRequestKeyError:
        return jsonify(description="Error creating directory", error="'targetPath' query string missing"), 400

    try:
        p = request.form["p"]
        parent = "-p"
    except BadRequestKeyError:
        parent = ""

    action = f"timeout {UTILITIES_TIMEOUT} mkdir {parent} -- '{path}'"

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            header = {"X-Machine-Not-Available":"Machine is not available"}
            return jsonify(description="Error creating directory"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error creating directory"), 400, header

        if in_str(error_str,"No such file"):
            header={"X-Invalid-Path":"{path} is an invalid path".format(path=path)}
            return jsonify(description="Error creating directory"), 400, header

        if in_str(error_str,"Permission denied") or in_str(retval["msg"],"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Error creating directory"), 400, header

        if in_str(error_str,"File exists"):
            header = {"X-Exists": "{path} already exists".format(path=path)}
            return jsonify(description="Error creating directory"), 400, header

        return jsonify(description="Error creating directory",error=retval["msg"]), 400


    return jsonify(description="Directory created", output=""), 201


## rename/move
## params:
##  - oldpath: Filesystem path of current object (Str) *required
##  - newpath: Filesystem path of new object (Str) *required
##  - machinename: str *required

@app.route("/rename", methods=["PUT"])
def rename():
    return common_operation(request, "rename", "PUT")


## copy cp
## params:
##  - sourcepath: Filesystem path of object to be copied (Str) *required
##  - targetpath: Filesystem path of copied object (Str) *required
##  - machinename: str *required

@app.route("/copy", methods=["POST"])
def copy():
    return common_operation(request, "copy", "POST")

## common code for file operations: copy, rename (move)
def common_operation(request, command, method):
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error on " + command + " operation", error="Machine does not exist"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        sourcePath = request.form["sourcePath"]
    except BadRequestKeyError:
        return jsonify(description="Error on " + command + " operation", error="'sourcePath' query string missing"), 400

    try:
        targetPath = request.form["targetPath"]
    except BadRequestKeyError:
        return jsonify(description="Error on " + command + " operation", error="target query string missing"), 400


    if command == "copy":
        # action to execute
        # -r is for recursivelly copy files into directories
        action = f"timeout {UTILITIES_TIMEOUT} cp --force -dR --preserve=all -- '{sourcePath}' '{targetPath}'"
        success_code = 201
    elif command == "rename":
        action = f"timeout {UTILITIES_TIMEOUT} mv --force -- '{sourcePath}' '{targetPath}'"
        success_code = 200
    else:
        app.logger.error("Unknown command on common_operation: " + command)
        return jsonify(description="Error on unkownon operation", error="Unknown"), 400

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            header = {"X-Machine-Not-Available":"Machine is not available"}
            return jsonify(description="Error on " + command + " operation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error on " + command + " operation"), 400, header

        # error no such file
        if in_str(error_str,"No such file"):
            if in_str(error_str,"cannot stat"):
                header={"X-Not-Found":"{sourcePath} not found.".format(sourcePath=sourcePath)}
                return jsonify(description="Error on " + command + " operation"), 400, header

            # copy: cannot create, rename: cannot move
            if in_str(error_str, "cannot create") or in_str(error_str,"cannot move"):
                header = {"X-Invalid-Path": "{sourcePath} and/or {targetPath} are invalid paths.".format(sourcePath=sourcePath, targetPath=targetPath)}
                return jsonify(description="Error on " + command + " operation"), 400, header

        # permission denied
        if in_str(error_str,"Permission denied") or in_str(retval["msg"],"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
            return jsonify(description="Error on " + command + " operation"), 400, header

        # if already exists, not overwrite (-i)
        if in_str(error_str,"overwrite"):
            header = {"X-Exists": "{targetPath} already exists".format(targetPath=targetPath)}
            return jsonify(description="Error on " + command + " operation"), 400, header

        return jsonify(description="Error on copy operation"), 400

    return jsonify(description="Success to " + command + " file or directory.", output=""), success_code



## Remove file or directory
## params:
## - path: path to the file or directory to be removed
## - X-Machine-Name: system

@app.route("/rm", methods=["DELETE"])
def rm():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error on delete operation", error="Machine does not exist"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        path = request.form["targetPath"]
    except BadRequestKeyError:
        return jsonify(description="Error on delete operation",error="'targetPath' query string missing"), 400

    # action to execute
    # -r is for recursivelly delete files into directories
    action = f"timeout {UTILITIES_TIMEOUT} rm -fr -- '{path}'"

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            header = {"X-Machine-Not-Available":"Machine is not available"}
            return jsonify(description="Error on delete operation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error on delete operation"), 400, header

        # error no such file
        if in_str(error_str,"No such file"):
            if in_str(error_str,"cannot remove"):
                header = {"X-Invalid-Path": "{path} is an invalid path.".format(path=path)}
                return jsonify(description="Error on delete operation"), 400, header

        # permission denied
        if in_str(error_str,"Permission denied") or in_str(retval["msg"],"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Error on delete operation"), 400, header

        return jsonify(description="Error on delete operation"), 400


    return jsonify(description="Success to delete file or directory.", output=""), 204



## Symbolic Link
## params:
##  - target: path to target that the symlink will point to (Str) *required
##  - source: absolute path to the new symlink *required
##  - machinename: str *required

@app.route("/symlink", methods=["POST"])
def symlink():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Failed to create symlink", error="Machine does not exist"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        linkPath = request.form["linkPath"]
    except BadRequestKeyError:
        return jsonify(description="Failed to create symlink",error="'linkPath' query string missing"), 400

    try:
        targetPath = request.form["targetPath"]
    except BadRequestKeyError:
        return jsonify(description="Failed to create symlink",error="'targetPath' query string missing"), 400

    action = f"timeout {UTILITIES_TIMEOUT} ln -s -- '{targetPath}' '{linkPath}'"

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            header = {"X-Machine-Not-Available":"Machine is not available"}
            return jsonify(description="Failed to create symlink"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Failed to create symlink"), 400, header

        # error no such file
        if in_str(error_str,"No such file"):
            header = {"X-Invalid-Path": "{targetPath} and/or {linkPath} are invalid paths.".format(targetPath=targetPath,linkPath=linkPath)}
            return jsonify(description="Failed to create symlink"), 400, header

        # permission denied
        if in_str(error_str,"Permission denied") or in_str(retval["msg"],"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
            return jsonify(description="Failed to create symlink"), 400, header

        # if already exists
        if in_str(error_str,"File exists"):
            header = {"X-Exists": "{linkPath} already exists".format(linkPath=linkPath)}
            return jsonify(description="Failed to create symlink"), 400, header


        return jsonify(description="Failed to create symlink"), 400


    return jsonify(description="Success create the symlink"), 201

## Returns the file from the specified path on the {machine} filesystem
## params:
##  - path: path to the file to download *required
##  - machinename: str *required

@app.route("/download", methods=["GET"])
def download():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Failed to download file", error="Machine does not exist"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    path = request.args.get("sourcePath")

    if path == None:
        return jsonify(description="Failed to download file",error="'sourcePath' query string missing"), 400

    #TODO: check path doesn't finish with /
    file_name = secure_filename(path.split("/")[-1])

    action = f"timeout {UTILITIES_TIMEOUT} stat --dereference -c %s -- '{path}'"
    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        if in_str(retval["msg"],"Permission") or in_str(retval["msg"],"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
            return jsonify(description="Failed to download file"), 400, header
        else:
            return jsonify(description="Failed to download file"), 400

    try:
        file_size = int(retval["msg"]) # in bytes
        if file_size > MAX_FILE_SIZE*(1024*1024):
            app.logger.warning("File size exceeds limit")
            # custom error raises when file size > SIZE_LIMIT env var
            header = {"X-Size-Limit": "File exceeds size limit"}
            return jsonify(description="Failed to download file"), 400, header
        elif file_size == 0:
            # may be empty, a special file or a directory, just return empty
            data = io.BytesIO()
            data.seek(0)
            return send_file(data,
                     mimetype="application/octet-stream",
                     attachment_filename=file_name,
                     as_attachment=True)

    except Exception as e:
        app.logger.error("Download decode error: " + e.message)
        return jsonify(description="Failed to download file"), 400

    # download with base64 to avoid encoding conversion and string processing
    action = f"timeout {UTILITIES_TIMEOUT} base64 --wrap=0 -- '{path}'"
    retval = exec_remote_command(auth_header, machine, action, file_transfer="download")

    # posible errors

    # IOError 13: Permission denied
    if retval["error"] == 13:
        header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
        return jsonify(description="Failed to download file"), 400, header

    # IOError 2: no such file
    if retval["error"] == 2:
        header = {"X-Invalid-Path": "{path} is invalid.".format(path=path)}
        return jsonify(description="Failed to download file"), 400, header

    # IOError -2: name or service not known
    if retval["error"] == -2:
        header = {"X-Machine-Not-Available": "Machine is not available"}
        return jsonify(description="Failed to download file"), 400, header

    if retval["error"] != 0:
        if in_str(retval["msg"],"Permission") or in_str(retval["msg"],"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
            return jsonify(description="Failed to download file"), 400, header
        else:
            return jsonify(description="Failed to download file"), 400

    try:
        data = io.BytesIO()
        data.write(base64.b64decode(retval["msg"]))
        data.seek(0)
    except Exception as e:
        app.logger.error("Download decode error: " + e.message)
        return jsonify(description="Failed to download file"), 400

    return send_file(data,
                     mimetype="application/octet-stream",
                     attachment_filename=file_name,
                     as_attachment=True)


## Returns the file from the specified path on the {machine} filesystem
## params:
##  - path: path to the file to download *required
##  - machinename: str *required

## error handler for files above SIZE_LIMIT -> app.config['MAX_CONTENT_LENGTH']
@app.errorhandler(413)
def request_entity_too_large(error):
    app.logger.error(error)
    return jsonify(description="Failed to upload file. The file is over {} MB".format(MAX_FILE_SIZE)), 413

@app.route("/upload", methods=["POST"])
def upload():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Failed to upload file", error="Machine does not exist"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    path = request.form["targetPath"]

    if path == None:
        return jsonify(description="Failed to upload file", error="'targetPath' query string missing"), 400

    if 'file' not in request.files:
        return jsonify(description="Failed to upload file", error="No file in query"), 400

    file = request.files['file']

    app.logger.info("Length: {length}".format(length=file.content_length))
    app.logger.info("Headers: {headers}".format(headers=file.headers))

    if file.filename == '':
        return jsonify(description="Failed to upload file", error="No file selected"), 400

    filename = secure_filename(file.filename)
    action = f"cat > {path}/{filename}"
    retval = exec_remote_command(auth_header, machine, action, file_transfer="upload", file_content=file.read())

    # IOError 13: Permission denied
    if retval["error"] == 13:
        header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
        return jsonify(description="Failed to upload file"), 400, header

    # IOError 2: no such file
    if retval["error"] == 2:
        header = {"X-Invalid-Path": "{path} is invalid.".format(path=path)}
        return jsonify(description="Failed to upload file"), 400, header

    # IOError -2: name or service not known
    if retval["error"] == -2:
        header = {"X-Machine-Not-Available": "Machine is not available"}
        return jsonify(description="Failed to upload file"), 400, header

    if retval["error"] != 0:
        if in_str(retval["msg"],"Permission") or in_str(retval["msg"],"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
            return jsonify(description="Failed to upload file"), 400, header
        else:
            return jsonify(description="Failed to upload file"), 400

    return jsonify(description="File upload successful"), 201


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
    logHandler = TimedRotatingFileHandler('/var/log/utilities.log', when='D', interval=1)

    logFormatter = logging.Formatter('%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                                     '%Y-%m-%d:%H:%M:%S')
    logHandler.setFormatter(logFormatter)
    logHandler.setLevel(logging.DEBUG)

    # get app log (Flask+werkzeug+python)
    logger = logging.getLogger()

    # set handler to logger
    logger.addHandler(logHandler)

    # run app
    # debug = False, so output redirects to log files
    app.run(debug=debug, host='0.0.0.0', port=UTILITIES_PORT)
