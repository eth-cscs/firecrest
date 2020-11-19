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

from cscs_api_common import check_auth_header, get_username,exec_remote_command, parse_io_error, check_command_error, in_str
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

### SSL parameters
USE_SSL = os.environ.get("F7T_USE_SSL", False)
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_KEY = os.environ.get("F7T_SSL_KEY", "")

app = Flask(__name__)
# max content lenght for upload in bytes
app.config['MAX_CONTENT_LENGTH'] = int(MAX_FILE_SIZE) * 1024 * 1024

## file: determines the type of file of path
## params:
##  - path: Filesystem path (Str) *required
##  - machinename: str *required

@app.route("/file", methods=["GET"])
@check_auth_header
def file_type():
    
    auth_header = request.headers[AUTH_HEADER_NAME]

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error in file operation", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    try:
        path = request.args.get("targetPath")
        if path == "":
            return jsonify(description="Error in file operation",error="'targetPath' value is empty"), 400
    except BadRequestKeyError as e:
        return jsonify(description="Error in file operation",error="'targetPath' query string missing"), 400


    action = f"timeout {UTILITIES_TIMEOUT} file -b -- '{path}'"

    retval = exec_remote_command(auth_header, system_name, system_addr, action)

    error_str = retval["msg"]

    if retval["error"] != 0:
        error_str   = retval["msg"]
        error_code  = retval["error"]
        service_msg = "Error in file operation"

        ret_data = check_command_error(error_str, error_code, service_msg)

        # if generic "error" not in the dict
        try:
            jsonify(description=ret_data["description"], error=ret_data["error"]), ret_data["status_code"], ret_data["header"]
        except:
            return jsonify(description=ret_data["description"]), ret_data["status_code"], ret_data["header"]

    return jsonify(description="Operation completed", out=retval["msg"]), 200


## chmod: Change Mode of path in Filesystem
## params:
##  - path: Filesystem path (Str) *required
##  - mode: numerical mode for file (e.g.: 700, 644, etc) *required
##  - machinename: str *required

@app.route("/chmod",methods=["PUT"])
@check_auth_header
def chmod():

    auth_header = request.headers[AUTH_HEADER_NAME]
    
    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error in chmod operation", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    # getting path from request form
    try:
        path = request.form["targetPath"]
        if path == "":
            return jsonify(description="Error in chmod operation",error="'targetPath' value is empty"), 400
    except BadRequestKeyError:
        return jsonify(description="Error in chmod operation",error="'targetPath' query string missing"), 400

    # getting chmode's mode from request form:
    try:
        mode = request.form["mode"]
        if mode == "":
            return jsonify(description="Error in chown operation",error="'mode' value is empty"), 400
    except BadRequestKeyError:
        return jsonify(description="Error in chmod operation", error="mode query string missing"), 400

    # using -c flag for verbose mode in stdout
    action = f"timeout {UTILITIES_TIMEOUT} chmod -v '{mode}' -- '{path}'"

    retval = exec_remote_command(auth_header, system_name, system_addr, action)

    if retval["error"] != 0:
        error_str   = retval["msg"]
        error_code  = retval["error"]
        service_msg = "Error in chmod operation"

        ret_data = check_command_error(error_str, error_code, service_msg)

        # if generic "error" not in the dict
        try:
            jsonify(description=ret_data["description"], error=ret_data["error"]), ret_data["status_code"], ret_data["header"]
        except:
            return jsonify(description=ret_data["description"]), ret_data["status_code"], ret_data["header"]

    return jsonify(description="Operation completed", out=retval["msg"]), 200


## chown: Change owner of path in Filesystem
## params:
##  - path: Filesystem path (Str) *required
##  - owner: new user owner of the path file
##  - group: new group owner of the path file
##  - machinename: str *required

@app.route("/chown",methods=["PUT"])
@check_auth_header
def chown():
    
    auth_header = request.headers[AUTH_HEADER_NAME]

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error in chown operation", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    try:
        path = request.form["targetPath"]
        if path == "":
            return jsonify(description="Error in chown operation",error="'targetPath' value is empty"), 400
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

    retval = exec_remote_command(auth_header, system_name, system_addr, action)

    if retval["error"] != 0:
        error_str   = retval["msg"]
        error_code  = retval["error"]
        service_msg = "Error in chown operation"

        ret_data = check_command_error(error_str, error_code, service_msg)

        # if generic "error" not in the dict
        try:
            jsonify(description=ret_data["description"], error=ret_data["error"]), ret_data["status_code"], ret_data["header"]
        except:
            return jsonify(description=ret_data["description"]), ret_data["status_code"], ret_data["header"]

        
    return jsonify(description="Operation completed", out=retval["msg"]), 200


## ls: List Directory contents
## params:
##  - path: Filesystem path (Str) *required
##  - showhidden: Bool
##  - machinename: str *required

@app.route("/ls",methods=["GET"])
@check_auth_header
def list_directory():
    
    auth_header = request.headers[AUTH_HEADER_NAME]

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error listing contents of path", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

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

    retval = exec_remote_command(auth_header, system_name, system_addr, action)

    if retval["error"] != 0:
        error_str   = retval["msg"]
        error_code  = retval["error"]
        service_msg = "Error listing contents of path"

        ret_data = check_command_error(error_str, error_code, service_msg)

        # if generic "error" not in the dict
        try:
            jsonify(description=ret_data["description"], error=ret_data["error"]), ret_data["status_code"], ret_data["header"]
        except:
            return jsonify(description=ret_data["description"]), ret_data["status_code"], ret_data["header"]
        
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
@check_auth_header
def make_directory():

    auth_header = request.headers[AUTH_HEADER_NAME]
    
    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error creating directory", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    try:
        path = request.form["targetPath"]
        if path == "":
            return jsonify(description="Error creating directory",error="'targetPath' value is empty"), 400
        
    except BadRequestKeyError:
        return jsonify(description="Error creating directory", error="'targetPath' query string missing"), 400

    try:
        p = request.form["p"]
        parent = "-p"
    except BadRequestKeyError:
        parent = ""

    action = f"timeout {UTILITIES_TIMEOUT} mkdir {parent} -- '{path}'"

    retval = exec_remote_command(auth_header, system_name, system_addr, action)

    if retval["error"] != 0:
        error_str   = retval["msg"]
        error_code  = retval["error"]
        service_msg = "Error creating directory"

        ret_data = check_command_error(error_str, error_code, service_msg)

        # if generic "error" not in the dict
        try:
            jsonify(description=ret_data["description"], error=ret_data["error"]), ret_data["status_code"], ret_data["header"]
        except:
            return jsonify(description=ret_data["description"]), ret_data["status_code"], ret_data["header"]
        
    return jsonify(description="Directory created", output=""), 201

## Returns the content from the specified path on the {machine} filesystem
## params:
##  - path: path to the file to download *required
##  - machinename: str *required

@app.route("/view", methods=["GET"])
@check_auth_header
def view():

    auth_header = request.headers[AUTH_HEADER_NAME]

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Failed to view file content", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    path = request.args.get("targetPath")

    if path == None:
        return jsonify(description="Failed to view file content",error="'targetPath' query string missing"), 400
    if path == "":
        return jsonify(description="Failed to view file content",error="'targetPath' value is empty"), 400

    # check file size
    action = f"timeout {UTILITIES_TIMEOUT} stat --dereference -c %s -- '{path}'"
    retval = exec_remote_command(auth_header, system_name, system_addr, action)

    if retval["error"] != 0:

        error_str   = retval["msg"]
        error_code  = retval["error"]
        service_msg = "Failed to view file content"

        ret_data = check_command_error(error_str, error_code, service_msg)

        # if generic "error" not in the dict
        try:
            jsonify(description=ret_data["description"], error=ret_data["error"]), ret_data["status_code"], ret_data["header"]
        except:
            return jsonify(description=ret_data["description"]), ret_data["status_code"], ret_data["header"]

    
    file_size = int(retval["msg"]) # in bytes
    max_file_size = MAX_FILE_SIZE*(1024*1024) 


    if file_size > max_file_size:
        app.logger.warning("File size exceeds limit")
        # custom error raises when file size > SIZE_LIMIT env var
        header = {"X-Size-Limit": "File exceeds size limit"}
        return jsonify(description="Failed to view file content"), 400, header

    # download with base64 to avoid encoding conversion and string processing
    action = f"timeout {UTILITIES_TIMEOUT} head -c {max_file_size} -- '{path}'"
    retval = exec_remote_command(auth_header, system_name, system_addr, action)
    if retval["error"] != 0:

        error_str   = retval["msg"]
        error_code  = retval["error"]
        service_msg = "Failed to view file content"

        ret_data = check_command_error(error_str, error_code, service_msg)

        # if generic "error" not in the dict
        try:
            return jsonify(description=ret_data["description"], error=ret_data["error"]), ret_data["status_code"], ret_data["header"]
        except:
            return jsonify(description=ret_data["description"]), ret_data["status_code"], ret_data["header"]

    content = retval["msg"].replace("$","\n")

    return jsonify(description="File content successfully returned", output=content), 200
    

## checksum: Print or check SHA256 (256-bit) checksums
## params:
##  - targetPath: Filesystem path (Str) *required##  
##  - machinename: str *required

@app.route("/checksum",methods=["GET"])
@check_auth_header
def checksum():

    auth_header = request.headers[AUTH_HEADER_NAME]
    
    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error obatining checksum", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    try:
        path = request.args.get("targetPath")
        if path == "":
            return jsonify(description="Error obatining checksum",error="'targetPath' value is empty"), 400
        
    except BadRequestKeyError:
        return jsonify(description="Error obatining checksum", error="'targetPath' query string missing"), 400

    action = f"timeout {UTILITIES_TIMEOUT} sha256sum -- '{path}'"

    retval = exec_remote_command(auth_header, system_name, system_addr, action)

    if retval["error"] != 0:

        error_str   = retval["msg"]
        error_code  = retval["error"]
        service_msg = "Error obtaining checksum"

        ret_data = check_command_error(error_str, error_code, service_msg)

        # if generic "error" not in the dict
        try:
            jsonify(description=ret_data["description"], error=ret_data["error"]), ret_data["status_code"], ret_data["header"]
        except:
            return jsonify(description=ret_data["description"]), ret_data["status_code"], ret_data["header"]

    # on success: retval["msg"] = "checksum  /path/to/file"
    output = retval["msg"].split()[0]
    

    return jsonify(description="Checksum successfully retrieved", output=output), 200

## rename/move
## params:
##  - oldpath: Filesystem path of current object (Str) *required
##  - newpath: Filesystem path of new object (Str) *required
##  - machinename: str *required

@app.route("/rename", methods=["PUT"])
@check_auth_header
def rename():
    return common_operation(request, "rename", "PUT")


## copy cp
## params:
##  - sourcepath: Filesystem path of object to be copied (Str) *required
##  - targetpath: Filesystem path of copied object (Str) *required
##  - machinename: str *required

@app.route("/copy", methods=["POST"])
@check_auth_header
def copy():
    return common_operation(request, "copy", "POST")

## common code for file operations: copy, rename (move)
def common_operation(request, command, method):
    
    auth_header = request.headers[AUTH_HEADER_NAME]

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error on " + command + " operation", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    try:
        sourcePath = request.form["sourcePath"]
        if sourcePath == "":
            return jsonify(description="Error on " + command + " operation",error="'sourcePath' value is empty"), 400
    except BadRequestKeyError:
        return jsonify(description="Error on " + command + " operation", error="'sourcePath' query string missing"), 400

    try:
        targetPath = request.form["targetPath"]
        if targetPath == "":
            return jsonify(description="Error on " + command + " operation",error="'targetPath' value is empty"), 400
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

    retval = exec_remote_command(auth_header,system_name ,system_addr, action)

    if retval["error"] != 0:
        error_str   = retval["msg"]
        error_code  = retval["error"]
        service_msg = f"Error on {command} operation"

        ret_data = check_command_error(error_str, error_code, service_msg)

        # if generic "error" not in the dict
        try:
            jsonify(description=ret_data["description"], error=ret_data["error"]), ret_data["status_code"], ret_data["header"]
        except:
            return jsonify(description=ret_data["description"]), ret_data["status_code"], ret_data["header"]
        
    return jsonify(description="Success to " + command + " file or directory.", output=""), success_code



## Remove file or directory
## params:
## - path: path to the file or directory to be removed
## - X-Machine-Name: system

@app.route("/rm", methods=["DELETE"])
@check_auth_header
def rm():

    auth_header = request.headers[AUTH_HEADER_NAME]
    
    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Error on delete operation", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    try:
        path = request.form["targetPath"]
        if path == "":
            return jsonify(description="Error on delete operation",error="'targetPath' value is empty"), 400    
    except BadRequestKeyError:
        return jsonify(description="Error on delete operation",error="'targetPath' query string missing"), 400

    # action to execute
    # -r is for recursivelly delete files into directories
    action = f"timeout {UTILITIES_TIMEOUT} rm -r --interactive=never -- '{path}'"

    retval = exec_remote_command(auth_header, system_name, system_addr, action)

    if retval["error"] != 0:
        error_str   = retval["msg"]
        error_code  = retval["error"]
        service_msg = "Error on delete operation"

        ret_data = check_command_error(error_str, error_code, service_msg)

        # if generic "error" not in the dict
        try:
            jsonify(description=ret_data["description"], error=ret_data["error"]), ret_data["status_code"], ret_data["header"]
        except:
            return jsonify(description=ret_data["description"]), ret_data["status_code"], ret_data["header"]
       
    return jsonify(description="Success to delete file or directory.", output=""), 204



## Symbolic Link
## params:
##  - target: path to target that the symlink will point to (Str) *required
##  - source: absolute path to the new symlink *required
##  - machinename: str *required

@app.route("/symlink", methods=["POST"])
@check_auth_header
def symlink():

    auth_header = request.headers[AUTH_HEADER_NAME]
    
    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Failed to create symlink", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    try:
        linkPath = request.form["linkPath"]
        if linkPath == "":
            return jsonify(description="Failed to create symlink",error="'linkPath' value is empty"), 400
    except BadRequestKeyError:
        return jsonify(description="Failed to create symlink",error="'linkPath' query string missing"), 400

    try:
        targetPath = request.form["targetPath"]
        if targetPath == "":
            return jsonify(description="Failed to create symlink",error="'targetPath' value is empty"), 400
    except BadRequestKeyError:
        return jsonify(description="Failed to create symlink",error="'targetPath' query string missing"), 400

    action = f"timeout {UTILITIES_TIMEOUT} ln -s -- '{targetPath}' '{linkPath}'"

    retval = exec_remote_command(auth_header, system_name, system_addr, action)

    if retval["error"] != 0:
        error_str   = retval["msg"]
        error_code  = retval["error"]
        service_msg = "Failed to create symlink"

        ret_data = check_command_error(error_str, error_code, service_msg)

        # if generic "error" not in the dict
        try:
            jsonify(description=ret_data["description"], error=ret_data["error"]), ret_data["status_code"], ret_data["header"]
        except:
            return jsonify(description=ret_data["description"]), ret_data["status_code"], ret_data["header"]
        
    return jsonify(description="Success create the symlink"), 201


## Returns the file from the specified path on the {machine} filesystem
## params:
##  - path: path to the file to download *required
##  - machinename: str *required

@app.route("/download", methods=["GET"])
@check_auth_header
def download():

    auth_header = request.headers[AUTH_HEADER_NAME]

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Failed to download file", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    path = request.args.get("sourcePath")

    if path == None:
        return jsonify(description="Failed to download file",error="'sourcePath' query string missing"), 400
    if path == "":
        return jsonify(description="Failed to download file",error="'sourcePath' value is empty"), 400

    #TODO: check path doesn't finish with /
    file_name = secure_filename(path.split("/")[-1])

    action = f"timeout {UTILITIES_TIMEOUT} stat --dereference -c %s -- '{path}'"
    retval = exec_remote_command(auth_header, system_name, system_addr, action)

    if retval["error"] != 0:
        return parse_io_error(retval, 'download file', path)

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
    retval = exec_remote_command(auth_header, system_name, system_addr, action, file_transfer="download")

    if retval["error"] != 0:
        return parse_io_error(retval, 'download file', path)

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
@check_auth_header
def upload():

    auth_header = request.headers[AUTH_HEADER_NAME]

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description="Failed to download file", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    path = request.form["targetPath"]

    if path == None:
        return jsonify(description="Failed to upload file", error="'targetPath' query string missing"), 400

    if path == "":
        return jsonify(description="Failed to upload file",error="'targetPath' value is empty"), 400

    if 'file' not in request.files:
        return jsonify(description="Failed to upload file", error="No file in query"), 400

    file = request.files['file']

    app.logger.info("Length: {length}".format(length=file.content_length))
    app.logger.info("Headers: {headers}".format(headers=file.headers))

    if file.filename == '':
        return jsonify(description="Failed to upload file", error="No file selected"), 400

    filename = secure_filename(file.filename)
    action = f"cat > {path}/{filename}"
    retval = exec_remote_command(auth_header, system_name, system_addr, action, file_transfer="upload", file_content=file.read())

    if retval["error"] != 0:
        return parse_io_error(retval, 'upload file', path)

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
                                     '%Y-%m-%dT%H:%M:%S')
    logHandler.setFormatter(logFormatter)
    logHandler.setLevel(logging.DEBUG)

    # get app log (Flask+werkzeug+python)
    logger = logging.getLogger()

    # set handler to logger
    logger.addHandler(logHandler)

    # run app
    # debug = False, so output redirects to log files
    if USE_SSL:        
        app.run(debug=debug, host='0.0.0.0', port=UTILITIES_PORT, ssl_context=(SSL_CRT, SSL_KEY))        
    else:
        app.run(debug=debug, host='0.0.0.0', port=UTILITIES_PORT)
