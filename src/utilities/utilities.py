#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, request, jsonify, send_file, g
from werkzeug.middleware.profiler import ProfilerMiddleware
import os, logging
from werkzeug.exceptions import BadRequestKeyError

import base64
import io
import json
from math import ceil
from flask_opentracing import FlaskTracing
from jaeger_client import Config
import opentracing
import re
import shlex

from cscs_api_common import check_auth_header, exec_remote_command, check_command_error, get_boolean_var, validate_input, setup_logging, extract_command

CERTIFICATOR_URL = os.environ.get("F7T_CERTIFICATOR_URL")
UTILITIES_PORT   = os.environ.get("F7T_UTILITIES_PORT", 5000)

AUTH_HEADER_NAME = os.environ.get("F7T_AUTH_HEADER_NAME","Authorization")

UTILITIES_TIMEOUT = int(os.environ.get("F7T_UTILITIES_TIMEOUT", "5"))

# SYSTEMS: list of ; separated systems allowed
SYSTEMS_PUBLIC  = os.environ.get("F7T_SYSTEMS_PUBLIC").strip('\'"').split(";")
# internal machines for file operations
SYS_INTERNALS   = os.environ.get("F7T_SYSTEMS_INTERNAL_UTILITIES").strip('\'"').split(";")

DEBUG_MODE = get_boolean_var(os.environ.get("F7T_DEBUG_MODE", False))

#max file size for upload/download in MB, internally used in bytes
MAX_FILE_SIZE_BYTES = int(os.environ.get("F7T_UTILITIES_MAX_FILE_SIZE", "5")) * 1024 * 1024

### SSL parameters
USE_SSL = get_boolean_var(os.environ.get("F7T_USE_SSL", False))
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_KEY = os.environ.get("F7T_SSL_KEY", "")

TRACER_HEADER = "uber-trace-id"

app = Flask(__name__)
profiling_middle_ware = ProfilerMiddleware(app.wsgi_app,
                                           restrictions=[15],
                                           filename_format="utilities.{method}.{path}.{elapsed:.0f}ms.{time:.0f}.prof",
                                           profile_dir='/var/log/profs')

# max content lenght for upload in bytes
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE_BYTES

logger = setup_logging(logging, 'utilities')

JAEGER_AGENT = os.environ.get("F7T_JAEGER_AGENT", "").strip('\'"')
if JAEGER_AGENT != "":
    config = Config(
        config={'sampler': {'type': 'const', 'param': 1 },
            'local_agent': {'reporting_host': JAEGER_AGENT, 'reporting_port': 6831 },
            'logging': True,
            'reporter_batch_size': 1},
            service_name = "utilities")
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

## file: determines the type of file of path
## params:
##  - path: Filesystem path (Str) *required
##  - machinename: str *required

@app.route("/file", methods=["GET"])
@check_auth_header
def file_type():
    return common_fs_operation(request, "file")


## stat: determines the status of a file
## params:
##  - path: Filesystem path (Str) *required
##  - machinename: str *required

@app.route("/stat", methods=["GET"])
@check_auth_header
def stat():
    return common_fs_operation(request, "stat")

## chmod: Change Mode of path in Filesystem
## params:
##  - path: Filesystem path (Str) *required
##  - mode: numerical mode for file (e.g.: 700, 644, etc) *required
##  - machinename: str *required

@app.route("/chmod", methods=["PUT"])
@check_auth_header
def chmod():
    return common_fs_operation(request, "chmod")


## chown: Change owner of path in Filesystem
## params:
##  - path: Filesystem path (Str) *required
##  - owner: new user owner of the path file
##  - group: new group owner of the path file
##  - machinename: str *required

@app.route("/chown", methods=["PUT"])
@check_auth_header
def chown():
    return common_fs_operation(request, "chown")


## head: Get first N bytes or lines of a file
## params:
##  - path: Filesystem path (Str) *required
##  - bytes: optional
##  - lines: optional, default is 10
##  - skip_ending: optional, add '-' before NUM in bytes/lines arguments
##  - machinename: str *required

@app.route("/head", methods=["GET"])
@check_auth_header
def head():
    return common_fs_operation(request, "head")


## ls: List Directory contents
## params:
##  - path: Filesystem path (Str) *required
##  - showhidden: Bool
##  - machinename: str *required

@app.route("/ls", methods=["GET"])
@check_auth_header
def list_directory():
    return common_fs_operation(request, "ls")



## parse ls output
def ls_parse_folder(folder_content:str,path:str=""):
    # Example of ls output
    # total 3
    # lrwxrwxrwx 1 username groupname 46 2023-07-25T14:18:00 "filename" -> "target link"
    # -rw-rw-r-- 1 root root           0 2023-07-24T11:45:35 "root_file.txt"
    # drwxrwxr-x 3 username groupname 4096 2023-07-24T11:45:35 "folder"
    file_list = []
    file_pattern = (r'^(?P<type>\S)(?P<permissions>\S+)\s+\d+\s+(?P<user>\S+)\s+'
                        r'(?P<group>\S+)\s+(?P<size>\d+)\s+(?P<last_modified>(\d|-|T|:)+)\s+(?P<filename>.+)$')
    matches = re.finditer(file_pattern, folder_content, re.MULTILINE)
    
    for m in matches:
        tokens = shlex.split(m.group("filename"))
        if len(tokens) == 1:
            name = tokens[0]
            link_target = ""
        elif len(tokens) == 3:
            # We could add an assertion that m.group("type") == 'l' if
            # we want to be sure that this is a link
            name = tokens[0]
            link_target = tokens[2]
        else:
            app.logger.error(f"Cannot get the filename from this line from ls: {m.group()}")
            continue

        file_list.append({
            "name": path + name,
            "type": m.group("type"),
            "link_target": link_target,
            "user": m.group("user"),
            "group": m.group("group"),
            "permissions": m.group("permissions"),
            "last_modified": m.group("last_modified"),
            "size": m.group("size")
        })
    return file_list


## parse ls output
def ls_parse(request, retval):
    # Example of ls output
    # ".":
    # total 8
    # lrwxrwxrwx 1 username groupname 46 2023-07-25T14:18:00 "filename" -> "target link"
    # -rw-rw-r-- 1 root root           0 2023-07-24T11:45:35 "root_file.txt"
    # drwxrwxr-x 3 username groupname 4096 2023-07-24T11:45:35 "folder"
    # "./folder":
    # total 1
    # -rw-rw-r-- 1 username groupname 0 2023-07-24T11:45:35 "file_in_folder.txt"
    # ...
    file_list = []

    #Check if ls has recursive folders
    if(re.match(r'\"(.+)\":\n',retval["msg"])):
        folders =  re.split(r'\"(.+)\":\n',retval["msg"])
        root_folder = ""
        for i in range(1,len(folders),2):
            if i==1:
                root_folder = folders[i]+"/"

            folder_name = (folders[i]+"/").replace(root_folder,"")
            folder_content = folders[i+1]
            file_list += ls_parse_folder(folder_content,folder_name)
    else:
        file_list += ls_parse_folder(retval["msg"])

    
    totalSize = len(file_list)
    logging.info(f"Length of file list: {len(file_list)}")

    # if pageSize and number were set:
    pageSize = request.args.get("pageSize", None)
    pageNumber = request.args.get("pageNumber", None)

    if DEBUG_MODE:
        logging.debug(f"PageSize: {pageSize}. PageNumber: {pageNumber}")

    # calculate the list to retrieve
    if pageSize and pageNumber:
        try:
            pageNumber = float(pageNumber)
            pageSize   = float(pageSize)

            totalPages = int(ceil(float(totalSize) / float(pageSize)))

            app.logger.info(f"Total Size: {totalSize} - Total Pages: {totalPages}")

            if pageNumber < 1 or pageNumber>totalPages:
                app.logger.info(f"pageNumber ({pageNumber}) greater than total pages ({totalPages})")
            else:
                beg_reg=int((pageNumber-1)*pageSize)
                end_reg=int(pageNumber*pageSize-1)
                app.logger.info(f"Initial reg {beg_reg}, final reg: {end_reg}")
                file_list = file_list[beg_reg:end_reg+1]
        except:
            app.logger.info(f"Invalid pageSize ({pageSize}) and/or pageNumber ({pageSize}), returning full list")

    return file_list


## mkdir: Make Directory
## params:
##  - path: Filesystem path (Str) *required
##  - p: -p, --parents no error if existing, make parent directories as needed (bool)
##  - machinename: str *required

@app.route("/mkdir", methods=["POST"])
@check_auth_header
def make_directory():
    return common_fs_operation(request, "mkdir")


## tail: Get last N bytes or lines of a file
## params:
##  - path: Filesystem path (Str) *required
##  - bytes: optional
##  - lines: optional, default is 10
##  - skip_beginning: optional, add '+' before NUM in bytes/lines arguments
##  - machinename: str *required

@app.route("/tail", methods=["GET"])
@check_auth_header
def tail():
    return common_fs_operation(request, "tail")


## Returns the content (head) from the specified path on the {machine} filesystem
## params:
##  - path: path to the file to download *required
##  - machinename: str *required

@app.route("/view", methods=["GET"])
@check_auth_header
def view():
    try:
        resp = common_fs_operation(request, "fsize")
        if resp[1] != 200:
            return resp
        out = json.loads(resp[0].data.decode())
    except:
        return jsonify(description='Error on stat operation', output=''), 400

    file_size = int(out["output"]) # in bytes

    if file_size > MAX_FILE_SIZE_BYTES:
        app.logger.warning("File size exceeds limit")
        # custom error raises when file size > SIZE_LIMIT env var
        header = {"X-Size-Limit": "File exceeds size limit"}
        return jsonify(description="Failed to view file content"), 400, header

    # TODO: download with base64 to avoid encoding conversion and string processing ?
    return common_fs_operation(request, "head")


## checksum: Print or check SHA256 (256-bit) checksums
## params:
##  - targetPath: Filesystem path (Str) *required##
##  - machinename: str *required

@app.route("/checksum", methods=["GET"])
@check_auth_header
def checksum():
    return common_fs_operation(request, "checksum")


## rename/move
## params:
##  - oldpath: Filesystem path of current object (Str) *required
##  - newpath: Filesystem path of new object (Str) *required
##  - machinename: str *required

@app.route("/rename", methods=["PUT"])
@check_auth_header
def rename():
    return common_fs_operation(request, "rename")


## copy cp
## params:
##  - sourcepath: Filesystem path of object to be copied (Str) *required
##  - targetpath: Filesystem path of copied object (Str) *required
##  - machinename: str *required
@app.route("/copy", methods=["POST"])
@check_auth_header
def copy():
    return common_fs_operation(request, "copy")

## compress with tar
## params:
##  - sourcepath: Filesystem path that will be compressed (Str) *required
##  - targetpath: Filesystem path of copied object (Str) *required
##  - machinename: str *required
@app.route("/compress", methods=["POST"])
@check_auth_header
def compress():
    return common_fs_operation(request, "compress")

## extract files
## params:
##  - sourcepath: Filesystem path of object to be decompressed (Str) *required
##  - targetpath: Filesystem path of extracted files (Str) *required
##  - machinename: str *required
##  - type: Extension of the file (Str)
@app.route("/extract", methods=["POST"])
@check_auth_header
def extract():
    return common_fs_operation(request, "extract")


## common code for file operations:
def common_fs_operation(request, command):
    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description=f"Error on {command} operation", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    # get targetPath to apply command
    tn = 'targetPath'
    if request.method == 'GET':
        targetPath = request.args.get("targetPath", None)
        if (targetPath == None) and (command in ['base64', 'fsize', 'stat']):
            # TODO: review API
            tn = "sourcePath"
            targetPath = request.args.get("sourcePath", None)
    else: # DELETE, POST, PUT
        targetPath = request.form.get("targetPath", None)

    v = validate_input(targetPath)
    if v != "" and command != "whoami":
        return jsonify(description=f"Error on {command} operation", error=f"'{tn}' {v}"), 400

    if command in ['copy', 'rename', 'compress', 'extract']:
        sourcePath = request.form.get("sourcePath", None)
        v = validate_input(sourcePath)
        if v != "":
            return jsonify(description=f"Error on {command} operation", error=f"'sourcePath' {v}"), 400

    file_content = None
    file_transfer = None
    success_code = 200

    if command == "base64":
        action = f"base64 --wrap=0 -- '{targetPath}'"
        file_transfer = 'download'
    elif command == "checksum":
        action = f"sha256sum -- '{targetPath}'"
    elif command == "chmod":
        mode = request.form.get("mode", None)
        v = validate_input(mode)
        if v != "":
            return jsonify(description="Error on chmod operation", error=f"'mode' {v}"), 400
        action = f"chmod -v '{mode}' -- '{targetPath}'"
    elif command == "chown":
        owner = request.form.get("owner", "")
        group = request.form.get("group", "")
        if owner == "" and group == "":
            return jsonify(description="Error in chown operation", error="group or owner must be set"), 400
        v = validate_input(owner + group)
        if v != "":
            return jsonify(description="Error in chown operation", error=f"group or owner {v}"), 400
        action = f"chown -v '{owner}':'{group}' -- '{targetPath}'"
    elif command == "copy":
        # -r is for recursivelly copy files into directories
        action = f"cp --force -dR --preserve=all -- '{sourcePath}' '{targetPath}'"
        success_code = 201
    elif command == "compress":
        basedir = os.path.dirname(sourcePath)
        file_path = os.path.basename(sourcePath)
        action = f"tar -czvf '{targetPath}' -C '{basedir}' '{file_path}'"
        success_code = 201
    elif command == "extract":
        extraction_type = request.form.get("type", "auto")
        action = extract_command(sourcePath, targetPath, type=extraction_type)
        if not action:
            return jsonify(description=f"Error on {command} operation", error=f"Unsupported file format in {sourcePath}."), 400

        success_code = 201
    elif command == "file":
        # -b: do not prepend filenames to output lines
        action = f"file -b -- '{targetPath}'"
    elif command in ["head", "tail"]:
        opt = ""
        bytes = request.args.get("bytes", None)
        lines = request.args.get("lines", None)
        if command ==  "head":
            reverse_mode = get_boolean_var(request.args.get("skip_ending", None))
        else:
            reverse_mode = get_boolean_var(request.args.get("skip_beginning", None))

        if bytes and lines:
            return jsonify(description=f"Error on {command} operation", error=f"Can not specify both 'bytes' and 'lines'"), 400

        if bytes:
            v = validate_input(bytes)
            if v != "":
                return jsonify(description=f"Error on {command} operation", error=f"'bytes' {v}"), 400

            if reverse_mode:
                if command == "head":
                    opt = f" --bytes='-{bytes}' "
                else:
                    opt = f" --bytes='+{bytes}' "
            else:
                opt = f" --bytes='{bytes}' "

        if lines:
            v = validate_input(lines)
            if v != "":
                return jsonify(description=f"Error on {command} operation", error=f"'lines' {v}"), 400

            if reverse_mode:
                if command == "head":
                    opt = f" --lines='-{lines}' "
                else:
                    opt = f" --lines='+{lines}' "
            else:
                opt = f" --lines='{lines}' "

        action = f"{command} {opt} -- '{targetPath}'"
        file_transfer = 'download'
    elif command == "ls":
        options = ""
        if get_boolean_var(request.args.get("showhidden", False)):
            # if set shows entrys starting with . (not including . and/or .. dirs)
            options = "-A "
        if get_boolean_var(request.args.get("numericUid", False)):
            # do not resolve UID and GID to names
            options += "--numeric-uid-gid "
        if get_boolean_var(request.args.get("recursive", False)):
            # do not resolve UID and GID to names
            options += "-R "
        action = f"ls -l --quoting-style=c {options} --time-style=+%Y-%m-%dT%H:%M:%S -- '{targetPath}'"
    elif command == "mkdir":
        try:
            p = request.form["p"]
            parent = "-p"
        except BadRequestKeyError:
            parent = ""
        action = f"mkdir {parent} -- '{targetPath}'"
        success_code = 201
    elif command == "rename":
        action = f"mv --force -- '{sourcePath}' '{targetPath}'"
    elif command == "rm":
        # -r is for recursivelly delete files into directories
        action = f"rm -r --interactive=never -- '{targetPath}'"
        success_code = 204
    elif command == "fsize":
        action = f"stat --dereference -c %s -- '{targetPath}'"
    elif command == "stat":
        deref = ""
        if get_boolean_var(request.args.get("dereference", False)):
            deref = "--dereference"
        action = f"stat {deref} -c '%f %i %d %h %u %g %s %X %Y %Z' -- '{targetPath}'"
    elif command == "symlink":
        linkPath = request.form.get("linkPath", None)
        v = validate_input(linkPath)
        if v != "":
            return jsonify(description="Failed to create symlink", error=f"'linkPath' value {v}"), 400
        action = f"ln -s -- '{targetPath}' '{linkPath}'"
        success_code = 201
    elif command == "upload":
        try:
            if 'file' not in request.files:
                return jsonify(description="Failed to upload file", error="No file in query"), 400
            file = request.files['file']
            app.logger.info(f"Upload length: {file.content_length}")
            v = validate_input(file.filename)
            if v != "":
                return jsonify(description="Failed to upload file", error=f"Filename {v}"), 400
        except:
            return jsonify(description='Error on upload operation', output=''), 400
        filename = file.filename
        action = f"cat > '{targetPath}/{filename}'"
        file_content = file.read()
        file_transfer = 'upload'
        success_code = 201
    elif command == "whoami":
        groups = request.args.get("groups")
        whoami_groups = get_boolean_var(groups)
        if not whoami_groups:
            action = "id -un" # id command is already whitelisted
        else:
            action = "id"
        success_code = 200
    else:
        app.logger.error(f"Unknown command on common_fs_operation: {command}")
        return jsonify(description="Error on internal operation", error="Internal error"), 400

    [headers, ID] = get_tracing_headers(request)
    action = f"ID={ID} timeout {UTILITIES_TIMEOUT} {action}"
    retval = exec_remote_command(headers, system_name ,system_addr, action, file_transfer, file_content)

    if retval["error"] != 0:
        error_str   = retval["msg"]
        error_code  = retval["error"]
        service_msg = f"Error on {command} operation"

        ret_data = check_command_error(error_str, error_code, service_msg)

        # if generic "error" not in the dict
        try:
            return jsonify(description=ret_data["description"], error=ret_data["error"]), ret_data["status_code"], ret_data["header"]
        except:
            return jsonify(description=ret_data["description"]), ret_data["status_code"], ret_data["header"]


    description = f"Success to {command} file."
    output = ''
    if command == 'checksum':
        # return only hash, msg sintax:  hash filename
        output = retval["msg"].split()[0]
    elif command in ['base64', 'chmod', 'chown', 'file', 'fsize']:
        if command in ['chmod', 'chown']:
            description = f"Success to {command} file or directory."
        output = retval["msg"]
    elif command == "head":
        # output first bytes (at most max value)
        output = retval["msg"][:MAX_FILE_SIZE_BYTES]
    elif command == 'ls':
        description = "List of contents"
        output = ls_parse(request, retval)
    elif command == 'stat':
        # follows: https://docs.python.org/3/library/os.html#os.stat_result
        output = dict(zip(['mode', 'ino', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime'], retval["msg"].split()))
        # convert to integers
        output["mode"] = int(output["mode"], base=16)
        output = {key: int(value) for key, value in output.items()}
    elif command == "tail":
        # output last bytes (at most max value)
        output = retval["msg"][-MAX_FILE_SIZE_BYTES:]
    elif command == "upload":
        description="File upload successful"
    elif command == "whoami":
        description = "User information"
        whoami_response = retval["msg"]
        output = whoami_response
        if whoami_groups:

            uid_i   = whoami_response.find("=",0)
            uname_i = whoami_response.find("(", whoami_response.find("uid=",0))
            uname_j = whoami_response.find(")", whoami_response.find("uid=",0))
            uname   = whoami_response[uname_i+1 : uname_j]
            uid     = whoami_response[uid_i+1:uname_i]
            user_json = {"name": uname, "id": uid}

            gid_i   = whoami_response.find("=",uname_j)
            gname_i = whoami_response.find("(", whoami_response.find("gid=",0))
            gname_j = whoami_response.find(")", whoami_response.find("gid=",0))
            gname   = whoami_response[gname_i+1 : gname_j]
            gid     = whoami_response[gid_i+1 : gname_i]
            group_json = {"name": gname, "id": gid}

            groups = []

            group_list = whoami_response[whoami_response.find("=",gname_j)+1:].split(",")

            for group in group_list:
                gname_i = group.find("(", 0)
                gname_j = group.find(")", 0)
                gname   = group[gname_i+1 : gname_j]
                gid     = group[:gname_i]

                groups.append({"name": gname, "id": gid})


            output = {"user": user_json, "group": group_json, "groups": groups}

    return jsonify(description=description, output=output), success_code



## Remove file or directory
## params:
## - path: path to the file or directory to be removed
## - X-Machine-Name: system

@app.route("/rm", methods=["DELETE"])
@check_auth_header
def rm():
    return common_fs_operation(request, "rm")


## Symbolic Link
## params:
##  - target: path to target that the symlink will point to (Str) *required
##  - source: absolute path to the new symlink *required
##  - machinename: str *required

@app.route("/symlink", methods=["POST"])
@check_auth_header
def symlink():
    return common_fs_operation(request, "symlink")


## Returns the file from the specified path on the {machine} filesystem
## params:
##  - path: path to the file to download *required
##  - machinename: str *required

@app.route("/download", methods=["GET"])
@check_auth_header
def download():
    try:
        # returns a tuple (json_msg, status_code [, header])
        resp = common_fs_operation(request, "fsize")
        if resp[1] != 200:
            return resp
        out = json.loads(resp[0].data.decode())
    except Exception as e:
        app.logger.error(e)
        return jsonify(description='Error on stat operation', output=''), 400

    #TODO: check path doesn't finish with /
    path = request.args.get("sourcePath")
    file_name = os.path.basename(path)

    try:
        file_size = int(out["output"]) # in bytes
        if file_size > MAX_FILE_SIZE_BYTES:
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
                     download_name=file_name,
                     as_attachment=True)
    except Exception as e:
        app.logger.error(f"Download decode error: {e.message}")
        return jsonify(description="Failed to download file"), 400

    # download with base64 to avoid encoding conversion and string processing
    try:
        # returns a tuple (json_msg, status_code [, header])
        resp = common_fs_operation(request, "base64")
        if resp[1] != 200:
            return resp
        out = json.loads(resp[0].data.decode())
    except:
        return jsonify(description='Error on download operation', output=''), 400

    try:
        data = io.BytesIO()
        data.write(base64.b64decode(out["output"]))
        data.seek(0)
    except Exception as e:
        app.logger.error(f"Download decode error: {e.message}")
        return jsonify(description="Failed to download file"), 400

    return send_file(data,
                     mimetype="application/octet-stream",
                     download_name=file_name,
                     as_attachment=True)



## error handler for files above SIZE_LIMIT -> app.config['MAX_CONTENT_LENGTH']
@app.errorhandler(413)
def request_entity_too_large(error):
    app.logger.error(error)
    return jsonify(description=f"Failed to upload file. The file is over {MAX_FILE_SIZE_BYTES} bytes"), 413


## Uploads file to specified path on the {machine} filesystem
## params:
##  - path: path to the file to download *required
##  - machinename: str *required

@app.route("/upload", methods=["POST"])
@check_auth_header
def upload():
    return common_fs_operation(request, "upload")


## whoami endpoint interface
## Params:
## - None
## Headers:
## - X-Machine-Name: <machine_name>
## - Authorization: <token_type> <access_token>
## Returns:
## - username (str)

@app.route("/whoami", methods=["GET"])
@check_auth_header
def whoami():
    return common_fs_operation(request, "whoami")


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
        app.run(debug=DEBUG_MODE, host='0.0.0.0', port=UTILITIES_PORT, ssl_context=(SSL_CRT, SSL_KEY))
    else:
        app.run(debug=DEBUG_MODE, host='0.0.0.0', port=UTILITIES_PORT)
