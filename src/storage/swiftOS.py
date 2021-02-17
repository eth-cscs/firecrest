#
#  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from objectstorage import ObjectStorage
import logging
import requests
import keystone
from time import time
import hmac
from hashlib import sha1


class Swift(ObjectStorage):

    def __init__(self,url,user,passwd,secret):
        self.url = url
        self.auth = None
        self.user = user
        self.passwd = passwd
        self.secret = secret

    def get_object_storage(self):
        return "OpenStack Swift"


    # authenticate SWIFT against keystone
    def authenticate(self):
        logging.info("GET TOKEN: {user} ".format(user=self.user))

        retVal = keystone.authenticate(self.user, self.passwd)

        if retVal["error"] == 1:
            logging.error("Keystone Auth Error:\n{msg}".format(msg=retVal["msg"]))
            return False

        self.auth = retVal["OS_TOKEN"]
        return True

    def is_token_valid(self):
        return keystone.is_token_valid(self.auth)

    # return list of containers created
    def get_users(self):

        # add json request query

        query_url = "{url}?format=json".format(url=self.url)

        logging.info("Storage URL: %s" % (query_url))

        try:
            # (headers, containers) =swiftclient.get_account(swift_account_url, os_token)

            req = requests.get(query_url, headers={"X-Auth-Token": self.auth})

            # if the request wasn't successful
            if not req.ok:
                logging.info(req.content)
                logging.info(req.status_code)
                return None

            resp_json = req.json()

            containers_names = []

            for item_json in resp_json:
                containers_names.append(item_json["name"])

            return containers_names

        except requests.exceptions.ConnectionError as ce:
            logging.error(ce)

            return None


    # Checks if container is already created (in order to not override it)
    # if exists returns True, otherwise False
    def is_container_created(self,containername):


        header = {"X-Auth-Token": self.auth}
        url = "{swift_url}/{containername}".format(
            swift_url=self.url,  containername=containername)

        logging.info("Container URL: " + url)

        ret = requests.get(url, headers=header)
        if ret.status_code == 200:
            logging.info("container {containername} exists".format(containername=containername))
            return True


        return False


    # Create Container which is a User for our means
    def create_container(self,containername):
        url = "{swift_url}/{container}".format(swift_url=self.url,container=containername)

        logging.info("Container name: %s" % containername)

        try:

            # create a container with PUT method on SWIFT
            # creating with FirecRest policy, so no backup to tape is made
            header = {"X-Auth-Token": self.auth, "X-Storage-Policy": "FirecRest"}

            req = requests.put(url, headers=header)

            if not req.ok:
                logging.error("Couldn't create container {container}".format(container=containername))
                logging.error("Response: {}".format(req.content))
                logging.error("Status code: {}".format(req.status_code))
                return -1

            logging.info("Container {} created succesfully".format(containername))
            return 0


        except Exception as ce:
            logging.error(ce)
            return -1

    # Checks if object is created in staging area
    # containername = name of the container
    # prefix = prefix of the object (hash_id)
    # objectname = name of the object
    def is_object_created(self,containername,prefix,objectname):

        object_prefix = "{prefix}/{objectname}".format(prefix=prefix, objectname=objectname)

        url = "{swift_url}/{container}/{object}".format(
            swift_url=self.url, container=containername,object=object_prefix)

        try:
            req = requests.head(url, headers={"X-Auth-Token": self.auth})
            headers = req.headers

            # if Content-Lenght == 0, then object doesn't exist
            if int(headers["Content-Length"]) == 0:
                return False

            # otherwise is created
            return True

        except Exception as e:

            logging.error(type(e))

            return False

    ## returns a Temporary URL for downloading without client and tokens
    def create_temp_url(self,containername,prefix,objectname,ttl):

        # separating the whole url into: API version, SWIFT Account and the prefix (ie: https://object.cscs.ch)
        separated_url = self.url.split("/")
        swift_url     = "/".join(separated_url[:-2])
        swift_version = separated_url[-2]
        swift_account = separated_url[-1]


        #Swift needs from version and on to set the path
        path = "/{swift_version}/{swift_account}/{containername}/{prefix}/{objectname}". \
            format(swift_version=swift_version, swift_account=swift_account, containername=containername, prefix=prefix,
                   objectname=objectname)

        secret = self.secret  # The secret temporary URL key set on the Swift cluster.
        # To set a key, run 'swift post -m "Temp-URL-Key: <tempurl key>"'

        method = "GET"  # or POST

        # expires = int(time() + 600)  # time before form must be submited 600 secs = 10 mins
        expires = int(time() + int(ttl))

        hmac_body = '%s\n%s\n%s' % (method, expires, path)

        secret = secret.encode('latin-1')
        hmac_body = hmac_body.encode('latin-1')

        signature = hmac.new(secret, hmac_body, sha1).hexdigest()

        return "{swift_url}{path}" \
               "?temp_url_sig={signature}" \
               "&temp_url_expires={expires}".format(swift_url=swift_url,path=path, signature=signature,
                                                    expires=expires)

    def create_upload_form(self,sourcepath,containername,prefix,ttl,max_file_size):


        # separating the whole url into: API version, SWIFT Account and the prefix (ie: https://object.cscs.ch)
        separated_url = self.url.split("/")
        swift_url = "/".join(separated_url[:-2])
        swift_version = separated_url[-2]
        swift_account = separated_url[-1]


        # Swift needs from version and on to set the path
        path = "/{swift_version}/{swift_account}/{containername}/{prefix}/". \
            format(swift_version=swift_version, swift_account=swift_account, containername=containername, prefix=prefix)


        # URL redirect after compeleting upload
        # left blank
        redirect = ""
        # max_file_size = STORAGE_MAX_FILE_SIZE  # bytes = 5 GB
        max_file_count = 1  # just one file to upload

        # expires = int(time() + 600)  # time before form must be submited 600 secs = 10 mins
        expires = int(time() + int(ttl))

        secret = self.secret  # The secret temporary URL key set on the Swift cluster.
        # To set a key, run 'swift post -m "Temp-URL-Key: <tempurl key>"'

        hmac_body = '%s\n%s\n%s\n%s\n%s' % (path, redirect,
                                            max_file_size, max_file_count, expires)

        secret = secret.encode("latin-1")
        hmac_body = hmac_body.encode("latin-1")

        signature = hmac.new(secret, hmac_body, sha1).hexdigest()

        # added OBJECT_PREFIX as dir_[task_id] in order to become unique the upload instead of user/filename
        command = f"curl -i {swift_url}/{swift_version}/{swift_account}/{containername}/{prefix}/" \
              f" -X POST " \
              f"-F max_file_size={max_file_size} -F max_file_count={max_file_count} " \
              f"-F expires={expires} -F signature={signature} " \
              f"-F redirect={redirect} -F file=@{sourcepath} "


        retval = {}

        retval["parameters"] = {
            "method": "POST",
            "url": f"{swift_url}/{swift_version}/{swift_account}/{containername}/{prefix}/",
            "data": {
                "max_file_size": max_file_size, 
                "max_file_count": max_file_count,
                "expires": expires,
                "signature": signature,
                "redirect": redirect,
            },
            "files": sourcepath,
            "json": {},
            "headers": {},
            "params": {}

        }

        retval["command"] = command
        

        return retval

    def list_objects(self,containername,prefix=None):
        # object_prefix = "{prefix}/{objectname}".format(prefix=prefix, objectname=objectname)

        url = f"{self.url}/{containername}"
        
        try:
            req = requests.get(url, headers={"X-Auth-Token": self.auth})
            if req.ok:
                
                values = req.content.decode("utf-8")
                object_list = values.split("\n")[0:-1] # last element on the list is a ''

                if prefix:
                    new_object_list = []
                    for obj in object_list:
                        
                        key = obj.split("/")
                        val = key[1]
                        key = key[0]
                        
                        if key == prefix:
                            new_object_list.append(val)

                    #object_list = list(filter(lambda obj: obj.split("/")[0] == prefix, object_list))
                return new_object_list
            return None

        except Exception as e:

            logging.error(type(e))

            return None


    # sets time to live (TTL) for an object in SWIFT
    def delete_object_after(self,containername,prefix,objectname,ttl):

        swift_account_url = "{swift_url}/{containername}/{prefix}/{objectname}".format(
            swift_url=self.url, containername=containername, prefix=prefix, objectname=objectname)

        header = {'X-Delete-After': "{}".format(ttl), "X-Auth-Token": self.auth}

        try:
            logging.info("Setting {seconds} [s] as X-Delete-After".format(seconds=ttl))

            req = requests.post(swift_account_url, headers=header)

            if not req.ok:
                logging.error("Object couldn't be marked as X-Delete-After")
                return -1
            return 0

        except Exception as e:
            logging.error("Object couldn't be marked as X-Delete-After")
            logging.error(e)
            return -1

    def delete_object(self,containername,prefix,objectname):

        swift_account_url = f"{self.url}/{containername}/{prefix}"

        header = {"X-Auth-Token": self.auth}


        try:

            logging.info("Deleting object: {}/{}/{}".format(containername,prefix,objectname))

            req = requests.delete(swift_account_url, headers=header)

            if not req.ok:
                logging.error("Object couldn't be deleted")
                logging.error(req.content)
                return -1

            logging.info("Object deleted successfully")

            return 0

        except Exception as e:
            logging.error("Object couldn't be deleted")
            logging.error(e)
            return -1

