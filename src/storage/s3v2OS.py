#
#  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from xml.etree import ElementTree
from io import StringIO, BytesIO
import urllib.request, urllib.parse, urllib.error

from objectstorage import ObjectStorage
import requests
import logging
import time
import base64
import hmac
import hashlib

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class S3v2(ObjectStorage):

    def __init__(self, url, user, passwd):
        self.user = user
        self.passwd = passwd
        self.url = url

    def get_object_storage(self):
        return "Amazon S3 - Signature V2"

    def create_container(self, containername):
        # by default just 120 secs, since is
        expires = 120 + int(time.time())
        httpVerb = "PUT"
        contentMD5 = ""
        contentType = ""
        canonicalizedAmzHeaders = ""
        canonicalizedResource = "/{containername}".format(containername=containername)

        string_to_sign = httpVerb + "\n" + contentMD5 + "\n" + contentType + "\n" + \
                         str(expires) + "\n" + canonicalizedAmzHeaders + canonicalizedResource

        # sig = base64.b64encode(hmac.new(self.passwd, string_to_sign, hashlib.sha1).digest())
        # to be used in hmac.new(key,msg,digestmode), the strings key (passwd) and msg (strin_to_sign) need to be byte type
        string_to_sign = string_to_sign.encode('latin-1')
        _passwd = bytes(self.passwd, 'latin1')

        sig = base64.b64encode(hmac.new(_passwd, string_to_sign, hashlib.sha1).digest())

        # signature will be Bytes type in Pytho3, so it needs to be decoded to str again
        sig = sig.decode('latin-1')

        url = "{url}/{containername}?AWSAccessKeyId={awsAccessKeyId}&Signature={signature}&Expires={expires}".format(
            url=self.url, containername=containername,
            awsAccessKeyId=self.user, signature=urllib.parse.quote(sig), expires=expires)

        logging.info("Creating bucket {}".format(containername))

        try:
            resp = requests.put(url)

            if resp.ok:
                return 0
            return -1
        except Exception as e:
            logging.error("Error: {}".format(e))
            return -1

    def is_container_created(self, containername):
        # by default just 120 secs, since is done instantly
        expires = 120 + int(time.time())
        httpVerb = "HEAD"
        contentMD5 = ""
        contentType = ""
        canonicalizedAmzHeaders = ""
        canonicalizedResource = "/{containername}".format(containername=containername)

        string_to_sign = httpVerb + "\n" + contentMD5 + "\n" + contentType + "\n" + \
                         str(expires) + "\n" + canonicalizedAmzHeaders + canonicalizedResource

        # sig = base64.b64encode(hmac.new(self.passwd, string_to_sign, hashlib.sha1).digest())
        # to be used in hmac.new(key,msg,digestmode), the strings key (passwd) and msg (strin_to_sign) need to be byte type
        string_to_sign = string_to_sign.encode('latin-1')
        _passwd = bytes(self.passwd, 'latin1')

        sig = base64.b64encode(hmac.new(_passwd, string_to_sign, hashlib.sha1).digest())

        # signature will be Bytes type in Pytho3, so it needs to be decoded to str again
        sig = sig.decode('latin-1')

        url = "{url}/{containername}?AWSAccessKeyId={awsAccessKeyId}&Expires={expires}&Signature={signature}".format(
            url=self.url, containername=containername, awsAccessKeyId=self.user, signature=urllib.parse.quote(sig), expires=expires)

        logging.info("Checking for container {}".format(containername))
        logging.info("URL: {}".format(url))
        try:
            resp = requests.head(url)

            logging.info(resp.status_code)

            return resp.ok

        except Exception as e:
            logging.error("Error: {}".format(e))
            logging.error("Error: {}".format(type(e)))
            return False

    def get_users(self):
        # by default just 120 secs, since is done instantly
        expires = 120 + int(time.time())


        string_to_sign = "GET\n\n\n%s\n/" % (expires)

        # to be used in hmac.new(key,msg,digestmode), the strings key (passwd) and msg (string_to_sign) need to be byte type
        string_to_sign = string_to_sign.encode('latin-1')
        _passwd = bytes(self.passwd,'latin1')

        sig = base64.b64encode(hmac.new(_passwd, string_to_sign, hashlib.sha1).digest())

        # signature will be Bytes type in Python3, so it needs to be decoded to str again
        sig = sig.decode('latin-1')

        url = "{url}?AWSAccessKeyId={awsAccessKeyId}&Expires={expires}&Signature={signature}".format(
            url=self.url, awsAccessKeyId=self.user, signature=urllib.parse.quote(sig), expires=expires)

        logging.info("URL: {}".format(url))
        try:
            resp = requests.get(url)

            logging.info(resp.status_code)

            if resp.ok:
                # logging.info(resp.content)
                root = ElementTree.fromstring(resp.content)

                for _, nsvalue in ElementTree.iterparse(BytesIO(resp.content), events=['start-ns']):
                    namespace = nsvalue[1]

                bucket_list = []

                # response format:
                # <ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                #   <Owner>
                #       <ID>firecrest:jdorsch</ID>
                #       <DisplayName>firecrest:jdorsch</DisplayName>
                #   </Owner>
                #   <Buckets>
                #       <Bucket>
                #           <Name>5497558138880</Name>
                #           <CreationDate>2009-02-03T16:45:09.000Z</CreationDate>
                #       </Bucket>

                # the tag syntax is formatted by a namespace, ie:
                # {http://s3.amazonaws.com/doc/2006-03-01/}Buckets

                for buckets in root.findall("{{{}}}Buckets".format(namespace)):
                    for bucket in buckets.findall("{{{}}}Bucket".format(namespace)):
                        name = bucket.find("{{{}}}Name".format(namespace)).text
                        bucket_list.append(name)

                return bucket_list

            return None

        except Exception as e:
            logging.error("Error: {}".format(e))
            logging.error("Error: {}".format(type(e)))
            return None

    def list_objects(self,containername,prefix=None):
            # by default just 120 secs, since is done instantly
        
        expires = 120 + int(time.time())
        httpVerb = "GET"
        contentMD5 = ""
        contentType = ""
        canonicalizedAmzHeaders = ""
        canonicalizedResource = f"/{containername}/"

        string_to_sign = httpVerb + "\n" + contentMD5 + "\n" + contentType + "\n" + \
                         str(expires) + "\n" + canonicalizedAmzHeaders + canonicalizedResource

        # string_to_sign = f"GET\n\n\n{str(expires)}\n/"

        # to be used in hmac.new(key,msg,digestmode), the strings key (passwd) and msg (strin_to_sign) need to be byte type
        string_to_sign = string_to_sign.encode('latin-1')
        _passwd = bytes(self.passwd,'latin1')

        sig = base64.b64encode(hmac.new(_passwd, string_to_sign, hashlib.sha1).digest())

        # signature will be Bytes type in Pytho3, so it needs to be decoded to str again
        sig = sig.decode('latin-1')

        url = "{url}/{containername}/?AWSAccessKeyId={awsAccessKeyId}&Expires={expires}&Signature={signature}".format(
            containername=containername,url=self.url, awsAccessKeyId=self.user, signature=urllib.parse.quote(sig), expires=expires)

        logging.info("URL: {}".format(url))
        try:
            resp = requests.get(url)

            logging.info(resp.status_code)

            if resp.ok:
                # logging.info(resp.content)
                root = ElementTree.fromstring(resp.content)

                for _, nsvalue in ElementTree.iterparse(BytesIO(resp.content), events=['start-ns']):
                    namespace = nsvalue[1]

                object_list = []

                

                for contents in root.findall("{{{}}}Contents".format(namespace)):
                    key = contents.find("{{{}}}Key".format(namespace)).text

                    
                    if prefix != None:
                        sep = key.split("/")
                        if prefix == sep[0]:
                            name = key.split("/")[-1]
                            object_list.append(name)
                            continue
                    
                    object_list.append(key)


                    

                return object_list

            logging.error(resp.content)
            return None

        except Exception as e:
            logging.error("Error: {}".format(e))
            logging.error("Error: {}".format(type(e)))
            return None

    def is_object_created(self, containername, prefix, objectname):
        # by default just 120 secs, since is done instantly
        expires = 120 + int(time.time())
        httpVerb = "HEAD"
        contentMD5 = ""
        contentType = ""
        canonicalizedAmzHeaders = ""
        canonicalizedResource = "/{containername}/{prefix}/{objectname}".format(
            containername=containername, prefix=prefix, objectname=objectname)

        string_to_sign = httpVerb + "\n" + contentMD5 + "\n" + contentType + "\n" + \
                         str(expires) + "\n" + canonicalizedAmzHeaders + canonicalizedResource



        # sig = base64.b64encode(hmac.new(self.passwd, string_to_sign, hashlib.sha1).digest())
        # to be used in hmac.new(key,msg,digestmode), the strings key (passwd) and msg (strin_to_sign) need to be byte type
        string_to_sign = string_to_sign.encode('latin-1')
        _passwd = bytes(self.passwd, 'latin1')

        sig = base64.b64encode(hmac.new(_passwd, string_to_sign, hashlib.sha1).digest())

        # signature will be Bytes type in Pytho3, so it needs to be decoded to str again
        sig = sig.decode('latin-1')

        url = "{url}/{containername}/{prefix}/{objectname}?AWSAccessKeyId={awsAccessKeyId}&Signature={signature}&Expires={expires}".format(
            url=self.url, containername=containername, prefix=prefix, objectname=objectname,
            awsAccessKeyId=self.user, signature=urllib.parse.quote(sig), expires=expires)

        try:
            resp = requests.head(url)

            if resp.ok:
                return True
            return False
        except Exception as e:
            logging.error("Error: {}".format(e))
            return False

    def authenticate(self, user, passwd):
        return True

    def is_token_valid(self):
        return True

    def create_upload_form(self, sourcepath, containername, prefix, ttl, max_file_size):

        objectname = sourcepath.split("/")[-1]

        expires = ttl + int(time.time())
        httpVerb = "PUT"
        contentMD5 = ""
        contentType = ""
        canonicalizedAmzHeaders = ""
        canonicalizedResource = "/{containername}/{prefix}/{objectname}".format(
            containername=containername, prefix=prefix, objectname=objectname)

        string_to_sign = httpVerb + "\n" + contentMD5 + "\n" + contentType + "\n" + \
                         str(expires) + "\n" + canonicalizedAmzHeaders + canonicalizedResource

        # to be used in hmac.new(key,msg,digestmode), the strings key (passwd) and msg (strin_to_sign) need to be byte type
        string_to_sign = string_to_sign.encode('latin-1')
        _passwd = bytes(self.passwd, 'latin1')

        sig = base64.b64encode(hmac.new(_passwd, string_to_sign, hashlib.sha1).digest())

        # signature will be Bytes type in Pytho3, so it needs to be decoded to str again
        sig = sig.decode('latin-1')
        
        url = "{url}/{containername}/{prefix}/{objectname}".format(
            url=self.url, containername=containername, prefix=prefix, objectname=objectname)

        retval = {}

        retval["parameters"] = {
            
            "url": url,
            "method": httpVerb,
            "params": {
                "AWSAccessKeyId": self.user,
                "Signature": sig,
                "Expires": expires
            },
            "files": sourcepath,
            "json": {},
            "data": {},
            "headers": {}
        }

        command = f"curl -s -i -X {httpVerb} '{url}?AWSAccessKeyId={self.user}&Signature={sig}&Expires={expires}' -T {sourcepath}"
        
        retval["command"] = command

        return retval

    def create_temp_url(self, containername, prefix, objectname, ttl):

        expires = ttl + int(time.time())
        httpVerb = "GET"
        contentMD5 = ""
        contentType = ""
        canonicalizedAmzHeaders = ""
        canonicalizedResource = "/{containername}/{prefix}/{objectname}".format(
            containername=containername, prefix=prefix, objectname=objectname)

        string_to_sign = httpVerb + "\n" + contentMD5 + "\n" + contentType + "\n" + \
                         str(expires) + "\n" + canonicalizedAmzHeaders + canonicalizedResource

        # sig = base64.b64encode(hmac.new(self.passwd, string_to_sign, hashlib.sha1).digest())

        # to be used in hmac.new(key,msg,digestmode), the strings key (passwd) and msg (strin_to_sign) need to be byte type
        string_to_sign = string_to_sign.encode('latin-1')
        _passwd = bytes(self.passwd, 'latin1')

        sig = base64.b64encode(hmac.new(_passwd, string_to_sign, hashlib.sha1).digest())

        # signature will be Bytes type in Pytho3, so it needs to be decoded to str again
        sig = sig.decode('latin-1')

        url = "{url}/{containername}/{prefix}/{objectname}?AWSAccessKeyId={awsAccessKeyId}&Signature={signature}&Expires={expires}".format(
            url=self.url, containername=containername, prefix=prefix, objectname=objectname,
            awsAccessKeyId=self.user, signature=urllib.parse.quote(sig), expires=expires)

        return url

    def delete_object_after(self,containername,prefix,objectname,ttl):

        # TODO: find a way to implement for s3

        return -1


    def delete_object(self,containername,prefix,objectname):

        expires = 360 + int(time.time())
        httpVerb = "DELETE"
        contentMD5 = ""
        contentType = ""
        canonicalizedAmzHeaders = ""
        canonicalizedResource = "/{containername}/{prefix}/{objectname}".format(
            containername=containername,prefix=prefix,objectname=objectname)

        string_to_sign = httpVerb + "\n" + contentMD5 + "\n" + contentType + "\n" + \
                         str(expires) + "\n" + canonicalizedAmzHeaders + canonicalizedResource


        # sig = base64.b64encode(hmac.new(self.passwd, string_to_sign, hashlib.sha1).digest())

        # to be used in hmac.new(key,msg,digestmode), the strings key (passwd) and msg (strin_to_sign) need to be byte type
        string_to_sign = string_to_sign.encode('latin-1')
        _passwd = bytes(self.passwd, 'latin1')

        sig = base64.b64encode(hmac.new(_passwd, string_to_sign, hashlib.sha1).digest())

        # signature will be Bytes type in Python3, so it needs to be decoded to str again
        sig = sig.decode('latin-1')

        url = "{url}/{containername}/{prefix}/{objectname}&AWSAccessKeyId={awsAccessKeyId}&Signature={signature}&Expires={expires}".format(
            url=self.url, containername=containername, prefix=prefix,objectname=objectname,
            awsAccessKeyId=self.user, signature=sig, expires=expires)

        print("Deleting {}/{}/{}".format(containername,prefix,objectname))
        print("URL: {}".format(url))

        try:
            resp = requests.delete(url)
            logging.info(resp.status_code)

            if resp.ok:
                logging.info("Object deleted succesfully")

                return 0
            # TODO: not working for some reason
            logging.error(resp.content)
            logging.error("Object couldn't be deleted "+url)
            return -1
        except Exception as e:
            logging.info(e)
            logging.error("Object couldn't be deleted "+url)
            return -1


