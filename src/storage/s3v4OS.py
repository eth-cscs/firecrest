#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
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
from _datetime import datetime, timedelta
import json


class S3v4(ObjectStorage):

    def __init__(self, url, user, passwd):
        self.user = user
        self.passwd = passwd
        self.url = url

    def get_object_storage(self):
        return "Amazon S3 - Signature v4"

    def sign(self,key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def getSignatureKey(self,key, dateStamp, regionName, serviceName):
        kDate = self.sign(('AWS4' + key).encode('utf-8'), dateStamp)
        kRegion = self.sign(kDate, regionName)
        kService = self.sign(kRegion, serviceName)
        kSigning = self.sign(kService, 'aws4_request')
        return kSigning

    def create_container(self, containername):
        ttl = 120
        httpVerb = "PUT"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        aws_access_key_id = self.user# "storage_access_key"
        aws_secret_access_key = self.passwd #"storage_secret_key"
        endpoint_url = self.url #"http://192.168.220.19:9000"
        host = self.url.split("/")[-1] #192.168.220.19:9000"
        region = "us-east-1"

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        canonical_uri = "/" + containername

        canonical_headers = 'host:' + host + "\n"  # + "x-amz-date:"+ amzdate + "\n"

        signed_headers = "host"  # "host;x-amz-content-sha256;x-amz-date"

        credential_scope = datestamp + '/' + region + '/' + service + '/' + aws_request

        # canonical_querystring = bucket_name+"/"+object_name
        canonical_querystring = 'X-Amz-Algorithm=AWS4-HMAC-SHA256'
        canonical_querystring += '&X-Amz-Credential=' + urllib.parse.quote_plus(
            aws_access_key_id + '/' + credential_scope)
        canonical_querystring += '&X-Amz-Date=' + amzdate
        canonical_querystring += '&X-Amz-Expires=' + str(ttl)
        canonical_querystring += '&X-Amz-SignedHeaders=' + signed_headers

        payload_hash = "UNSIGNED-PAYLOAD"  # ???????? hashlib.sha256(("").encode("utf-8")).hexdigest()

        canonical_request = httpVerb + "\n" + canonical_uri + "\n" + canonical_querystring + "\n" + canonical_headers + '\n' + signed_headers + "\n" + payload_hash

        string_to_sign = algorithm + "\n" + amzdate + "\n" + credential_scope + "\n" + hashlib.sha256(
            canonical_request.encode("utf-8")).hexdigest()

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += '&X-Amz-Signature=' + signature

        # print(f"Canonical request: \n{canonical_request}")
        # print(f"String to Sign: \n{string_to_sign}")

        url = endpoint_url + canonical_uri + "?" + canonical_querystring

        logging.info("Deleting {}".format(containername))
        logging.info("URL: {}".format(url))

        try:
            resp = requests.put(url)
            print(resp.status_code)
            print(resp.text)

            if resp.ok:
                logging.info("Container created succesfully")

                return 0
            logging.error("Container couldn't be created")
            return -1
        except Exception as e:
            logging.error(e)
            logging.error("Container couldn't be created")
            return -1



    def is_container_created(self, containername):
        httpVerb = "HEAD"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        aws_access_key_id = self.user  #
        aws_secret_access_key = self.passwd  # 
        endpoint_url = self.url  # 
        host = self.url.split("/")[-1]  # 
        region = "us-east-1"

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        canonical_uri = "/" + containername

        canonical_headers = 'host:' + host + "\n"  # + "x-amz-date:"+ amzdate + "\n"

        signed_headers = "host"  # "host;x-amz-content-sha256;x-amz-date"

        credential_scope = datestamp + '/' + region + '/' + service + '/' + aws_request

        # canonical_querystring = bucket_name+"/"+object_name
        canonical_querystring = 'X-Amz-Algorithm=AWS4-HMAC-SHA256'
        canonical_querystring += '&X-Amz-Credential=' + urllib.parse.quote_plus(
            aws_access_key_id + '/' + credential_scope)
        canonical_querystring += '&X-Amz-Date=' + amzdate
        canonical_querystring += '&X-Amz-Expires=' + str(120)
        canonical_querystring += '&X-Amz-SignedHeaders=' + signed_headers

        payload_hash = "UNSIGNED-PAYLOAD"  # ???????? hashlib.sha256(("").encode("utf-8")).hexdigest()

        canonical_request = httpVerb + "\n" + canonical_uri + "\n" + canonical_querystring + "\n" + canonical_headers + '\n' + signed_headers + "\n" + payload_hash

        string_to_sign = algorithm + "\n" + amzdate + "\n" + credential_scope + "\n" + hashlib.sha256(
            canonical_request.encode("utf-8")).hexdigest()

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += '&X-Amz-Signature=' + signature

        # print(f"Canonical request: \n{canonical_request}")
        # print(f"String to Sign: \n{string_to_sign}")

        url = endpoint_url + canonical_uri + "?" + canonical_querystring

        try:
            response = requests.head(url)
            if response.ok:
                return True
            return False
        except requests.exceptions.ConnectionError as ce:
            logging.error(ce.strerror)
            return False

    def get_users(self):
        httpVerb = "GET"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        aws_access_key_id = self.user  #
        aws_secret_access_key = self.passwd  # 
        endpoint_url = self.url  # 
        host = self.url.split("/")[-1]  # 
        region = "us-east-1"

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        canonical_uri = "/" 

        canonical_headers = 'host:' + host + "\n"  # + "x-amz-date:"+ amzdate + "\n"

        signed_headers = "host"  # "host;x-amz-content-sha256;x-amz-date"

        credential_scope = datestamp + '/' + region + '/' + service + '/' + aws_request

        # canonical_querystring = bucket_name+"/"+object_name
        canonical_querystring = 'X-Amz-Algorithm=AWS4-HMAC-SHA256'
        canonical_querystring += '&X-Amz-Credential=' + urllib.parse.quote_plus(
            aws_access_key_id + '/' + credential_scope)
        canonical_querystring += '&X-Amz-Date=' + amzdate
        canonical_querystring += '&X-Amz-Expires=' + str(120)
        canonical_querystring += '&X-Amz-SignedHeaders=' + signed_headers

        payload_hash = "UNSIGNED-PAYLOAD"  # ???????? hashlib.sha256(("").encode("utf-8")).hexdigest()

        canonical_request = httpVerb + "\n" + canonical_uri + "\n" + canonical_querystring + "\n" + canonical_headers + '\n' + signed_headers + "\n" + payload_hash

        string_to_sign = algorithm + "\n" + amzdate + "\n" + credential_scope + "\n" + hashlib.sha256(
            canonical_request.encode("utf-8")).hexdigest()

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += '&X-Amz-Signature=' + signature

        # print(f"Canonical request: \n{canonical_request}")
        # print(f"String to Sign: \n{string_to_sign}")

        url = endpoint_url + canonical_uri + "?" + canonical_querystring

        try:
            resp = requests.get(url)

            # logging.info(response.text)

            
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
        except requests.exceptions.ConnectionError as ce:
            logging.error(ce.strerror)
            return None

        except Exception as e:
            logging.error("Error: {}".format(e))
            logging.error("Error: {}".format(type(e)))
            return None

    def is_object_created(self, containername, prefix, objectname):

        httpVerb = "HEAD"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        aws_access_key_id = self.user  # "storage_access_key"
        aws_secret_access_key = self.passwd  # "storage_secret_key"
        endpoint_url = self.url  # "http://192.168.220.19:9000"
        host = self.url.split("/")[-1]  # 192.168.220.19:9000"
        region = "us-east-1"

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        canonical_uri = "/" + containername + "/" + prefix + "/" + objectname

        canonical_headers = 'host:' + host + "\n"  # + "x-amz-date:"+ amzdate + "\n"

        signed_headers = "host"  # "host;x-amz-content-sha256;x-amz-date"

        credential_scope = datestamp + '/' + region + '/' + service + '/' + aws_request

        # canonical_querystring = bucket_name+"/"+object_name
        canonical_querystring = 'X-Amz-Algorithm=AWS4-HMAC-SHA256'
        canonical_querystring += '&X-Amz-Credential=' + urllib.parse.quote_plus(
            aws_access_key_id + '/' + credential_scope)
        canonical_querystring += '&X-Amz-Date=' + amzdate
        canonical_querystring += '&X-Amz-Expires=' + str(120)
        canonical_querystring += '&X-Amz-SignedHeaders=' + signed_headers

        payload_hash = "UNSIGNED-PAYLOAD"  # ???????? hashlib.sha256(("").encode("utf-8")).hexdigest()

        canonical_request = httpVerb + "\n" + canonical_uri + "\n" + canonical_querystring + "\n" + canonical_headers + '\n' + signed_headers + "\n" + payload_hash

        string_to_sign = algorithm + "\n" + amzdate + "\n" + credential_scope + "\n" + hashlib.sha256(
            canonical_request.encode("utf-8")).hexdigest()

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += '&X-Amz-Signature=' + signature

        # print(f"Canonical request: \n{canonical_request}")
        # print(f"String to Sign: \n{string_to_sign}")

        url = endpoint_url + canonical_uri + "?" + canonical_querystring

        try:
            response = requests.head(url)
            if response.ok:
                return True
            return False
        except requests.exceptions.ConnectionError as ce:
            logging.error(ce.strerror)
            return False



    def authenticate(self, user, passwd):
        return True

    def is_token_valid(self):
        return True

    def create_upload_form(self, sourcepath, containername, prefix, ttl, max_file_size):

        httpVerb = "POST"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        # aws_access_key_id = self.user
        aws_secret_access_key = self.passwd
        endpoint_url = self.url  # "http://ip[:port]"
        # host = self.url.split("/")[-1]  # ip[:port["
        region = "us-east-1"
        objectname = sourcepath.split("/")[-1]

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        credentials = f"{self.user}/{datestamp}/{region}/{service}/{aws_request}"

        policy = {
            "expiration": (datetime.now() + timedelta(seconds=ttl)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "conditions":[
                {"bucket": containername},
                {"key": prefix+"/"+objectname},
                {"x-amz-algorithm": algorithm},
                {"x-amz-credential": credentials},
                {"x-amz-date": amzdate}
            ]
        }

        base64Policy = base64.b64encode(json.dumps(policy).encode('utf-8')).decode('utf-8')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope
        signing_key = self.getSignatureKey(aws_secret_access_key,datestamp,region,service)

        signature = hmac.new(signing_key, base64Policy.encode('utf-8'), hashlib.sha256).hexdigest()

        fields = {
            "key": prefix + "/" + objectname,
            "x-amz-algorithm": algorithm,
            "x-amz-credential": credentials,
            "x-amz-date": amzdate,
            "policy": base64Policy,
            "x-amz-signature" : signature
        }

        command = f"curl -i -X {httpVerb} {endpoint_url}/{containername}"

        for k,v in fields.items():
            command += f" -F '{k}={v}'"

        command+=f" -F file=@{sourcepath}"

        fields["command"] = command
        fields["method"]  = httpVerb
        fields["url"] = f"{endpoint_url}/{containername}"

        return fields


    def create_temp_url(self, containername, prefix, objectname, ttl):

        httpVerb = "GET"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        aws_access_key_id = self.user
        aws_secret_access_key = self.passwd 
        endpoint_url = self.url 
        host = self.url.split("/")[-1] 
        region = "us-east-1"

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        canonical_uri = "/" + containername + "/" + prefix + "/" + objectname

        canonical_headers = 'host:' + host + "\n"  # + "x-amz-date:"+ amzdate + "\n"

        signed_headers = "host"  # "host;x-amz-content-sha256;x-amz-date"

        credential_scope = datestamp + '/' + region + '/' + service + '/' + aws_request

        # canonical_querystring = bucket_name+"/"+object_name
        canonical_querystring = 'X-Amz-Algorithm=AWS4-HMAC-SHA256'
        canonical_querystring += '&X-Amz-Credential=' + urllib.parse.quote_plus(
            aws_access_key_id + '/' + credential_scope)
        canonical_querystring += '&X-Amz-Date=' + amzdate
        canonical_querystring += '&X-Amz-Expires=' + str(ttl)
        canonical_querystring += '&X-Amz-SignedHeaders=' + signed_headers

        payload_hash = "UNSIGNED-PAYLOAD"  # ???????? hashlib.sha256(("").encode("utf-8")).hexdigest()

        canonical_request = httpVerb + "\n" + canonical_uri + "\n" + canonical_querystring + "\n" + canonical_headers + '\n' + signed_headers + "\n" + payload_hash

        string_to_sign = algorithm + "\n" + amzdate + "\n" + credential_scope + "\n" + hashlib.sha256(
            canonical_request.encode("utf-8")).hexdigest()

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += '&X-Amz-Signature=' + signature

        # print(f"Canonical request: \n{canonical_request}")
        # print(f"String to Sign: \n{string_to_sign}")

        url = endpoint_url + canonical_uri + "?" + canonical_querystring

        return url

    def delete_object_after(self,containername,prefix,objectname,ttl):

        # TODO: find a way to implement for s3

        return -1


    def delete_object(self,containername,prefix,objectname):

        ttl = 120
        httpVerb = "DELETE"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        aws_access_key_id = self.user# "storage_access_key"
        aws_secret_access_key = self.passwd #"storage_secret_key"
        endpoint_url = self.url #"http://192.168.220.19:9000"
        host = self.url.split("/")[-1] #192.168.220.19:9000"
        region = "us-east-1"

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        canonical_uri = "/" + containername + "/" + prefix + "/" + objectname

        canonical_headers = 'host:' + host + "\n"  # + "x-amz-date:"+ amzdate + "\n"

        signed_headers = "host"  # "host;x-amz-content-sha256;x-amz-date"

        credential_scope = datestamp + '/' + region + '/' + service + '/' + aws_request

        # canonical_querystring = bucket_name+"/"+object_name
        canonical_querystring = 'X-Amz-Algorithm=AWS4-HMAC-SHA256'
        canonical_querystring += '&X-Amz-Credential=' + urllib.parse.quote_plus(
            aws_access_key_id + '/' + credential_scope)
        canonical_querystring += '&X-Amz-Date=' + amzdate
        canonical_querystring += '&X-Amz-Expires=' + str(ttl)
        canonical_querystring += '&X-Amz-SignedHeaders=' + signed_headers

        payload_hash = "UNSIGNED-PAYLOAD"  # ???????? hashlib.sha256(("").encode("utf-8")).hexdigest()

        canonical_request = httpVerb + "\n" + canonical_uri + "\n" + canonical_querystring + "\n" + canonical_headers + '\n' + signed_headers + "\n" + payload_hash

        string_to_sign = algorithm + "\n" + amzdate + "\n" + credential_scope + "\n" + hashlib.sha256(
            canonical_request.encode("utf-8")).hexdigest()

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += '&X-Amz-Signature=' + signature

        # print(f"Canonical request: \n{canonical_request}")
        # print(f"String to Sign: \n{string_to_sign}")

        url = endpoint_url + canonical_uri + "?" + canonical_querystring

        logging.info("Deleting {}/{}/{}".format(containername,prefix,objectname))
        logging.info("URL: {}".format(url))

        try:
            resp = requests.delete(url)
            # print(resp.status_code)
            # print(resp.text)

            if resp.ok:
                logging.info("Object deleted succesfully")

                return 0
            logging.error("Object couldn't be deleted")
            return -1
        except Exception as e:
            logging.error(e)
            logging.error("Object couldn't be deleted")
            return -1


