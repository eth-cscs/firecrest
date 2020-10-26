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
        aws_access_key_id = self.user
        aws_secret_access_key = self.passwd
        endpoint_url = self.url
        host = self.url.split("/")[-1]
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

        url = endpoint_url + canonical_uri + "?" + canonical_querystring

        return url

    def list_objects(self,containername,prefix=None):
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

        canonical_uri = f"/{containername}" 

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

        url = endpoint_url + canonical_uri + "?" + canonical_querystring

        try:
            resp = requests.get(url)

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
            else:
                return None
        except requests.exceptions.ConnectionError as ce:
            logging.error(ce.strerror)
            return None

        except Exception as e:
            logging.error("Error: {}".format(e))
            logging.error("Error: {}".format(type(e)))
            return None

    def _prepare_xml(self,prefix, expiration_date_value):

        lc_root = ElementTree.Element("LifecycleConfiguration", {'xmlns': "http://s3.amazonaws.com/doc/2006-03-01/"})
        rule_branch = ElementTree.SubElement(lc_root,"Rule")
        rule_status = ElementTree.SubElement(rule_branch,"Status")
        rule_status.text = "Enabled"
        rule_expiration = ElementTree.SubElement(rule_branch, "Expiration")
        expiration_date = ElementTree.SubElement(rule_expiration, "Date")
        expiration_date.text = expiration_date_value
        rule_filter = ElementTree.SubElement(rule_branch, "Filter")
        filter_prefix = ElementTree.SubElement(rule_filter, "Prefix")
        filter_prefix.text = f"{prefix}/"
        rule_id = ElementTree.SubElement(rule_branch,"ID")
        rule_id.text= prefix
        
        

        import io
        body_data = io.BytesIO()
        
        ElementTree.ElementTree(lc_root).write(body_data, encoding=None, xml_declaration=False)
        body = body_data.getvalue()

        import hashlib
        hasher = hashlib.md5()
        hasher.update(body)
        
        import base64
        md5sum = base64.b64encode(hasher.digest())
        md5sum_decoded = md5sum.decode()

        hash256 = hashlib.sha256()
        hash256.update(body)
        sha256sum =  hash256.hexdigest()
        # sha256sum_decoded = sha256sum.decode()

        return body, md5sum_decoded, sha256sum

    # For S3v4 delete_at only works at midnight UTC (from http://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTlifecycle.html)
    # "The date value must conform to the ISO 8601 format. The time is always midnight UTC."
    # 
    #  therefore the expiration time will be managed to the midnigt of the next day and timezone is Z (UTC+0)
    def delete_object_after(self,containername,prefix,objectname,ttl):
        
        httpVerb = "PUT"
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

        # since only midnight is allowed, deleting T%H:%M:%S
        d1_str = datetime.utcfromtimestamp(ttl).strftime("%Y-%m-%d")
        
        d1 = datetime.strptime(d1_str,"%Y-%m-%d") # convert to datetime        
        d2 = d1 + timedelta(days=1) # add 1 day        
        _delete_at_iso = d2.strftime("%Y-%m-%dT%H:%M:%SZ") # after adding 1 day, reconvert to str

        
        [body, content_md5, content_sha256] = self._prepare_xml(prefix, _delete_at_iso)

        canonical_uri = "/" + containername 

        canonical_headers = f"content-md5:{content_md5}\nhost:{host}\nx-amz-content-sha256:{content_sha256}\nx-amz-date:{amzdate}"
        
        signed_headers = "content-md5;host;x-amz-content-sha256;x-amz-date"

        credential_scope = datestamp + '/' + region + '/' + service + '/' + aws_request
        

        canonical_querystring = "lifecycle="

        

        headers = { "Content-MD5": content_md5, 
                    "Host": host,
                    "X-Amz-Content-Sha256": content_sha256,
                    "X-Amz-Date": amzdate}


        canonical_request = httpVerb + "\n" + canonical_uri + "\n" + canonical_querystring + "\n" + canonical_headers + '\n\n' + signed_headers + "\n" + content_sha256
       

        canonical_request_hash = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()

        string_to_sign = f"{algorithm}\n{amzdate}\n{credential_scope}\n{canonical_request_hash}"

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={aws_access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    
        url = endpoint_url + canonical_uri +"?"+ canonical_querystring
       
        
        try:
            resp = requests.put(url, data=body, headers=headers)

            if resp.ok:
                logging.info("Object marked as delete-at succesfully")

                return 0
            
            logging.error("Object couldn't be marked as delete-at")
            logging.error(resp.content)
            logging.error(resp.headers)
            return -1
        except Exception as e:
            logging.error(e)
            logging.error("Object couldn't be marked as delete-at")
            return -1


    def delete_object(self,containername,prefix,objectname):

        ttl = 120
        httpVerb = "DELETE"
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
        
        url = endpoint_url + canonical_uri + "?" + canonical_querystring

        logging.info(f"Deleting {canonical_uri}")
        logging.info("URL: {}".format(url))

        try:
            resp = requests.delete(url)
            
            if resp.ok:
                logging.info("Object deleted succesfully")

                return 0
            logging.error("Object couldn't be deleted")
            return -1
        except Exception as e:
            logging.error(e)
            logging.error("Object couldn't be deleted")
            return -1


