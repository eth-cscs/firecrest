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
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

class S3v4(ObjectStorage):

    def __init__(self, priv_url, publ_url, user, passwd):
        self.user = user
        self.passwd = passwd
        self.priv_url = priv_url
        self.publ_url = publ_url
        logger.info('Initialized s3v4')

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
        endpoint_url = self.priv_url
        host = endpoint_url.split("/")[-1]
        region = "us-east-1"

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        canonical_uri = f"/{containername}"
        canonical_headers = f"host:{host}\n"
        signed_headers = "host"
        credential_scope = f"{datestamp}/{region}/{service}/{aws_request}"

        # canonical_querystring = bucket_name+"/"+object_name
        canonical_querystring = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        canonical_querystring += f"&X-Amz-Credential={urllib.parse.quote_plus(f'{aws_access_key_id}/{credential_scope}')}"
        canonical_querystring += f"&X-Amz-Date={amzdate}"
        canonical_querystring += f"&X-Amz-Expires={str(ttl)}"
        canonical_querystring += f"&X-Amz-SignedHeaders={signed_headers}"

        payload_hash = "UNSIGNED-PAYLOAD"

        canonical_request = f"{httpVerb}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

        string_to_sign = f"{algorithm}\n{amzdate}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += f"&X-Amz-Signature={signature}"

        url = f"{endpoint_url}{canonical_uri}?{canonical_querystring}"

        logger.info(f"Creating container '{containername}'")
        logger.info(f"URL: {url}")

        try:
            resp = requests.put(url)
            
            if resp.ok:
                logger.info("Container created succesfully")
                return 0
            logger.error("Container couldn't be created")
            logger.error(resp.content)
            return -1
        except Exception as e:
            
            logger.error("Container couldn't be created")
            logger.error(e)
            return -1



    def is_container_created(self, containername):
        httpVerb = "HEAD"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        aws_access_key_id = self.user
        aws_secret_access_key = self.passwd
        endpoint_url = self.priv_url
        host = endpoint_url.split("/")[-1]
        region = "us-east-1"

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        canonical_uri = f"/{containername}"
        canonical_headers = f"host:{host}\n"
        signed_headers = "host"
        credential_scope = f"{datestamp}/{region}/{service}/{aws_request}"
        
        canonical_querystring = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        canonical_querystring += f"&X-Amz-Credential={urllib.parse.quote_plus(f'{aws_access_key_id}/{credential_scope}')}"
        canonical_querystring += f"&X-Amz-Date={amzdate}"
        canonical_querystring += f"&X-Amz-Expires={str(120)}"
        canonical_querystring += f"&X-Amz-SignedHeaders={signed_headers}"

        payload_hash = "UNSIGNED-PAYLOAD" 

        canonical_request = f"{httpVerb}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        string_to_sign = f"{algorithm}\n{amzdate}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += f"&X-Amz-Signature={signature}"

        url = f"{endpoint_url}{canonical_uri}?{canonical_querystring}"

        try:
            resp = requests.head(url)
            if resp.ok:
                return True
            logging.error("Container couldn't be checked")
            logging.error(resp.content)
            return False
        except requests.exceptions.ConnectionError as ce:
            logger.error("Container couldn't be checked")
            logger.error(ce.strerror)
            return False

    def get_users(self):
        httpVerb = "GET"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        aws_access_key_id = self.user
        aws_secret_access_key = self.passwd
        endpoint_url = self.priv_url
        host = endpoint_url.split("/")[-1]
        region = "us-east-1"

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope
        
        canonical_uri = "/"
        canonical_headers = f"host:{host}\n"
        signed_headers = "host"
        credential_scope = f"{datestamp}/{region}/{service}/{aws_request}"
        
        canonical_querystring = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        canonical_querystring += f"&X-Amz-Credential={urllib.parse.quote_plus(f'{aws_access_key_id}/{credential_scope}')}"
        canonical_querystring += f"&X-Amz-Date={amzdate}"
        canonical_querystring += f"&X-Amz-Expires={str(120)}"
        canonical_querystring += f"&X-Amz-SignedHeaders={signed_headers}"

        payload_hash = "UNSIGNED-PAYLOAD"

        canonical_request = f"{httpVerb}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        string_to_sign = f"{algorithm}\n{amzdate}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        
        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += f"&X-Amz-Signature={signature}"

        url = f"{endpoint_url}{canonical_uri}?{canonical_querystring}"

        try:
            resp = requests.get(url)
            
            if resp.ok:
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
            logger.error(ce.strerror)
            return None

        except Exception as e:
            logger.error(f"Error getting users: {e}")
            logger.error(f"Error type: {type(e)}")
            return None

    def is_object_created(self, containername, prefix, objectname):

        httpVerb = "HEAD"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        aws_access_key_id = self.user
        aws_secret_access_key = self.passwd
        endpoint_url = self.priv_url
        host = endpoint_url.split("/")[-1]
        region = "us-east-1"

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        canonical_uri = f"/{containername}/{prefix}/{objectname}"
        canonical_headers = f"host:{host}\n"
        signed_headers = "host"
        credential_scope = f"{datestamp}/{region}/{service}/{aws_request}"
        
        canonical_querystring = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        canonical_querystring += f"&X-Amz-Credential={urllib.parse.quote_plus(f'{aws_access_key_id}/{credential_scope}')}"
        canonical_querystring += f"&X-Amz-Date={amzdate}"
        canonical_querystring += f"&X-Amz-Expires={str(120)}"
        canonical_querystring += f"&X-Amz-SignedHeaders={signed_headers}"

        payload_hash = "UNSIGNED-PAYLOAD" 

        canonical_request = f"{httpVerb}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        string_to_sign = f"{algorithm}\n{amzdate}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += f"&X-Amz-Signature={signature}"

        url = f"{endpoint_url}{canonical_uri}?{canonical_querystring}"

        logger.info(f'Trying {url}')
        try:
            response = requests.head(url)
            if response.ok:
                return True
            return False
        except requests.exceptions.ConnectionError as ce:
            logger.error(ce.strerror)
            return False



    # Since S3 is used with signature, no token is needed,
    # but this is kept only for consistency with objectstorage class
    def authenticate(self, user, passwd):
        return True

    def is_token_valid(self):
        return True

    def renew_token(self):
        return True

    ## returns a Temporary Form URL for uploading without client and tokens
    # internal=True: by default the method asumes that the temp URL will be used in the internal network
    def create_upload_form(self, sourcepath, containername, prefix, ttl, max_file_size, internal=True):

        httpVerb = "POST"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        aws_secret_access_key = self.passwd
        if internal:
            endpoint_url = self.priv_url
        else:
            endpoint_url = self.publ_url
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


        retval = {}

        retval["parameters"] = {

            "method": httpVerb,
            "url": f"{endpoint_url}/{containername}",
            "data": {
                "key": prefix + "/" + objectname,
                "x-amz-algorithm": algorithm,
                "x-amz-credential": credentials,
                "x-amz-date": amzdate,
                "policy": base64Policy,
                "x-amz-signature" : signature
            },
            "files": sourcepath,
            "json" : {},
            "params": {},
            "headers": {}
        }

        command = f"curl --show-error -s -i -X {httpVerb} {endpoint_url}/{containername}"

        for k,v in retval["parameters"]["data"].items():
            command += f" -F '{k}={v}'"

        command+=f" -F file=@{retval['parameters']['files']}"
        logger.info(f'Created {command}')

        retval["command"] = command

        return retval
        
    ## returns a Temporary URL for downloading without client and tokens
    # internal=True: by default the method asumes that the temp URL will be used in the internal network
    def create_temp_url(self, containername, prefix, objectname, ttl, internal=True):

        httpVerb = "GET"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        aws_access_key_id = self.user
        aws_secret_access_key = self.passwd 
        if internal:
            endpoint_url = self.priv_url
        else:
            endpoint_url = self.publ_url
        
        host = endpoint_url.split("/")[-1] 
        region = "us-east-1"

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        canonical_uri = f"/{containername}/{prefix}/{objectname}"
        canonical_headers = f"host:{host}\n"
        signed_headers = "host"
        credential_scope = f"{datestamp}/{region}/{service}/{aws_request}"
        
        canonical_querystring = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        canonical_querystring += f"&X-Amz-Credential={urllib.parse.quote_plus(f'{aws_access_key_id}/{credential_scope}')}"
        canonical_querystring += f"&X-Amz-Date={amzdate}"
        canonical_querystring += f"&X-Amz-Expires={str(ttl)}"
        canonical_querystring += f"&X-Amz-SignedHeaders={signed_headers}"

        payload_hash = "UNSIGNED-PAYLOAD" 

        canonical_request = f"{httpVerb}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        string_to_sign = f"{algorithm}\n{amzdate}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += f"&X-Amz-Signature={signature}"

        url = f"{endpoint_url}{canonical_uri}?{canonical_querystring}"

        return url

    def list_objects(self,containername,prefix=None):
        httpVerb = "GET"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        aws_access_key_id = self.user  
        aws_secret_access_key = self.passwd  
        endpoint_url = self.priv_url
        host = endpoint_url.split("/")[-1]  
        region = "us-east-1"

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        canonical_uri = f"/{containername}" 
        canonical_headers = f"host:{host}\n"
        signed_headers = "host"
        credential_scope = f"{datestamp}/{region}/{service}/{aws_request}"

        
        canonical_querystring = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        canonical_querystring += f"&X-Amz-Credential={urllib.parse.quote_plus(f'{aws_access_key_id}/{credential_scope}')}"
        canonical_querystring += f"&X-Amz-Date={amzdate}"
        canonical_querystring += f"&X-Amz-Expires={str(120)}"
        canonical_querystring += f"&X-Amz-SignedHeaders={signed_headers}"

        payload_hash = "UNSIGNED-PAYLOAD" 

        canonical_request = f"{httpVerb}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        string_to_sign = f"{algorithm}\n{amzdate}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += f"&X-Amz-Signature={signature}"

        url = f"{endpoint_url}{canonical_uri}?{canonical_querystring}"

        try:
            resp = requests.get(url)

            if resp.ok:
                # logger.info(resp.content)
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
            logger.error(ce.strerror)
            return None

        except Exception as e:
            logger.error(f"Error listing objects: {e}")
            logger.error(f"Error type: {type(e)}")
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
        endpoint_url = self.priv_url
        host = endpoint_url.split("/")[-1]
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

        canonical_uri = f"/{containername}"
        canonical_headers = f"content-md5:{content_md5}\nhost:{host}\nx-amz-content-sha256:{content_sha256}\nx-amz-date:{amzdate}"
        signed_headers = "content-md5;host;x-amz-content-sha256;x-amz-date"
        credential_scope = f"{datestamp}/{region}/{service}/{aws_request}"
        canonical_querystring = "lifecycle="

        headers = { "Content-MD5": content_md5, 
                    "Host": host,
                    "X-Amz-Content-Sha256": content_sha256,
                    "X-Amz-Date": amzdate}

        canonical_request = f"{httpVerb}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n\n{signed_headers}\n{content_sha256}"
        
        canonical_request_hash = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()

        string_to_sign = f"{algorithm}\n{amzdate}\n{credential_scope}\n{canonical_request_hash}"

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={aws_access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

        url = f"{endpoint_url}{canonical_uri}?{canonical_querystring}"
        
        try:
            resp = requests.put(url, data=body, headers=headers)

            if resp.ok:
                logger.info(f"Object was marked as to be deleted at {_delete_at_iso}")

                return 0

            logger.error("Object couldn't be marked as delete-at")
            logger.error(resp.content)
            logger.error(resp.headers)
            return -1
        except Exception as e:
            logger.error(e)
            logger.error("Object couldn't be marked as delete-at")
            return -1


    def delete_object(self,containername,prefix,objectname):

        ttl = 120
        httpVerb = "DELETE"
        algorithm = 'AWS4-HMAC-SHA256'
        service = "s3"
        aws_request = "aws4_request"
        aws_access_key_id = self.user
        aws_secret_access_key = self.passwd 
        endpoint_url = self.priv_url
        host = endpoint_url.split("/")[-1] 
        region = "us-east-1"

        # Create a date for headers and the credential string
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        canonical_uri = f"/{containername}/{prefix}/{objectname}"

        canonical_headers = f"host:{host}\n"
        signed_headers = "host"
        credential_scope = f"{datestamp}/{region}/{service}/{aws_request}"

        
        canonical_querystring = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        canonical_querystring += f"&X-Amz-Credential={urllib.parse.quote_plus(f'{aws_access_key_id}/{credential_scope}')}"
        canonical_querystring += f"&X-Amz-Date={amzdate}"
        canonical_querystring += f"&X-Amz-Expires={str(ttl)}"
        canonical_querystring += f"&X-Amz-SignedHeaders={signed_headers}"

        payload_hash = "UNSIGNED-PAYLOAD" 

        canonical_request = f"{httpVerb}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        string_to_sign = f"{algorithm}\n{amzdate}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

        # Create the signing key
        signing_key = self.getSignatureKey(aws_secret_access_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        canonical_querystring += f"&X-Amz-Signature={signature}"
        
        url = f"{endpoint_url}{canonical_uri}?{canonical_querystring}"

        logger.info(f"Deleting object {canonical_uri}")
        logger.info(f"URL: {url}")

        try:
            resp = requests.delete(url)

            if resp.ok:
                logger.info("Object deleted succesfully")

                return 0
            logger.error("Object couldn't be deleted")
            return -1
        except Exception as e:
            logger.error("Object couldn't be deleted")
            logger.error(e)
            return -1


