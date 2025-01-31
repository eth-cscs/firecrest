#
#  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from objectstorage import ObjectStorage

import boto3
import botocore.exceptions
from botocore.config import Config as BotoConfig
from botocore.handlers import validate_bucket_name
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


class S3v4(ObjectStorage):

    def __init__(self, priv_url, publ_url, user, passwd, region, tenant=None):
        self.user = user
        self.passwd = passwd
        self.priv_url = priv_url
        self.publ_url = publ_url
        self.region = region
        self.tenant = tenant

        self.s3_client = boto3.client("s3",
                                      endpoint_url=publ_url,
                                      aws_access_key_id=user,
                                      aws_secret_access_key=passwd,
                                      region_name=region,
                                      config=BotoConfig(
                                        signature_version="s3v4"))

        self.s3_client_priv = boto3.client("s3",
                                           endpoint_url=publ_url,
                                           aws_access_key_id=user,
                                           aws_secret_access_key=passwd,
                                           region_name=region,
                                           config=BotoConfig(
                                            signature_version="s3v4"))

        if tenant is not None:
            self.s3_client.meta.events.unregister(
                "before-parameter-build.s3", validate_bucket_name
            )

            self.s3_client_priv.meta.events.unregister(
                "before-parameter-build.s3", validate_bucket_name
            )

    def get_object_storage(self) -> str:
        '''
        Description:
            - returns description of the object storage

        Parameters:
            - `None`

        Returns:
            - `str`
        '''
        return "Amazon S3 - Signature v4"

    def create_container(self, containername: str, ttl: int = None) -> int:
        '''
        Description:
            creates a container (bucket) on the S3 server

        Parameters:
        - `containername (str)`: name of the container (or "bucket" on S3) to
        create

        Returns:
        - `int`
          - `0` if container was created correctly
          - `-1`if container wasn't created
        '''

        try:

            self.s3_client.create_bucket(Bucket=containername,
                                         CreateBucketConfiguration={
                                            "LocationConstraint": self.region
                                         }
                                         )

            logging.info(f"Created bucket/container {containername}")

            if ttl < 86400:  # 1 day
                ttl_days = 1
            else:
                ttl_days = ttl // 86400

            self.s3_client.put_bucket_lifecycle_configuration(
                Bucket=containername,
                LifecycleConfiguration={
                    "Rules": [
                        {
                            "Expiration": {"Days": ttl_days},
                            "Status": "Enabled",
                            "ID": "ExpiredObjects",
                            "Prefix": ""
                        }
                    ]
                }
            )
            logging.info(f"Lifecycle to bucket/container {containername}"
                         "applied")

        except botocore.exceptions.ClientError as ce:
            logging.error(f"Error creating bucket/container {containername}"
                          f"(error: {ce})")
            return -1

    def is_container_created(self, containername: str) -> bool:

        '''
        Description:
            checks if the container is created on the S3 server

        Parameters:
        - `containername (str)`: name of the container (or "bucket" on S3) to
        check if it's created

        Returns:
        - `bool`
          - `True` if container exists
          - `False` if container doesn't exist
        '''

        try:
            self.s3_client.head_bucket(Bucket=containername)
            logging.debug(f"Container {containername} found!")
            return True
        except botocore.exceptions.ClientError as ce:
            logging.debug(f"Container {containername} NOT found ({ce})")
            return False

    def get_users(self) -> List[str]:
        '''
        Description:
            returns a list of buckets on the s3 service

        Parameters:
        - `None`

        Returns:
        - `list[str]`
          - list of bucket names
        - `None`
          - error retrieving buckets
        '''

        try:
            bucket_names = []
            bucket_list = self.s3_client.list_buckets()

            for bucket in bucket_list["Buckets"]:
                bucket_names.append(bucket["Name"])

            return bucket_names

        except botocore.exceptions.ClientError as ce:
            logging.error(f"Error retrieving buckets ({ce})")
            return None

    def is_object_created(self, containername: str, prefix: str,
                          objectname: str) -> bool:
        '''
        Description:
            returns a list of buckets on the s3 service

        Parameters:
        - `containername (str)`: name of the container where the object is
        found
        - `prefix (str)`: name of the prefix where the object is found
        - `objectname (str)`: name of the object to found

        Returns:
        - `bool`
          - `True` if object is found
          - `False` if object is not found
        '''
        try:

            self.s3_client.head_object(Bucket=containername,
                                       Key=f"{prefix}/{objectname}")

            logging.debug(f"Object {prefix}/{objectname} found")
            return True

        except botocore.exceptions.ClientError as ce:
            logging.debug(f"Object not found ({ce})")
            return False

    #  Since S3 is used with signature, no token is needed,
    #  but this is kept only for consistency with objectstorage class
    def authenticate(self, user, passwd):
        return True

    def is_token_valid(self):
        return True

    def renew_token(self):
        return True

    def create_upload_form(self, sourcepath: str, containername: str,
                           prefix: str, ttl: int,
                           max_file_size: int, internal: bool = True) -> Dict:
        '''
        Description:
            returns a presigned temporary POST form (valid until `ttl` seconds
            after creation) to upload a local file in `sourcepath` into
            a `containername` (bucket) and `prefix

        Parameters:
        - `sourcepath (str)`: path to the local file to upload
        - `containername (str)`: name of the container where the object is
        found
        - `prefix (str)`: name of the prefix where the object is found
        - `ttl (int)`: expiration time in seconds for the Upload Form after
        creation
        - `max_file_size (int)`: legacy, not used
        - `internal (bool)` (default: `True`): used to indicate if the URL is
        related to the internal or external URL

        Returns:
        - `dict`
          - if empty, the URL couldn't be created
        '''

        objectname = sourcepath.split("/")[-1]
        endpoint_url = self.priv_url if internal else self.publ_url
        http_method = "POST"

        try:
            if not internal:
                form = self.s3_client.generate_presigned_post(
                    Bucket=containername,
                    Key=f"{prefix}/{objectname}",
                    ExpiresIn=ttl
                    )
            else:
                form = self.s3_client_priv.generate_presigned_post(
                    Bucket=containername,
                    Key=f"{prefix}/{objectname}",
                    ExpiresIn=ttl
                    )

        except botocore.exceptions.ClientError as ce:
            logging.error(f"Error creating URL to download"
                          f"{prefix}/{objectname} ({ce})")
            return {}

        retval = {}

        presigned_url = f"{form['url']}" if (self.tenant is None) \
                        else f"{endpoint_url}/{self.tenant}:{containername}"

        retval["parameters"] = {

            "method": http_method,
            "url": presigned_url,
            "data": form["fields"],
            "files": sourcepath,
            "json": {},
            "params": {},
            "headers": {}
        }

        command = f"curl -f --show-error -s -i -X {http_method} \
            {presigned_url}"

        for k, v in retval["parameters"]["data"].items():
            command += f" -F '{k}={v}'"

        command += f" -F file=@{retval['parameters']['files']}"

        retval["command"] = command

        return retval

    def create_temp_url(self, containername: str, prefix: str, objectname: str,
                        ttl: int, internal: bool = True) -> str:
        '''
        Description:
            returns a presigned temporary URL (valid until `ttl` seconds after
            creation) for an object in a container/bucket and prefix

        Parameters:
        - `containername (str)`: name of the container where the object is
        found
        - `prefix (str)`: name of the prefix where the object is found
        - `objectname (str)`: name of the object to found
        - `ttl (int)`: expiration time in seconds for the URL after creation
        - `internal (bool)` (default: `True`): used to indicate if the URL is
        related to the internal or external URL

        Returns:
        - `str`
          - URL to download the object
          - if empty, the URL couldn't be created
        '''

        bucketname = containername if self.tenant is None else \
            f"{self.tenant}:{containername}"

        try:
            if not internal:
                url = self.s3_client.generate_presigned_url(
                    "get_object",
                    Params={
                            "Bucket": bucketname,
                            "Key": f"{prefix}/{objectname}"
                           },
                    ExpiresIn=ttl
                    )
            else:
                url = self.s3_client_priv.generate_presigned_url(
                    "get_object",
                    Params={
                            "Bucket": bucketname,
                            "Key": f"{prefix}/{objectname}"
                           },
                    ExpiresIn=ttl
                    )

            return url
        except botocore.exceptions.ClientError as ce:
            logging.error(f"Error creating URL to download"
                          f"{prefix}/{objectname} ({ce})")
            return ""

    def list_objects(self, containername: str,
                     prefix: str = None) -> List[str]:
        '''
        Description:
            returns a list of objects on a specific bucket (and prefix)

        Parameters:
        - `containername (str)`: name of the container where objects are
        found
        - `prefix (str)`: name of the prefix where the objects are found

        Returns:
        - `list[str]`
          - objects returned correctly
        - `None`
          - objects couldn't be listed
        '''

        try:
            if prefix is None:
                response = self.s3_client.list_objects(Bucket=containername)
            else:
                response = self.s3_client.list_objects(Bucket=containername,
                                                       Prefix=prefix)

            object_list = []

            for bucket in response["Contents"]:
                object_list.append(bucket["Key"])

            return object_list

        except botocore.exceptions.ClientError as ce:
            logging.error(f"Error listing objects from {containername} ({ce})")
            return None
        except KeyError as ke:
            logging.error(f"Error listing objects from {containername} ({ke})")
            print(response)
            return None
        except Exception as e:
            logging.error(f"Error listing objects from {containername} ({e})")
            print(response)
            return None

    # it won't be applied, since buckets are already created with TTL
    # on /invalidate we just remove the object with `delete_object`
    def delete_object_after(self, containername: str, prefix: str,
                            objectname: str, ttl: int) -> int:

        return 0

    def delete_object(self, containername: str, prefix: str,
                      objectname: str) -> int:
        '''
        Description:
            deletes an object on a specific bucket (and prefix)

        Parameters:
        - `containername (str)`: name of the container where object to delete
        is found
        - `prefix (str)`: name of the prefix where object to delete
        is found
        - `object (str)`: name of the object to delete

        Returns:
        - `int`
          - `0` object deleted correctly
        - `-1`
          - objects couldn't be deleted
        '''

        try:

            self.s3_client.delete_object(Bucket=containername,
                                         Key=f"{prefix}/{objectname}")

            logging.info(f"Object {prefix}/{objectname} removed correctly")
            return 0

        except botocore.exceptions.ClientError as ce:
            logging.error(f"Object {prefix}/{objectname}"
                          f"couldn't be removed ({ce})")

            return -1
