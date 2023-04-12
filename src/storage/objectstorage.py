#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from abc import ABCMeta,abstractmethod


class ObjectStorage:
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self,url):
        pass

    @abstractmethod
    def authenticate(self,user,passwd):
        pass

    @abstractmethod
    def is_token_valid(self):
        pass

    @abstractmethod
    def renew_token(self):
        pass

    @abstractmethod
    def create_container(self,containername):
         pass

    @abstractmethod
    def get_users(self):
         pass

    @abstractmethod
    def delete_object_after(self,containername,prefix,objectname,ttl):
         pass

    @abstractmethod
    def delete_object(self,containername,prefix,objectname):
        pass

    @abstractmethod
    def get_object_storage(self):
        pass

    @abstractmethod
    def is_object_created(self,containername,prefix,objectname):
        pass

    @abstractmethod
    def create_temp_url(self,containername,prefix,objectname,ttl,internal):
        pass

    @abstractmethod
    def is_container_created(self,containername):
        pass

    @abstractmethod
    def create_upload_form(self,sourcepath,containername,prefix,ttl,max_file_size,internal):
        pass

    @abstractmethod
    def list_objects(self,containername,prefix):
        pass




