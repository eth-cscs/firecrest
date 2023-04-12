#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from abc import ABCMeta,abstractmethod


class Keystone:
    __metaclass__ = ABCMeta

    # default constructor
    @abstractmethod
    def __init__(self,url):
        pass

    # returns a valid token if username & password are valid keystone credentials
    @abstractmethod
    def authenticate(username,password):
        pass

    # Checks if token is valid directly with keystone API
    @abstractmethod
    def is_token_valid(token):
        pass


