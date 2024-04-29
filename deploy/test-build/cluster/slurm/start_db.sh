#!/bin/bash
##
##  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##

# initialize DB
/usr/libexec/mariadb-prepare-db-dir

# inits on foreground
/usr/bin/mysqld_safe

