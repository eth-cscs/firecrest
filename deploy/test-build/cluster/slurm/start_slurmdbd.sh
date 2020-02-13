#!/bin/bash
##
##  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##

while true; do
   echo "use mysql;" | mysql -u root
   # continue if succesful
   if [ "$?" == 0 ]; then
     break
   fi
   sleep 1
done

echo "CREATE USER slurmdb@localhost IDENTIFIED BY 'slurmdbpass';" | mysql -u root
echo "CREATE DATABASE slurmdb; GRANT ALL PRIVILEGES ON slurmdb.* TO slurmdb;" | mysql -u root

/usr/sbin/slurmdbd -D