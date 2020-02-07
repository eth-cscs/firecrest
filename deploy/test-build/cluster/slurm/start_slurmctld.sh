#!/bin/bash
##
##  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
while true; do
   sleep 1
   # Search for "slurmdbd version 19.05.4 started"
   t=$(tail -n 2 /var/log/slurm/slurmdbd.log | grep started)
   # continue if succesful
   if [ "$t" != "" ]; then
     break
   fi
   echo "Slurmdbd not ready, retrying..."
done

sleep 1
echo "Slurmdbd ready, create cluster"
sacctmgr --immediate create cluster cluster

echo "Starting slurmctld"
/usr/sbin/slurmctld -D
