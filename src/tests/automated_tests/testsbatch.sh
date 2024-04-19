#!/bin/bash
##
##  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##

#SBATCH --job-name=testsbatch
#SBATCH --ntasks=1
#SBATCH --tasks-per-node=1
#SBATCH --output=testsbatch.output
#SBATCH --error=testsbatch.error
#SBATCH --oversubscribe --mem=50M

echo $F7T_TEST_JOB_ENV > /tmp/env_${SLURM_JOB_ID}.out
echo $F7T_TEST_JOB_ENV2 >> /tmp/env_${SLURM_JOB_ID}.out

sleep 60s
