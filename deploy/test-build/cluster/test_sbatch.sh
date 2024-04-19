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


sleep 60s
