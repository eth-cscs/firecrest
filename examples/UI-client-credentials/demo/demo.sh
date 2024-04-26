#!/bin/bash
##
##  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
#! /bin/bash -l
#SBATCH --job-name=sarus
#SBATCH --error=job-%j.err
#SBATCH --output=job-%j.out

# optional parameters
#SBATCH --partition=debug
#SBATCH --account=test
#SBATCH --constraint=gpu


#SBATCH --dependency=afterok:12


#SBATCH --ntasks=1
#SBATCH --tasks-per-node=1

step=7
cd /home/test/dir

echo -e "$SLURM_JOB_NAME started on $(date)"
sleep 120s
echo "Solution $step" > out_${step}0.00.pyfrs
echo -e "$SLURM_JOB_NAME finished on $(date)"