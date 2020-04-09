#!/bin/bash
#SBATCH --job-name=testsbatch
#SBATCH --ntasks=1
#SBATCH --tasks-per-node=1
#SBATCH --output=testsbatch.output
#SBATCH --error=testsbatch.error


sleep 60s
