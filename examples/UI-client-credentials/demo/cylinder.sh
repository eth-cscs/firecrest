#!/bin/bash -l
#SBATCH --job-name=sarus
#SBATCH --time=00:10:00
#SBATCH --nodes=1
#SBATCH --partition=debug
#SBATCH --constraint=gpu
#SBATCH --account=test


#SBATCH --dependency=afterok:12

module load daint-gpu
module load sarus

step=7
cd /home/test/dir

ini=cylinder_${step}.ini
if [ $step -eq 1 ]; then
   command="run"
   prev=""
 else
   # there's a previous solution
   command="restart"
   prev=" solution.pyfrs "
fi
sarus run --mount=type=bind,src=$(pwd),dst=/pyfr --workdir=/pyfr ethcscs/pyfr:1.12.0-cuda11.3-mpich3.1.4-ubuntu20.04 pyfr $command -b cuda -p inc_cylinder_2d.pyfrm ${prev} $ini
cp --force inc_cylinder_2d_20.00.pyfrs solution.pyfrs

