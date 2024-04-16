#!/bin/bash
#SBATCH --job-name=f7t_test
#SBATCH --ntasks=1
#SBATCH --tasks-per-node=1


echo "FirecREST test submit on demo\n"
echo "Host: `hostname`"
echo "Test starts: `date` \n"
echo "Sleeping 120s \n"

sleep 120s

echo "Test finishes: `date` \n"
