#
#  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
# from __future__ import annotations

import datetime
import os
import pendulum

from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.sensors.filesystem import FileSensor

from firecrest_airflow_operators import (FirecRESTSubmitOperator,
                                         FirecRESTUploadOperator,
                                         FirecRESTDownloadOperator)


workdir =   # absolute path to the directory `use-case-airflow-operator` in the repo
username =  # the course account (classXXX)

job_script = """#!/bin/bash -l

#SBATCH --job-name=fc-airflow-example
#SBATCH --time=00:05:00
#SBATCH --nodes=1
#SBATCH --ntasks-per-core=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=12
#SBATCH --constraint=gpu
#SBATCH --account=class08
#SBATCH --reservation=firecrest_api

module load daint-gpu
module load QuantumESPRESSO

export OMP_NUM_THREADS=$SLURM_CPUS_PER_TASK

mv $SCRATCH/si.scf.in $SCRATCH/Si.pz-vbc.UPF .

srun pw.x -in si.scf.in
"""

with DAG(
    dag_id="firecrest_example",
    schedule="@daily",
    start_date=pendulum.datetime(2023, 9, 1, tz="UTC"),
    catchup=False,
    dagrun_timeout=datetime.timedelta(minutes=60),
    tags=["firecrest-training-2023"],
) as dag:

    wait_for_file = FileSensor(
        task_id="wait-for-file",
        filepath=os.path.join(workdir, "structs", "si.scf.in"),
        poke_interval=10
    )

    upload_in = FirecRESTUploadOperator(
        task_id="upload-in",
        system="daint",
        source_path=os.path.join(workdir, "structs", "si.scf.in"),
        target_path=f"/scratch/snx3000/{username}"
    )

    upload_pp = FirecRESTUploadOperator(
        task_id="upload-pp",
        system="daint",
        source_path=os.path.join(workdir, "Si.pz-vbc.UPF"),
        target_path=f"/scratch/snx3000/{username}"
    )

    submit_task = FirecRESTSubmitOperator(
        task_id="job-submit",
        system="daint", script=job_script
    )

    download_task = FirecRESTDownloadOperator(
        task_id="download-out",
        system="daint",
        local_path=os.path.join(workdir, "output.out"),
        target_task_id="job-submit"
    )

    log_results = BashOperator(
        task_id="log-results",
        bash_command=(f"echo $(date) '  |  ' "
                      f"$(grep '!    total energy' {workdir}/output.out) >> {workdir}/list.txt"),
    )

    remove_struct = BashOperator(
        task_id="remove-struct",
        bash_command=(f"rm {workdir}/structs/si.scf.in"),
    )

    wait_for_file >> upload_in
    wait_for_file >> upload_pp
    upload_in >> submit_task >> download_task >> log_results
    upload_pp >> submit_task
    upload_in >> remove_struct


if __name__ == "__main__":
    dag.test()
