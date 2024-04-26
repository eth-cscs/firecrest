#
#  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#

def create_batch_script(repo, constraint, num_nodes=1, account=None, custom_modules=None, branch="main"):
    script =f"""#!/bin/bash -l
#SBATCH --job-name="ci_job"
#SBATCH --output=job.out
#SBATCH --error=job.err
#SBATCH --time=0:10:0
#SBATCH --nodes={num_nodes}
"""

    if constraint:
        script += f"#SBATCH --constraint={constraint}\n"

    if account:
        script += f"#SBATCH --account={account}\n"

    script += f"""

git clone -b {branch} {repo} firecrest-ci
cd firecrest-ci/use-case-CI-pipeline
"""

    if custom_modules:
        script += f"module load {' '.join(custom_modules)}\n"

    script += """
python -m venv testing-venv
. ./testing-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

python --version

srun python -m timeit --setup='import dist; import numpy as np; \
    p = np.arange(1000); q = np.arange(1000) + 2' \
    'dist.simple_numpy_dist(p, q)'
"""

    return script


def check_output(file_content):
    assert "loops, best of" in file_content
