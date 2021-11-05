##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
ARG BASE_IMAGE=f7t-base
from $BASE_IMAGE

ADD deploy/docker/tasks/requirements.txt deps/requirements.txt
RUN pip3 install -r deps/requirements.txt

ADD src/tasks/tasks.py tasks.py
ADD src/common/async_task.py async_task.py
ADD src/common/cscs_api_common.py cscs_api_common.py
ADD src/common/tasks_persistence.py tasks_persistence.py

ENTRYPOINT ["python3"]
CMD ["tasks.py"]