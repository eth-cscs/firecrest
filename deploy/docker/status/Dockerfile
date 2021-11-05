##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
ARG BASE_IMAGE=f7t-base
from $BASE_IMAGE

ADD deploy/docker/status/requirements.txt deps/requirements.txt
RUN pip3 install -r deps/requirements.txt

ADD src/status/status.py status.py
ADD src/common/cscs_api_common.py cscs_api_common.py

ENTRYPOINT ["python3"]
CMD ["status.py"]