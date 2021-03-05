##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
from f7t-base

ADD deploy/docker/utilities/requirements.txt deps/requirements.txt
RUN pip3 install -r deps/requirements.txt

ADD src/utilities/utilities.py utilities.py
ADD src/common/cscs_api_common.py cscs_api_common.py

ENTRYPOINT ["python3"]
CMD ["utilities.py"]