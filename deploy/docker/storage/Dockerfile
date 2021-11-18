##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##
ARG BASE_IMAGE=f7t-base
from $BASE_IMAGE

ADD deploy/docker/storage/requirements.txt deps/requirements.txt
RUN pip3 install -r deps/requirements.txt

ADD src/storage/storage.py storage.py
ADD src/storage/keystone.py keystone.py
ADD src/storage/keystoneoidc.py keystoneoidc.py
ADD src/storage/keystonesaml.py keystonesaml.py
ADD src/storage/objectstorage.py objectstorage.py
ADD src/storage/s3v2OS.py s3v2OS.py
ADD src/storage/s3v4OS.py s3v4OS.py
ADD src/storage/swiftOS.py swiftOS.py

ADD src/common/async_task.py async_task.py
ADD src/common/job_time.py job_time.py
ADD src/common/cscs_api_common.py cscs_api_common.py

ENTRYPOINT ["python3"]
CMD ["storage.py"]