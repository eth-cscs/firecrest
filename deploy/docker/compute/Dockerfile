from centos:7

RUN yum install -y epel-release
RUN yum -y update
RUN yum install -y python3-pip

RUN pip3 install --upgrade pip

RUN pip3 install Flask paramiko cryptography pyjwt requests

ADD src/compute/compute.py compute.py
ADD src/common/async_task.py async_task.py
ADD src/common/cscs_api_common.py cscs_api_common.py
ADD src/common/job_time.py job_time.py

ENTRYPOINT ["python3"]
CMD ["compute.py"]

