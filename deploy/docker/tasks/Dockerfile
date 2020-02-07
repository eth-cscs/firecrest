from centos:7

# install epel repo for python-pip package
RUN yum install -y epel-release
# update yum
RUN yum -y update

# install python-pip from repo
RUN yum install -y python3-pip

# upgrade
RUN pip3 install --upgrade pip

RUN pip3 install Flask cryptography pyjwt redis requests

ADD src/tasks/tasks.py tasks.py
ADD src/common/async_task.py async_task.py
ADD src/common/cscs_api_common.py cscs_api_common.py
ADD src/common/tasks_persistence.py tasks_persistence.py

ENTRYPOINT ["python3"]
CMD ["tasks.py"]
