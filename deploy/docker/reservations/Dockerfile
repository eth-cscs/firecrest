from centos:7

# install epel repo for python-pip package
RUN yum install -y epel-release
# update yum
RUN yum -y update

# install python-pip from repo
RUN yum install -y python3-pip

# upgrade
RUN pip3 install --upgrade pip

ADD deploy/docker/base/requirements.txt base/requirements.txt
ADD deploy/docker/reservations/requirements.txt deps/requirements.txt
RUN pip3 install -r deps/requirements.txt

ADD src/reservations/reservations.py reservations.py
ADD src/common/cscs_api_common.py cscs_api_common.py

ENTRYPOINT ["python3"]
CMD ["reservations.py"]
