FROM centos:7

# install epel repo for python-pip package
RUN yum install -y epel-release
# update yum
RUN yum -y update

# RUN yum -y install bzip2-devel gcc libffi-devel make openssl-devel wget

# download and install python3
# RUN wget https://www.python.org/ftp/python/3.7.4/Python-3.7.4.tgz; tar xzf Python-3.7.4.tgz; cd Python-3.7.4; ./configure --enable-optimizations;  make altinstall; cd ..; rm -rf Python-3.7.4

# install python-pip from repo
# this install also python 3.6
RUN yum install -y python3-pip
# RUN yum remove -y cyrus-sasl-gssapi python-gssapi

# upgrade
RUN pip3 install --upgrade pip

RUN pip3 install Flask paramiko cryptography pyjwt requests

ADD src/status/status.py status.py
ADD src/common/cscs_api_common.py cscs_api_common.py

ENTRYPOINT ["python3"]
CMD ["status.py"]

