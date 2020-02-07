from centos:7

# install epel repo for python-pip package
RUN yum install -y epel-release
# update yum
RUN yum -y update

# install python-pip from repo
RUN yum install -y python3-pip

# upgrade
RUN pip3 install --upgrade pip


RUN pip3 install Flask paramiko cryptography pyjwt requests

ADD src/utilities/utilities.py utilities.py
ADD src/common/cscs_api_common.py cscs_api_common.py

#ADD common/keys/user-key user-key
#ADD common/keys/user-key.pub user-key.pub
#RUN chmod 400 user-key*

ENTRYPOINT ["python3"]
CMD ["utilities.py"]

