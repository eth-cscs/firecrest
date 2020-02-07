from centos:7

# install epel repo for python-pip package
RUN yum install -y epel-release
# update yum
RUN yum -y update

# install python-pip from repo
RUN yum install -y python3-pip

# upgrade
RUN pip3 install --upgrade pip

# ##### RUN yum install -y gcc git net-tools openssh-clients python-devel wget

# RUN wget https://bootstrap.pypa.io/get-pip.py && python get-pip.py

RUN pip3 install Flask paramiko lxml cryptography pyjwt keystoneauth1 python-keystoneclient



ADD src/storage/storage.py storage.py
ADD src/storage/keystone.py keystone.py
ADD src/storage/objectstorage.py objectstorage.py
ADD src/storage/s3OS.py s3OS.py
ADD src/storage/swiftOS.py swiftOS.py

ADD src/common/async_task.py async_task.py
ADD src/common/job_time.py job_time.py
ADD src/common/cscs_api_common.py cscs_api_common.py


#ADD common/keys/user-key user-key
#ADD common/keys/user-key.pub user-key.pub

#RUN chmod 400 user-key*

ENTRYPOINT ["python3"]
CMD ["storage.py"]
