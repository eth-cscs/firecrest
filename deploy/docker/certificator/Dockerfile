from centos:7

# install epel repo for python-pip package
RUN yum install -y epel-release
# update yum
RUN yum -y update

# install python-pip from repo
RUN yum install -y python3-pip

# upgrade
RUN pip3 install --upgrade pip

RUN yum install -y openssh

RUN pip3 install Flask cryptography pyjwt

ADD src/certificator/certificator.py certificator.py
ADD src/common/cscs_api_common.py cscs_api_common.py

ADD deploy/test-build/environment/keys/ca-key /ca-key
RUN chmod 400 /ca-key && chown root:root /ca-key

ENTRYPOINT ["python3"]
CMD ["certificator.py"]

