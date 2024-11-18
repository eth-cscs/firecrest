FROM f7t-cluster
 
RUN yum update -y && \
    yum install -y sqlite-devel openssl-devel bzip2-devel libffi-devel wget && \
    yum groupinstall -y "Development Tools"

RUN wget https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1/openssl-1.1.1.tar.gz && \
    tar -xzvf openssl-1.1.1.tar.gz && \
    cd openssl-1.1.1 && \
    ./config --prefix=/usr/openssl1.1 --openssldir=/etc/ssl --libdir=lib no-shared zlib-dynamic && \
    make && \
    make install && \
    rm -r ../openssl-1.1.1.tar.gz ../openssl-1.1.1

RUN wget https://www.python.org/ftp/python/3.10.2/Python-3.10.2.tgz && \
    tar -xzf Python-3.10.2.tgz && \
    cd Python-3.10.2 && \
    export TCLTK_LIBS='-ltk8.5 -ltcl8.5' && \
    ./configure --enable-shared --with-openssl=/usr/openssl1.1 --with-openssl-rpath=auto --enable-optimizations && \
    make altinstall

ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

RUN python3.10 -m venv /opt/jhub-env

RUN . /opt/jhub-env/bin/activate && \
    python3.10 -m pip install --no-cache jupyterlab jupyterhub==4.1.6 pyfirecrest==2.1.0 SQLAlchemy==1.4.52 oauthenticator==16.3.1 notebook==7.2.1
 
RUN . /opt/jhub-env/bin/activate && \
    git clone https://github.com/eth-cscs/firecrestspawner.git && \
    cd firecrestspawner && \
    pip install --no-cache . && \
    cd .. && \
    rm -r firecrestspawner

RUN localedef -i en_US -f UTF-8 en_US.UTF-8
