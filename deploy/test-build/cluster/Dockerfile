##
##  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##

# partially based on https://github.com/giovtorres/slurm-docker-cluster

FROM centos:7

ARG SLURM_VERSION=19.05.4

###    && yum -y update \
RUN set -ex \
    && yum makecache fast \
    && yum -y install epel-release \
    && yum -y install \
       bzip2 \
       file \
       gcc \
       gcc-c++\
       make \
       mariadb-devel \
       mariadb-server \
       munge \
       munge-devel \
       openssh-server \
       perl \
       python-pip \
       psmisc \
       rsyslog \
       sudo \
       wget \       
    && yum clean all \
    && rm -rf /var/cache/yum > /dev/null

RUN set -x \
    && wget https://download.schedmd.com/slurm/slurm-$SLURM_VERSION.tar.bz2 \
    && tar -xvf slurm-$SLURM_VERSION.tar.bz2 > /dev/null

RUN set -x \
    && cd slurm-$SLURM_VERSION \
    && ./configure --disable-debug --prefix=/usr --sysconfdir=/etc/slurm --libdir=/usr/lib64 \
                   --disable-x11 --disable-glibtest --disable-gtktest --without-hdf5 --without-ofed  \
    && make install > /dev/null

RUN set -x \
    && rm -rf slurm \
    && groupadd -r --gid=995 slurm \
    && useradd -r -g slurm --uid=995 slurm \
    && mkdir /etc/sysconfig/slurm \
        /var/spool/slurmd \
        /var/run/slurmd \
        /var/run/slurmdbd \
        /var/lib/slurmd \
        /var/log/slurm \
    && chown -R slurm:slurm /var/lib/slurmd/ \
    && chown -R slurm:slurm /var/log/slurm   \
    && chown -R slurm:slurm /var/spool/slurm*


ADD cluster/slurm/*.conf /etc/slurm/
ADD cluster/slurm/*.sh /
RUN chmod 644 /etc/slurm/* && chmod 755 /*.sh

RUN mkdir /etc/slurm/plugstack.conf.d
RUN chmod 755 /etc/slurm/plugstack.conf.d
ADD cluster/slurm/plugstack.conf.d/cscs-slurm-nohome.conf /etc/slurm/plugstack.conf.d/

RUN mkdir /spank
ADD cluster/spank/nohome-1.*.rpm /spank/
RUN rpm -i /spank/nohome-*.rpm

RUN set -x \
    && /sbin/create-munge-key


RUN pip install supervisor
ADD cluster/supervisord.conf /etc/supervisord.conf

RUN chown -R munge:munge /var/log/munge && chmod 755 /var/log/munge && chmod 755 /run/munge


RUN chmod 755 /*.sh

RUN useradd -m -s /bin/bash test1 && useradd -m -s /bin/bash test2
RUN echo 'test1:test11' | chpasswd  && echo 'test2:test22' | chpasswd
RUN useradd -m -s /bin/bash testuser && echo 'testuser:testuser' | chpasswd
RUN useradd -m -s /bin/bash service-account-firecrest-sample && echo 'service-account-firecrest-sample:service-account-firecrest-sample' | chpasswd

ADD cluster/ssh/* /etc/ssh/
ADD environment/keys/ca-key.pub  /etc/ssh/
RUN chmod -R 400 /etc/ssh/  && chown -R root:root /etc/ssh/

RUN /usr/libexec/mariadb-prepare-db-dir 2>/dev/null

ADD cluster/ssh/ssh_command_wrapper.sh /ssh_command_wrapper.sh
RUN chmod 555 /ssh_command_wrapper.sh

## add rsyslog configuration files
ADD cluster/rsyslog/rsyslog.conf /etc/
ADD cluster/rsyslog/listen.conf /etc/rsyslog.d

## advance reservation tool files
ADD cluster/rsvsvc/usr/local/bin/* /usr/local/bin/
ADD cluster/rsvsvc/usr/local/lib/* /usr/local/lib/
ADD cluster/rsvsvc/usr/local/sbin/* /usr/local/sbin/
ADD cluster/rsvsvc/rsvmgmt_users /etc/sudoers.d/

# add sbatch scripts for testing purposes
RUN mkdir /srv/f7t
ADD cluster/test_sbatch.sh /srv/f7t/.
ADD cluster/test_sbatch.sh /srv/f7t/test_sbatch_forbidden.sh
ADD cluster/test_sbatch.sh /srv/f7t/test_sbatch_rm.sh
ADD cluster/test_sbatch.sh /srv/f7t/test_sbatch_mv.sh
RUN chmod 777 /srv/f7t
RUN chmod 555 /srv/f7t/test_sbatch.sh
RUN chmod 777 /srv/f7t/test_sbatch_rm.sh
RUN chmod 777 /srv/f7t/test_sbatch_mv.sh
RUN chmod 700 /srv/f7t/test_sbatch_forbidden.sh

ENTRYPOINT ["/usr/bin/supervisord"]

