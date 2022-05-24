#!/bin/bash
echo -n "Removing logs and temp files... "
rm -fr logs/client/*.log
rm -fr logs/cluster/*.log
rm -fr logs/firecrest/*.log
rm -fr logs/keycloak/*.log
rm -fr minio/.minio.sys
rm -fr taskpersistence-data/dump.rdb taskpersistence-data/redis.log
echo "done."
