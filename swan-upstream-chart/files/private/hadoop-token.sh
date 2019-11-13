#!/bin/bash
# Located at [/srv/jupyterhub/private/get_hdfs_tokens.sh]

CLUSTER=$1
USER=$2

if [[ ! -f "/srv/jupyterhub/private/hadoop.keytab" ]]; then
    exit 1;
fi

THEUID=`id -u "$USER"`
if [[ $? -ne 0 ]]; then
    exit 1;
fi

THEUID=`id -u "$USER"`
USER_GROUP="$USER":def-cg

rm /tmp/hadoop_$THEUID

# Generate HDFS, YARN, HIVE tokens
export KRB5CCNAME=$(mktemp /tmp/hswan.XXXXXXXXX)
LCG_VIEW=/cvmfs/sft.cern.ch/lcg/views/LCG_94/x86_64-slc6-gcc62-opt
export OVERRIDE_HADOOP_MAPRED_HOME=$LCG_VIEW
source $LCG_VIEW/setup.sh
source /cvmfs/sft.cern.ch/lcg/etc/hadoop-confext/hadoop-swan-setconf.sh $CLUSTER
kinit -V -kt /srv/jupyterhub/private/hadoop.keytab hswan@CERN.CH -c $KRB5CCNAME >/dev/null 2>&1
/usr/hdp/hadoop-fetchdt-0.1.0/hadoop-fetchdt -proxyuser $USER -tokenfile /tmp/hadoop_$THEUID >/dev/null 2>&1
echo $(cat /tmp/hadoop_$THEUID | base64 -w 0)

kdestroy -c $KRB5CCNAME
