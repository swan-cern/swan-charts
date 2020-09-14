#!/bin/bash
# Located at [/srv/jupyterhub/private/hadoop-token.sh]

CLUSTER=$1
USER=$2

if [[ ! -f "/srv/jupyterhub/private/hadoop.cred" ]]; then
    exit 1;
fi

USER_GROUP="$USER":def-cg

# Generate HDFS, YARN, HIVE tokens
export KRB5CCNAME=$(mktemp /tmp/hswan.XXXXXXXXX)
LCG_VIEW=/cvmfs/sft.cern.ch/lcg/views/LCG_94/x86_64-slc6-gcc62-opt
export OVERRIDE_HADOOP_MAPRED_HOME=$LCG_VIEW
source $LCG_VIEW/setup.sh
source /cvmfs/sft.cern.ch/lcg/etc/hadoop-confext/hadoop-swan-setconf.sh $CLUSTER
kinit -V -kt /srv/jupyterhub/private/hadoop.cred hswan@CERN.CH -c $KRB5CCNAME >/dev/null 2>&1
/usr/hdp/hadoop-fetchdt-0.2.0/hadoop-fetchdt -required hdfs,yarn -optional hive -proxyuser $USER -tokenfile /tmp/hadoop_$USER >/dev/null 2>&1
echo $(cat /tmp/hadoop_$USER | base64 -w 0)

kdestroy -c $KRB5CCNAME
