#!/bin/bash
# Located at [/hadoop-token-generator/hadoop-token.sh]

TOKEN_FILE_PATH=${1}
USER=${2}
CLUSTER=${3}

if [[ ! -f "/hadoop-token-generator/hadoop.cred" ]]; then
    echo "keytab file not found" >&2
    exit 1;
fi

USER_GROUP="${USER}:def-cg"

# Generate HDFS, YARN, HIVE tokens
export KRB5CCNAME=$(mktemp /tmp/hswan.XXXXXXXXX)
LCG_VIEW=/cvmfs/sft.cern.ch/lcg/views/LCG_94/x86_64-slc6-gcc62-opt
export OVERRIDE_HADOOP_MAPRED_HOME="${LCG_VIEW}"

source "${LCG_VIEW}/setup.sh"
# HADOOP_CONF_HOME set from chart template
source "${HADOOP_CONF_HOME}/hadoop-swan-setconf.sh" "${CLUSTER}"

kinit -V -kt /hadoop-token-generator/hadoop.cred hswan@CERN.CH -c "${KRB5CCNAME}"

/usr/hdp/hadoop-fetchdt-0.2.0/hadoop-fetchdt -required hdfs,yarn -proxyuser "${USER}" -tokenfile "${TOKEN_FILE_PATH}"

kdestroy -c "${KRB5CCNAME}"
