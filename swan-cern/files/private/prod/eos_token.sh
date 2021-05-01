#!/bin/bash

# Function variables
# 1) username for which to check ticket
USER=$1

if [[ ! -f "/srv/jupyterhub/private/eos.cred" ]]; then
    exit 1;
fi

FILENAME="/tmp/krb5cc_$USER"

kS4U -v -u $USER -s constrdt -proxy xrootd/eosuser.cern.ch,xrootd/eospublic.cern.ch,xrootd/eoshome.cern.ch,xrootd/eosatlas.cern.ch,xrootd/eoscms.cern.ch,xrootd/eoslhcb.cern.ch,xrootd/eosproject-i00.cern.ch,xrootd/eosproject-i01.cern.ch,xrootd/eosproject-i02.cern.ch -k /srv/jupyterhub/private/eos.cred -c $FILENAME > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
    exit 1;
fi

echo $(cat $FILENAME | base64 -w 0)
rm $FILENAME
