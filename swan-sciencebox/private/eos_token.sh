#!/bin/bash

# Function variables
# 1) username for which to check ticket
USER=$1

if [[ ! -f "/tmp/krb5cc_0" ]]; then
    exit 1;
fi

echo $(cat /tmp/krb5cc_0 | base64 -w 0)