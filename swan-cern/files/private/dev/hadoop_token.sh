#!/bin/bash

TOKEN_FILE_PATH=${1}
USER=${2}
CLUSTER=${3}

if [[ ! -f "/hadoop-token-generator/hadoop.cred" ]]; then
    exit 1;
fi

# in dev, one can provide already generated token instead of the proxy user keytab
cat /srv/jupyterhub/private/hadoop.cred > "${TOKEN_FILE_PATH}"