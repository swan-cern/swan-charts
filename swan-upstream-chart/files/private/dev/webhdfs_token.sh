#!/bin/bash

# Function variables
# 1) username
CLUSTER=$1
USER=$2

if [[ ! -f "/srv/jupyterhub/private/hadoop.cred" ]]; then
    exit 1;
fi

echo "Not supported"
exit 1