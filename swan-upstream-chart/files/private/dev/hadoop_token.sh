#!/bin/bash

# Function variables
# 1) username
CLUSTER=$1
USER=$2


if [[ ! -f "/srv/jupyterhub/private/hadoop.cred" ]]; then
    exit 1;
fi

cat "/srv/jupyterhub/private/hadoop.cred" | base64 -w 0