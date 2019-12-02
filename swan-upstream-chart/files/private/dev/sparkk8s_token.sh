#!/bin/bash

# Function variables
# 1) username
CLUSTER=$1
USER=$2

KUBECONFIG="/srv/jupyterhub/private/sparkk8s.cred"

if [[ ! -f "/srv/jupyterhub/private/sparkk8s.cred" ]]; then
    exit 1;
fi

cat "/srv/jupyterhub/private/sparkk8s.cred" | base64 -w 0