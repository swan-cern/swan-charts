#!/bin/bash

KUBECONFIG="/srv/jupyterhub/private/sparkk8s.cred"

if [[ ! -f "/srv/jupyterhub/private/sparkk8s.cred" ]]; then
    exit 1;
fi

# in dev, one can provide already generated token
echo $(cat /srv/jupyterhub/private/sparkk8s.cred | base64 -w 0)