#!/bin/bash

# Function variables
# 1) username for which to check ticket
USER=$1

if [[ ! -f "/srv/jupyterhub/private/eos.cred" ]]; then
    exit 1;
fi

id -u "$USER" > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
    exit 1;
fi

# in dev, one can provide already generated token
echo $(cat /srv/jupyterhub/private/eos.cred | base64 -w 0)
