#!/bin/bash

if [[ ! -f "/srv/jupyterhub/private/hadoop.cred" ]]; then
    exit 1;
fi

# in dev, one can provide already generated token
echo $(cat /srv/jupyterhub/private/hadoop.cred | base64 -w 0)