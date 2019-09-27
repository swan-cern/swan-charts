#!/bin/bash

# Function variables
# 1) username for which to check ticket
USER=$1

USER_TOKENS_SECRET_NAMESPACE="swan"
USER_TOKENS_SECRET_PREFIX='user-tokens-'
USER_TOKENS_SECRET_KEY='eosToken'
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
SECRET_NAME="${USER_TOKENS_SECRET_PREFIX}${USER}"

# Get new eos token for the user
KRB5CC_BASE64=$(bash /srv/jupyterhub/private/eos_token.sh $USER)
if [ $? -ne 0 ]; then
    echo "Failed to retrieve token ${USER_TOKENS_SECRET_KEY} for ${USER}"
    exit 1
fi

# Create new secret with renewed token
STATUS_REPLACE=$(curl -ik \
    -o /dev/null \
    -w "%{http_code}" \
    -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d '{
    "kind": "Secret",
    "apiVersion": "v1",
    "metadata": {
        "name": "'"$SECRET_NAME"'"
    },
    "data": {
        "'"$USER_TOKENS_SECRET_KEY"'": "'"$KRB5CC_BASE64"'"
    }
    }' \
    https://kubernetes.default.svc/api/v1/namespaces/${USER_TOKENS_SECRET_NAMESPACE}/secrets/${SECRET_NAME})

echo "Replacing a secret ${USER_TOKENS_SECRET_NAMESPACE}/${SECRET_NAME} with token ${USER_TOKENS_SECRET_KEY} status-create: ${STATUS_REPLACE}"

case "${STATUS_REPLACE}" in
    200)
        exit 0
    ;;
    *)
        exit 1
    ;;
esac


