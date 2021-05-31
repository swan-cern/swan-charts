#!/bin/bash

# Function variables
# 1) username for which to check ticket
USER=$1

TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
EOS_TOKENS_SECRET_NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
EOS_TOKENS_SECRET_NAME="eos-tokens-${USER}"

# Get new eos token for the user
KRB5CC_BASE64=$(bash /srv/jupyterhub/private/eos_token.sh $USER)
if [ $? -ne 0 ]; then
    echo "Failed to retrieve token ${EOS_TOKENS_SECRET_NAME} for ${USER}"
    exit 1
fi

# Create new secret with renewed token
STATUS_REPLACE=$(curl -ik \
    -s \
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
        "name": "'"$EOS_TOKENS_SECRET_NAME"'"
    },
    "data": {
        "krb5cc": "'"$KRB5CC_BASE64"'"
    }
    }' \
    https://kubernetes.default.svc/api/v1/namespaces/${EOS_TOKENS_SECRET_NAMESPACE}/secrets/${EOS_TOKENS_SECRET_NAME})

echo "Replacing a secret ${EOS_TOKENS_SECRET_NAMESPACE}/${EOS_TOKENS_SECRET_NAME} with token ${EOS_TOKENS_SECRET_NAMESPACE} status-create: ${STATUS_REPLACE}"

case "${STATUS_REPLACE}" in
    200)
        exit 0
    ;;
    *)
        exit 1
    ;;
esac


