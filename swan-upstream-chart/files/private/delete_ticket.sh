#!/bin/bash

# Function variables
# 1) username for which to check ticket
USER=$1

USER_TOKENS_SECRET_NAMESPACE="swan"
USER_TOKENS_SECRET_PREFIX='user-tokens-'
USER_TOKENS_SECRET_KEY='eosToken'
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
SECRET_NAME="${USER_TOKENS_SECRET_PREFIX}${USER}"

# Delete user secret
STATUS_DELETE=$(curl -ik \
    -o /dev/null \
    -w "%{http_code}" \
    -X DELETE \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d '{}' \
    https://kubernetes.default.svc/api/v1/namespaces/${USER_TOKENS_SECRET_NAMESPACE}/secrets/${SECRET_NAME})
echo "Delete a previous secret ${USER_TOKENS_SECRET_NAMESPACE}/${SECRET_NAME} status: ${STATUS_DELETE}"

case "$STATUS_DELETE" in
    200)
        exit 0
    ;;
    *)
        exit 1
    ;;
esac