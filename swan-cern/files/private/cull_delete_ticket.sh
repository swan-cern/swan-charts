#!/bin/bash

# Function variables
# 1) username for which to check ticket
USER=$1

TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
EOS_TOKENS_SECRET_NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
EOS_TOKENS_SECRET_NAME="eos-tokens-${USER}"

# Delete user secret
STATUS_DELETE=$(curl -ik \
    -o /dev/null \
    -w "%{http_code}" \
    -X DELETE \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d '{}' \
    https://kubernetes.default.svc/api/v1/namespaces/${EOS_TOKENS_SECRET_NAMESPACE}/secrets/${EOS_TOKENS_SECRET_NAME})
echo "Delete a previous secret ${EOS_TOKENS_SECRET_NAMESPACE}/${EOS_TOKENS_SECRET_NAME} status: ${STATUS_DELETE}"

case "$STATUS_DELETE" in
    200)
        exit 0
    ;;
    *)
        exit 1
    ;;
esac