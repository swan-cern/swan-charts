#!/bin/bash

log_info() {
    echo "[INFO $(date '+%Y-%m-%d %T.%3N') $(basename $0)] $1"
}
log_error() {
    echo "[INFO $(date '+%Y-%m-%d %T.%3N') $(basename $0)] $1"
}

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
    --silent \
    -w "%{http_code}" \
    -X DELETE \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -d '{}' \
    https://kubernetes.default.svc/api/v1/namespaces/${USER_TOKENS_SECRET_NAMESPACE}/secrets/${SECRET_NAME})

case "$STATUS_DELETE" in
    200)
        log_info "Deleted a secret ${USER_TOKENS_SECRET_NAMESPACE}/${SECRET_NAME}/${USER_TOKENS_SECRET_KEY} with token eos/krb5cc, returned status: ${STATUS_DELETE}"
        exit 0
    ;;
    *)
        log_error "Failed deleting a secret ${USER_TOKENS_SECRET_NAMESPACE}/${SECRET_NAME}/${USER_TOKENS_SECRET_KEY} with token eos/krb5cc, returned status: ${STATUS_DELETE}"
        exit 1
    ;;
esac