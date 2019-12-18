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

id -u "$USER" > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
    log_info "Skip generating token eos/krb5cc, user ${USER} never logged in"
    exit 0
fi


# Get new eos token for the user
KRB5CC_BASE64=$(bash /srv/jupyterhub/private/eos_token.sh $USER)
if [ $? -ne 0 ]; then
    log_error "Failed to generate token eos/krb5cc for ${USER}"
    exit 1
fi

# Create new secret with renewed token
STATUS_REPLACE=$(curl -ik \
    -o /dev/null \
    --silent \
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

case "${STATUS_REPLACE}" in
    200)
        log_info "Refreshing a secret ${USER_TOKENS_SECRET_NAMESPACE}/${SECRET_NAME}/${USER_TOKENS_SECRET_KEY} with token eos/krb5cc, returned status: ${STATUS_REPLACE}"
        exit 0
    ;;
    *)
        log_error "Failed refreshing a secret ${USER_TOKENS_SECRET_NAMESPACE}/${SECRET_NAME}/${USER_TOKENS_SECRET_KEY} with token eos/krb5cc, returned status: ${STATUS_REPLACE}"
        exit 1
    ;;
esac


