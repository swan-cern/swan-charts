#!/bin/bash

USER_ID=$1
USER_GID=$2
CULL_PERIOD=$3

# make sure the contents of /srv/notebook/tokens cannot be accidentally deleted
mkdir -p /srv/notebook/tokens
chown root:root /srv/notebook/tokens

copy_token_to_notebook() {
    # make sure token in target dir has always correct permissions
    token_source=$1
    token_target=$2
    token_tmp=/tmp/$RANDOM

    cp $token_source $token_tmp
    chmod 400 $token_tmp
    chown $USER_ID:$USER_GID $token_tmp
    mv $token_tmp $token_target
}

if [[ ! -f "/srv/side-container/eos/krb5cc" ]]; then
    echo "required secret /srv/notebook/tokens/krb5cc does not exist"
    exit 1
fi

if [[ -f "/srv/side-container/hadoop/webhdfs.toks" ]]; then
    echo "add hadoop.toks to user container"
    copy_token_to_notebook /srv/side-container/hadoop/webhdfs.toks /srv/notebook/tokens/webhdfs.toks
else
    echo "webhdfs.toks not required, skipping"
fi

if [[ -f "/srv/side-container/hadoop/hadoop.toks" ]]; then
    echo "add hadoop.toks to user container"
    copy_token_to_notebook /srv/side-container/hadoop/hadoop.toks /srv/notebook/tokens/hadoop.toks
else
    echo "hadoop.toks not required, skipping"
fi

if [[ -f "/srv/side-container/hadoop/k8s-user.config" ]]; then
    echo "add k8s-user.config to user container"
    copy_token_to_notebook /srv/side-container/hadoop/k8s-user.config /srv/notebook/tokens/k8s-user.config
else
    echo "k8s-user.config not required, skipping"
fi

echo "start refreshing /srv/notebook/tokens/krb5cc in user container"
copy_token_to_notebook /srv/side-container/eos/krb5cc /srv/notebook/tokens/krb5cc
klist -c /srv/notebook/tokens/krb5cc
while true; do
    sleep $CULL_PERIOD
    copy_token_to_notebook /srv/side-container/eos/krb5cc /srv/notebook/tokens/krb5cc
done