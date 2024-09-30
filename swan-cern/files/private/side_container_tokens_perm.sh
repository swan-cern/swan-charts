#!/bin/bash

USER_ID=$1
USER_GID=$2
CULL_PERIOD=$3

# Create a directory to store the tokens. Those intended to be read-only for the
# user are stored in tokens, those that can be overwritten by the user are stored
# in tokens/writable
mkdir -p /srv/notebook/tokens/writable
chmod 777 /srv/notebook/tokens/writable

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

echo "start refreshing EOS kerberos tickets in user container"
copy_token_to_notebook /srv/side-container/eos/krb5cc /srv/notebook/tokens/krb5cc
copy_token_to_notebook /srv/side-container/eos/krb5cc /srv/notebook/tokens/writable/krb5cc_nb_term
klist -c /srv/notebook/tokens/krb5cc
while true; do
    sleep $CULL_PERIOD

    # Check whether the kerberos ticket for the Jupyter server (krb5cc) and the one for
    # notebooks and terminals (krb5cc_nb_term) differ. If they do, it means the user ran
    # a kinit from their session and overwrote krb5cc_nb_term. In such a case, the krb5cc_nb_term
    # ticket is not refreshed: the user is now responsible for it.
    diff /srv/notebook/tokens/krb5cc /srv/notebook/tokens/writable/krb5cc_nb_term &> /dev/null
    if [ $? == 0 ]
    then
        copy_token_to_notebook /srv/side-container/eos/krb5cc /srv/notebook/tokens/writable/krb5cc_nb_term
    fi

    # The Jupyter server ticket is always refreshed. It can't be overwritten by the user
    copy_token_to_notebook /srv/side-container/eos/krb5cc /srv/notebook/tokens/krb5cc
done