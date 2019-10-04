
# Option 2: Deployment to Openstack K8s with KUBECTL / LDAP

##### Prerequisites

- [jupyterhub spawner/handler customized for SWAN on branch swan_k8s](https://gitlab.cern.ch/swan/jupyterhub/tree/swan_k8s)
- [jupyterhub docker image on branch master](https://gitlab.cern.ch/swan/docker-images/jupyterhub)

##### Namespace 

Create namespace for swan
```bash
kubectl apply -f swan-namespace.yaml
```

##### LDAP configuration (testing)

Install ldap

```bash
kubectl apply -f swan-ldap.yaml
```

Exec into pod to create demo users (real CERN user names)

```bash
kubectl exec -it ldap-pod-X -n swan bash
```

Define CERN user

```bash
USER=<your-cern-username>
```

Create that CERN user

```bash

ACTION_FILE='/tmp/action.ldif'
ldapadd_macro  () {
  ldapadd -x -H $LDAP_URI -D $LDAP_ADMIN_BIND_DN -w $LDAP_ADMIN_BIND_PASSWORD -f $ACTION_FILE
}

echo "Creating groups branch..."
cat >$ACTION_FILE <<EOM
dn: ou=groups,$LDAP_BASE_DN
ou: groups
description: Generic Groups Branch
objectclass: top
objectclass: organizationalunit
EOM
ldapadd_macro

# Create groups
echo "Creating group"
group_no=$RANDOM

cat <<EON
dn: cn=group$group_no,ou=groups,$LDAP_BASE_DN
objectClass: top
objectClass: posixGroup
gidNumber: $group_no
EON
> $ACTION_FILE
ldapadd_macro


echo "Configuring demo users on LDAP server..."
user_no=$RANDOM
cat >$ACTION_FILE << EOF
dn: uid=$USER,$LDAP_BASE_DN
objectclass: top
objectclass: account
objectclass: unixAccount
cn: $USER
uid: $USER
uidNumber: $user_no
gidNumber: $user_no
homeDirectory: /home/$USER
loginShell: /bin/bash
gecos: $USER
userPassword: {crypt}x
EOF

ldapadd_macro
ldappasswd -x -H $LDAP_URI -D $LDAP_ADMIN_BIND_DN -w $LDAP_ADMIN_BIND_PASSWORD "uid=$USER,$LDAP_BASE_DN" -s "test"

cat <<EOP
dn: cn=group$group_no,ou=groups,$LDAP_BASE_DN
changetype: modify
add: memberuid
memberuid: $USER

EOP
>$ACTION_FILE
ldapmodify -x -H $LDAP_URI -D $LDAP_ADMIN_BIND_DN -w $LDAP_ADMIN_BIND_PASSWORD -f $ACTION_FILE
```

##### SWAN configuration

Install swan configuration

```bash
kubectl create configmap swan-config --namespace swan \
--from-file=configs/jupyterhub_config.py \
--from-file=configs/jupyterhub_form.html
```

Install swan private scripts

```bash
kubectl create secret generic swan-scripts --namespace swan \
--from-file=private/eos_token.sh \
--from-file=private/check_ticket.sh \
--from-file=private/delete_ticket.sh
```

Install swan

```bash
kubectl apply -f swan-deployment.yaml
```

Go inside SWAN pod and provide user auth for `eos_token.sh`

```bash
kubectl exec -it -n swan $(kubectl get pods -n swan | grep swan- | grep Running | awk '{print $1}') bash
 
# kinit <user>@CERN.CH
```

Access swan at cluster NodePort and login as `<username>:test`

```bash
https://<any-cluster-node-ip>:30443
```