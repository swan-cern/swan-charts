# SWAN@CERN on k8s

### How is it built

CERN jupyterhub image (leveraged from sciencebox work)  
Helm Chart to deploy jupyterhub (yaml for development, for production we can use helm chart from upstream Zero to JupyterHub with Kubernetes)  
Image for the user session is developed by CERN IT (systemuser image from current SWAN production)  
  
Integrations  

- SSO (OAuth or Shibboleth)  
- Authentication Tokens for CERNBox, Hadoop (and OS_TOKEN for k8s clusters in future, maybe) and refresh mechanism  
- Podspec customization to run Spark with IT Hadoop clusters and user home being CERNBox and software  
- Extensions  
	All can be reused from current SWAN production  
  
This repository serves as equivalent of `https://gitlab.cern.ch/ai/it-puppet-hostgroup-swan` in magnum k8s

- provides configuration bound to CERN infrastructure (puppet equivalent)
- single purpose components
- general purpose jupyter and jupyterhub images
- jupyterhub_config ConfigMap for customization of deployments (clusters at CERN configuration, ports configuration, env variables configuration, storage configuration, authentication configuration)

### Prerequisites

Create cluster
- `openstack magnum` - https://clouddocs.web.cern.ch/clouddocs/containers/quickstart.html#kubernetes

Install in `kube-system` namespace (if not provided by openstack by default)
- `eosxd` - https://gitlab.cern.ch/helm/charts/cern/tree/master/eosxd
- `cvmfs-csi` - https://gitlab.cern.ch/cloud-infrastructure/cvmfs-csi

Build docker image:
- jupyterhub [docker image](https://gitlab.cern.ch/swan/docker-images/jupyterhub) build with jupyterhub branch [swan_k8s](https://gitlab.cern.ch/swan/jupyterhub/tree/swan_k8s)

### Deployment to Openstack K8s with LDAP

### Namespace 

Create namespace for swan
```bash
kubectl apply -f swan-namespace.yaml
```

#### LDAP configuration (testing)

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

#### SWAN configuration

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

### Useful commands

Entering Jupyterhub Container

```bash
kubectl exec -it -n swan $(kubectl get pods -n swan | grep swan- | grep Running | awk '{print $1}') bash
```

Restarting JupyterHub Container

```bash
kubectl delete pod -n swan $(kubectl get pods -n swan | grep swan- | grep Running | awk '{print $1}')
```

Editing Jupyterhub inside the container (requires jupyterhub process restart) 

```bash
# vi /srv/jupyterhub/<required-file>
# cd <some-path-if-required>; pip install .
```

Restarting Jupyterhub inside the container 

```bash
# supervisorctl stop jupyterhub; ps aux | grep http-proxy | awk '{print $2}' | head -1 | xargs -I{} kill {}; supervisorctl start jupyterhub
```

Checking logs of Jupyterhub

```bash
# less /var/log/jupyterhub/jupyterhub.log
```

Entering user Notebook

```bash
kubectl exec -it -n swan jupyter-<username> -c notebook bash
```

Checking user Notebook logs

```bash
kubectl logs -n swan jupyter-<username>
```