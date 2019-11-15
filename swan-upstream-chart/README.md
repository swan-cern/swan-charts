# Option 1: Deployment to Openstack K8s with HELM

Prerequisite: build helm chart with required dependencies (`Chart.yaml`, `requirements.yaml` and `values.yaml` customized)
- [jupyterhub spawner/handler customized for SWAN on branch swan_k8s](https://gitlab.cern.ch/swan/jupyterhub/tree/swan_k8s)
- [jupyterhub docker image on branch swan_k8s](https://gitlab.cern.ch/swan/docker-images/jupyterhub/tree/swan_k8s)
- [system user image from this commit] (https://gitlab.cern.ch/swan/jupyter/commit/fc44790348c0ac9987dc204709160d4273b96fec)- 
- `helm init --history-max 5 --service-account tiller`

## K8s cluster creation, OAuth setup and Certificates

(placeholder to add k8s creation instructions)

Build chart dependency (optional) and package the chart

```
$ helm dependency build swan-upstream-chart
$ helm package swan-upstream-chart
```

## Install Prod SWAN (`https://swan-k8s.cern.ch` and login with cern oauth)

```bash
$ helm upgrade --install --namespace swan \
--set jupyterhub.hub.db.password=redacted \
--set jupyterhub.auth.custom.config.client_secret=redacted \
--set-file swan.secrets.ingress.cert=path \
--set-file swan.secrets.ingress.key=path \
--set-file swan.secrets.hadoop.script=path \
--set-file swan.secrets.webhdfs.script=path \
--set-file swan.secrets.eos.script=path \
--set swan.secrets.hadoop.cred="$(base64 -w0 path)" \
--set swan.secrets.eos.cred="$(base64 -w0 path)" \
swan swan-upstream-chart-0.0.1.tgz
```

## Install Developer SWAN (`https://swan-k8s-dev01.cern.ch` and login with cern oauth)

```bash
# Create authentication token for eos and spark
# It will be mounted to `/srv/jupyterhub/private/eos.cred` and `/srv/jupyterhub/private/hadoop.cred`
 
$ kinit <username>@CERN.CH -c krb5cc
```
```bash
# Create script that gets krb5cc and prints its contents
 
$ cat << 'EOF' > eos_token.sh
#!/bin/bash
USER=$1
if [[ ! -f "/srv/jupyterhub/private/eos.cred" ]]; then
    exit 1;
fi
id -u "$USER" > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
    exit 1;
fi
echo $(cat /srv/jupyterhub/private/eos.cred | base64 -w 0)
EOF
```
```bash
# Create script that gets krb5cc and prints its contents
 
$ cat << 'EOF' > hadoop_token.sh
#!/bin/bash
CLUSTER=$1
USER=$2
if [[ ! -f "/srv/jupyterhub/private/hadoop.cred" ]]; then
    exit 1;
fi
id -u "$USER" > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
    exit 1;
fi
echo $(cat /srv/jupyterhub/private/hadoop.cred | base64 -w 0)
EOF
```
```bash
# Install development swan authenticated as <username>
 
$ helm upgrade --install --namespace swandev01 --recreate-pods \
--set jupyterhub.hub.db.type=sqlite-memory \
--set jupyterhub.ingress.hosts={swan-k8s-dev01.cern.ch} \
--set jupyterhub.hub.extraEnv.OAUTH_CALLBACK_URL=https://swan-k8s-dev01.cern.ch/hub/oauth_callback \
--set jupyterhub.auth.custom.config.client_id=swan-k8s-dev01.cern.ch \
--set jupyterhub.auth.custom.config.client_secret=redacted \
--set jupyterhub.custom.cvmfs.prefetcher.enable=false \
--set jupyterhub.prePuller.hook.enabled=false \
--set jupyterhub.debug.enabled=true \
--set-file swan.secrets.ingress.cert=hostcert.pem \
--set-file swan.secrets.ingress.key=hostkey.pem \
--set-file swan.secrets.hadoop.script=hadoop_token.sh \
--set-file swan.secrets.eos.script=eos_token.sh \
--set swan.secrets.hadoop.cred="$(base64 -w0 krb5cc)" \
--set swan.secrets.eos.cred="$(base64 -w0 krb5cc)" \
swandev01 swan-upstream-chart-0.0.1.tgz
```
