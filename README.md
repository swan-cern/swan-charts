# SWAN@CERN on k8s

### How is it built

Helm Chart to deploy SWAN (from upstream https://zero-to-jupyterhub.readthedocs.io/en/latest/)  
CERN jupyterhub image (from https://gitlab.cern.ch/swan/jupyterhub/tree/sciencebox)  
User session image developed by CERN IT (https://gitlab.cern.ch/swan/docker-images/systemuser)  
  
Integrations  

- SSO (OAuth) 
- Authentication Tokens for CERNBox, Hadoop and Spark k8s and refresh mechanism  
- Podspec customization to run Spark with IT Hadoop clusters and user home being CERNBox and software  
- Extensions  
	All can be reused from current SWAN production  
  
This repository serves as equivalent of `https://gitlab.cern.ch/ai/it-puppet-hostgroup-swan` in magnum k8s

- provides configuration bound to CERN infrastructure (puppet equivalent)
- general purpose jupyter and jupyterhub images
- jupyterhub_config ConfigMap for customization of deployments (clusters at CERN configuration, ports configuration, env variables configuration, storage configuration, authentication configuration)

#### SWAN Deployment including dependencies

<b>[1] Create cluster with `CSI 0.3.0`, ingress `traefik` and `kubernetes-1.13.10-1`. </b>

```bash
$ openstack coe cluster create \
  --cluster-template kubernetes-1.13.10-1 \
  --master-flavor m2.medium \
  --node-count 2 \
  --flavor m2.large \
  --keypair k8s-spark \
  swan-k8s
```

<b>[2] Create DNS alias, label nodes to run ingress and obtain ssl certificates. </b>

Add specific nodes to `swan-k8s.cern.ch` alias and label ingress nodes, retrieve certificates and OAuth client token

Create DNS alias for openstack servers running kubernetes nodes
```bash
$ i=0;for node in $(kubectl get nodes --no-headers | grep -v master | awk '{print $1}'); do openstack server set --property landb-alias=swan-k8s--load-$i- $node; i=$(($i + 1)); done
```

Create ingress labels for kubernetes nodes
```bash
$ for node in $(kubectl get nodes --no-headers | grep -v master | awk '{print $1}'); do kubectl label node $node role=ingress; done
```

Obtain SSL
Request from - https://ca.cern.ch/ca/host/Request.aspx?template=ee2host (automatic certificate generation) and unpack
```bash
#Extract the certificate:
openssl pkcs12 -in swan-k8s-7w5vw3dlewud-minion-0.p12 -clcerts -nokeys -out hostcert.pem

#Extract the encrypted private key. To avoid protecting the key with a passphrase, specify the -nodes option:
openssl pkcs12 -in swan-k8s-7w5vw3dlewud-minion-0.p12 -nocerts -nodes -out hostkey.pem
```

Register for OAuth - https://sso-management.web.cern.ch/OAuth/RegisterOAuthClient.aspx

```bash
client_id: swan-k8s.cern.ch
redirect_uri: https://swan-k8s.cern.ch/hub/oauth_callback
```

<b>[3] Initialize helm</b>

https://clouddocs.web.cern.ch/containers/tutorials/helm.html

More in 
https://clouddocs.web.cern.ch/clouddocs/containers/quickstart.html#kubernetes

<b>[4] SWAN Helm Deployment</b>

Dependencies:
- EOS Fuse Chart [based on cern/eosxd]()
- CVMFS Chart [currently running in openstack magnum as label, should be based on IT provided chart]()
- Fluentd Chart [FIXME: currently copied from openstack magnum, should be based on cern/fluentd]()
- SWAN JupyterHub Chart [based on jupyterhub/jupyterhub]()

Install Prod SWAN (`https://swan-k8s.cern.ch` and login with cern oauth)

```bash
$ /srv/swan-k8s/source/deploy_k8s.sh <qa|prod>
```

Install Developer SWAN (`http://masterip:30080` and login with your krb5cc user)

```bash
# make sure eosxd and cvmfs are configured
$ helm upgrade --install --namespace kube-system  \
eosxd ./swan-eosxd-config-chart
 
# authenticate to create  (you can also provide generated k8s and hadoop base64 tokens if needed)
$ kinit -c krb5cc
 
# install swan (linux example)
$ helm upgrade --install --namespace swandev01  \
--values swan-upstream-chart/swan.dev.values.yaml \
--set jupyterhub.hub.annotations.version="release-$(date +%s)" \
--set jupyterhub.auth.dummy.password=test \
--set swan.secrets.eos.cred="$(base64 -w0 krb5cc)" \
--set swan.secrets.hadoop.cred="$(base64 -w0 /spark/hadoop.toks)" \
--set swan.secrets.sparkk8s.cred="$(base64 -w0 /spark/k8s-user.config)" \
swandev01 ./swan-upstream-chart
```

### Demo of upstream JupyterHub (no SWAN, no EOS, no CVMFS)
This option uses upstream [JupyterHub Helm Chart](https://jupyterhub.github.io/helm-chart/)

[JupyterHub Helm Chart](jupyterhub-upstream-chart/README.md)