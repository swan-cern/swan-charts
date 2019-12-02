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
- general purpose jupyter and jupyterhub images
- jupyterhub_config ConfigMap for customization of deployments (clusters at CERN configuration, ports configuration, env variables configuration, storage configuration, authentication configuration)

### Demo of upstream JupyterHub (no SWAN, no EOS, no CVMFS)
This option uses upstream [JupyterHub Helm Chart](https://jupyterhub.github.io/helm-chart/)

[JupyterHub Helm Chart](jupyterhub-upstream-chart/README.md)

### SWAN Deployment including dependencies

<b>[1] Create cluster with `CSI 1.0`, ingress `traefik` and `kubernetes-1.14.6-2`. </b>

```bash
$ openstack coe cluster create \
  --cluster-template kubernetes-1.14.6-2 \
  --labels cvmfs_csi_enabled=false \
  --labels cephfs_csi_enabled=false \
  --labels kube_csi_enabled=true \
  --labels kube_csi_version=cern-csi-1.0-2 \
  --labels influx_grafana_dashboard_enabled=false \
  --labels manila_enabled=true \
  --labels kube_tag=v1.14.6 \
  --labels container_infra_prefix=gitlab-registry.cern.ch/cloud/atomic-system-containers/ \
  --labels cgroup_driver=cgroupfs \
  --labels flannel_backend=vxlan \
  --labels admission_control_list=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota,Priority \
  --labels ingress_controller=traefik \
  --labels manila_version=v0.3.0 \
  --labels heat_container_agent_tag=stein-dev-1 \
  --master-flavor m2.medium \
  --node-count 2 \
  --flavor m2.large \
  --keypair pmrowczy-mac \
  swan-k8s-dev
```

Add specific nodes to `swan-k8s.cern.ch` alias and label ingress nodes, retrieve certificates and OAuth client token

```bash
$ place to add commands
```

Initialize helm

https://clouddocs.web.cern.ch/containers/tutorials/helm.html

More in 
https://clouddocs.web.cern.ch/clouddocs/containers/quickstart.html#kubernetes

<b>[2] SWAN Helm Deployment</b>

Dependencies:
- EOS Fuse Chart [based on cern/eosxd]()
- CVMFS CSI Chart [currently from openstack magnum]()
- Fluentd Chart [currently from openstack magnum]()
- SWAN JupyterHub Chart [based on jupyterhub/jupyterhub]()

Install Prod SWAN (`https://swan-k8s.cern.ch` and login with cern oauth)

```bash
$ /srv/swan-k8s/source/deploy_k8s.sh <qa|prod>
```

Install Developer SWAN (`http://masterip:30080` and login with your krb5cc user)

```bash
$ export KUBECONFIG=<path>
$ kinit -c krb5cc
$ helm upgrade --install --namespace swandev01  \
--values swan-upstream-chart/swan.dev.values.yaml \
--set jupyterhub.hub.annotations.version="release-$(date +%s)" \
--set jupyterhub.auth.dummy.password=test \
--set swan.secrets.hadoop.cred="$(base64 -b0 krb5cc)" \
--set swan.secrets.eos.cred="$(base64 -b0 krb5cc)" \
--set swan.secrets.sparkk8s.cred="$(base64 -b0 krb5cc)" \
swandev01 swan-upstream-chart
```