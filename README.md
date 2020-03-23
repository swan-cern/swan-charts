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

<b>[1] Create cluster with Openstack magnum </b>

```bash
# Create cluster
$ export OS_PROJECT_NAME="SWAN"
$ openstack coe cluster create \
  --cluster-template kubernetes-1.15.3-3 \
  --master-flavor m2.xlarge \
  --node-count 4 \
  --flavor m2.xlarge \
  --keypair swan \
  --labels influx_grafana_dashboard_enabled="true" \
  --labels kube_csi_enabled="true" \
  --labels kube_csi_version="cern-csi-1.0-2" \
  --labels cloud_provider_tag="v1.15.0" \
  --labels container_infra_prefix="gitlab-registry.cern.ch/cloud/atomic-system-containers/" \
  --labels manila_enabled="true" \
  --labels heat_container_agent_tag="stein-dev-2" \
  --labels cgroup_driver="cgroupfs" \
  --labels cephfs_csi_enabled="true" \
  --labels cvmfs_csi_version="v1.0.0" \
  --labels admission_control_list="NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota,Priority" \
  --labels kube_tag="v1.15.3" \
  --labels flannel_backend="vxlan" \
  --labels manila_version="v0.3.0" \
  --labels cvmfs_csi_enabled="true" \
  --labels ingress_controller="traefik" \
  --labels autoscaler_tag="v1.15.2" \
  --labels cephfs_csi_version="cern-csi-1.0-2" \
  --labels tiller_enabled="true" \
  --labels monitoring_enabled="true" \
  swan
# Add cluster
$ openstack coe nodegroup create --node-count 1 --flavor g106.xlarge swan gpu
# Obtain Configuration
openstack coe cluster config swan > env.sh
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
openssl pkcs12 -in swan-jlhuibic74vm-node-0.p12 -clcerts -nokeys -out hostcert.pem

#Extract the encrypted private key. To avoid protecting the key with a passphrase, specify the -nodes option:
openssl pkcs12 -in swan-jlhuibic74vm-node-0.p12 -nocerts -nodes -out hostkey.pem
```

Register application with KeyCloak - https://application-portal.web.cern.ch - and get its secret

```bash
client_id: swan-k8s
redirect_uri: https://swan-k8s.cern.ch/hub/oauth_callback
```

<b>[3] Initialize helm</b>

https://clouddocs.web.cern.ch/containers/tutorials/helm.html

More in 
https://clouddocs.web.cern.ch/clouddocs/containers/quickstart.html#kubernetes

<b>[4] Enable GPUs in Kubernetes cluster</b>

This is a manual process until Cloud Team boots the GPU machine with required prerequisites (NVIDIA drivers, nvidia-docker etc)

```bash
# install lshw
rpm-ostree install lshw
# ensure the node has a GPU
lshw -C display
# download the driver from NVidia appropriate for the model in our case Tesla V100 PCIe 32GB
curl http://us.download.nvidia.com/tesla/440.33.01/NVIDIA-Linux-x86_64-440.33.01.run -o NVIDIA-Linux-x86_64-440.33.01.run
# install the driver (ref https://www.if-not-true-then-false.com/2015/fedora-nvidia-guide/)
# upgrade kernel
rpm-ostree upgrade
# install dependencies
rpm-ostree install kernel-devel kernel-headers gcc make dkms acpid libglvnd-glx libglvnd-opengl libglvnd-devel pkgconfig
# Add repos.
rpm-ostree install https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.repo | tee /etc/yum.repos.d/nvidia-docker.repo
# install NVIDIA GPU stuff
rpm-ostree install akmod-nvidia xorg-x11-drv-nvidia-cuda nvidia-docker2
# fixes for GPU to work
rpm-ostree kargs --append=systemd.legacy_systemd_cgroup_controller=yes
rpm-ostree kargs --append=rd.driver.blacklist=nouveau
rmmod nouveau
# deployment to enable GPUs
kubectl create -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/1.0.0-beta4/nvidia-device-plugin.yml
```

<b>[5] SWAN Helm Deployment</b>

Install Prod SWAN (`https://swan-k8s.cern.ch` and login with cern oauth)

This will install the following dependencies:
- EOS Fuse Chart [based on cern/eosxd](https://gitlab.cern.ch/helm/charts/cern/eosxd)
- CVMFS Fuse Chart [based on boxed/cvmfs](https://gitlab.cern.ch/cernbox/boxed/tree/master/cvmfs.d)
- Fluentd Chart [based on cern/fluentd](https://gitlab.cern.ch/helm/charts/cern/fluentd)
- SWAN JupyterHub Chart [based on jupyterhub/jupyterhub](https://github.com/jupyterhub/helm-chart)

```bash
# prerequisies - copy ssl certificates (hostkey.pem, hostcert.pem) and kubeconfig to swan-spare003:/srv/swan-k8s/private
$ ssh swan-spare003.cern.ch
$ /srv/swan-k8s/source/utils/deploy_k8s.sh --env <qa|prod>
```

### Utilities and development

Authenticate to given environment to execute `helm`/`kubectl` commands

```bash
source ./utils/auth_k8s.sh --env prod
```

Install Developer SWAN (`http://masterip:30080` and login with your krb5cc user)

```bash
# make sure eosxd and cvmfs are configured
$ helm upgrade --install --namespace kube-system  \
eosxd ./swan-eosxd-config-chart
$ helm upgrade --install --namespace kube-system  \
cvmfsd ./swan-cvmfsd-config-chart
 
# authenticate to provide eos token (you can also provide generated k8s and hadoop base64 tokens if needed)
$ kinit -c krb5cc
 
# install swan (linux example)
$ helm upgrade --install --namespace swan  \
--values swan-upstream-chart/swan.dev.values.yaml \
--set jupyterhub.hub.annotations.version="release-$(date +%s)" \
--set jupyterhub.auth.custom.config.client_id="redacted" \
--set jupyterhub.auth.custom.config.client_secret="redacted" \
--set jupyterhub.hub.extraEnv.OAUTH_CALLBACK_URL="http://<url>:30080/hub/oauth_callback" \
--set swan.secrets.eos.cred="$(base64 -w0 krb5cc)" \
--set swan.secrets.hadoop.cred="$(base64 -w0 hadoop.toks)" \
--set swan.secrets.sparkk8s.cred="$(base64 -w0 k8s-user.config)" \
swan ./swan-upstream-chart
```

### Demo of upstream JupyterHub (no SWAN, no EOS, no CVMFS)
This option uses upstream [JupyterHub Helm Chart](https://jupyterhub.github.io/helm-chart/)

[JupyterHub Helm Chart](jupyterhub-upstream-chart/README.md)
