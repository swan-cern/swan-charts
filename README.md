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

List of contents
- [Prerequisites](#prerequisites)
- [Option 1: Deployment to Openstack K8s with HELM](#option-1:-deployment-to-openstack-k8s-with-jupyterhub-helm-chart)
- [Option 2: Deployment to Openstack K8s with KUBECTL / LDAP](#option-2:-deployment-to-openstack-k8s-with-sciencebox-templates)
- [Useful commands](#useful-commands)
- [Current Sciencebox issues](#sciencebox-issues)
- [Current Jupyterhub Chart issues](#current-jupyterhub-chart-issues)

### Prerequisites

Create cluster
- `openstack magnum` - https://clouddocs.web.cern.ch/clouddocs/containers/quickstart.html#kubernetes

Install in `kube-system` namespace (if not provided by openstack by default)
- `eosxd` - https://clouddocs.web.cern.ch/clouddocs/containers/tutorials/eos.html
- `cvmfs-csi` - https://clouddocs.web.cern.ch/clouddocs/containers/tutorials/cvmfs.html#cvmfs (https://gitlab.cern.ch/cloud-infrastructure/cvmfs-csi)

### Option 1: Deployment to Openstack K8s with JupyterHub Helm Chart

This option uses upstream [JupyterHub Helm Chart](https://jupyterhub.github.io/helm-chart/)

[SWAN Helm Chart](swan-upstream-chart/README.md)

### Option 2: Deployment to Openstack K8s with ScienceBox Templates

This option uses [ScienceBox Kuboxed](https://github.com/cernbox/kuboxed/blob/master/SWAN.yaml)

[ScienceBox Templates](swan-sciencebox/README.md)

### Useful commands

Entering Jupyterhub Container

```bash
kubectl exec -it -n swan $(kubectl get pods -n swan | grep hub- | awk '{print $1}') bash
```

Describe Jupyterhub Container

```bash
kubectl describe pod -n swan $(kubectl get pods -n swan | grep hub- | awk '{print $1}')
```

Get logs of Jupyterhub Container

```bash
kubectl logs -f -n swan $(kubectl get pods -n swan | grep hub- | awk '{print $1}')
```

Restarting JupyterHub Container

```bash
kubectl delete pod -n swan $(kubectl get pods -n swan | grep hub- | awk '{print $1}')
```

Checking Jupyter Proxy logs

```bash
kubectl logs -f -n swan $(kubectl get pods -n swan | grep proxy- | awk '{print $1}')
```

Entering user Notebook

```bash
kubectl exec -it -n swan jupyter-<username> -c notebook bash
```

Checking user Notebook logs

```bash
kubectl logs -n swan jupyter-<username>
```

### Current JupyterHub chart issues

Using JupyterHub chart from [upstream](https://github.com/jupyterhub/zero-to-jupyterhub-k8s/blob/master/jupyterhub/values.yaml) :
- does not allow to specify separate user namespace

### ScienceBox issues

Using JupyterHub image from [ScienceBox](https://gitlab.cern.ch/swan/docker-images/jupyterhub) :

- sciencebox proxy with supervisord instead of separate deployment (as in upstream)
- we need [hadoop-fetchdt rpm](https://gitlab.cern.ch/db/hadoop-fetchdt/tree/qa) installed
- we need [kS4U]() installed
- should we generate tokens for EOS/Spark in JupyterHub or as part of side-container in each pod ? 
