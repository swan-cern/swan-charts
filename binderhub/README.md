# Demo: Deployment to Openstack K8s with HELM

Prerequisite 
- `helm init --history-max 5`

Install Upstream JupyterHub with all required settings

```bash
helm repo add jupyterhub https://jupyterhub.github.io/helm-chart/
helm repo update
# This installs binderhub in kubernetes cluster, pointing to SWAN service running on physical machines (look config.yaml)
helm upgrade --install --namespace binder --values config.yaml --version=0.2.0-n156.hec14d4a -f secret.yaml -f ssl.yaml bhub jupyterhub/binderhub
```

Access swan-binder

```bash
https://swan-binder.cern.ch
```
