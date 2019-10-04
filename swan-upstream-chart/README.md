# Option 1: Deployment to Openstack K8s with HELM

Prerequisite: build helm chart with required dependencies (`Chart.yaml`, `requirements.yaml` and `values.yaml` customized)
- [jupyterhub spawner/handler customized for SWAN on branch swan_k8s](https://gitlab.cern.ch/swan/jupyterhub/tree/swan_k8s)
- [jupyterhubdocker image on branch swan_k8s](https://gitlab.cern.ch/swan/docker-images/jupyterhub/tree/swan_k8s)
- `helm init --history-max 5 --service-account tiller`
- `helm dependency build swan-upstream-chart`
- `helm package swan-upstream-chart`

Install SWAN with all required settings

```bash
helm upgrade --install --namespace swan --recreate-pods swan swan-upstream-chart-0.0.1.tgz
```

Access swan at cluster NodePort and login as `<username>:test`

```bash
http://<any-cluster-node-ip>:31080
```
