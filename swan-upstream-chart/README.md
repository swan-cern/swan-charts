# Option 1: Deployment to Openstack K8s with HELM

Prerequisite: build helm chart with required dependencies (`Chart.yaml`, `requirements.yaml` and `values.yaml` customized)
- [jupyterhub spawner/handler customized for SWAN on branch swan_k8s](https://gitlab.cern.ch/swan/jupyterhub/tree/swan_k8s)
- [jupyterhub docker image on branch swan_k8s](https://gitlab.cern.ch/swan/docker-images/jupyterhub/tree/swan_k8s)
- `helm init --history-max 5 --service-account tiller`

Build chart dependency (optional) and package the chart

```
$ helm dependency build swan-upstream-chart
$ helm package swan-upstream-chart
```

Install Prod SWAN (`https://swan-k8s.cern.ch` and login with cern oauth)

```bash
$ helm upgrade --install --namespace swan --recreate-pods \
--set jupyterhub.hub.db.password=redacted \
--set jupyterhub.custom.config.client_secret=redacted \
--set-file jupyterhub.swan.ingress.cert=path-to-cert.pem \
--set-file jupyterhub.swan.ingress.key=path-to-key.pem \
--set jupyterhub.debug.enabled=true \
swan swan-upstream-chart-0.0.1.tgz
```

