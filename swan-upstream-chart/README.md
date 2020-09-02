# SWAN Deployment Chart

Dependencies:
- upstream JupyterHub Helm Chart `https://jupyterhub.github.io/helm-chart/`
- SWAN Spawner `https://github.com/swan-cern/jupyterhub-extensions/tree/master`
- jupyterhub docker image `https://github.com/swan-cern/jupyterhub-image/tree/master/`
- system user image `https://github.com/swan-cern/systemuser-image/`

Build chart dependency based on `requirements.yaml`

```
$ helm dependency build swan-upstream-chart
```
