# SWAN Deployment Chart

Dependencies:
- upstream JupyterHub Helm Chart `https://jupyterhub.github.io/helm-chart/`
- [jupyterhub spawner/handler customized for SWAN on branch sciencebox](https://gitlab.cern.ch/swan/jupyterhub/tree/sciencebox)
- [jupyterhub docker image on branch swan_k8s](https://gitlab.cern.ch/swan/docker-images/jupyterhub/tree/swan_k8s)
- [system user image from this commit] (https://gitlab.cern.ch/swan/jupyter/commit/fc44790348c0ac9987dc204709160d4273b96fec)- 

Build chart dependency based on `requirements.yaml`

```
$ helm dependency build swan-upstream-chart
```