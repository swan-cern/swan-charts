# Demo: Deployment to Openstack K8s with HELM

Prerequisite 
- `helm init --history-max 5`

Create settings

```bash
cat <<EOF >values.yaml
proxy:
  service:
    type: NodePort
    nodePorts:
      http: 30080
  secretToken: 9840739268135b56fc340d5c8b4b5962c489479eecfd0e1e7b6bbb108697b90a
singleuser:
  uid: 0
  fsGid: 0
  startTimeout: 90
  storage:
    type: none
  cloudMetadata:
    enabled: true
  profileList:
    - display_name: "standard (cpu)"
      description: "resources offering cpus"
      default: true
    - display_name: "swan"
      description: "this will spawn systemuser but no layout"
      kubespawner_override:
        image: gitlab-registry.cern.ch/swan/docker-images/systemuser:v5.1.1
    - display_name: "failed spawn"
      description: "this will fail to spawn"
      kubespawner_override:
        image: busybox
hub:
  uid: 0
  fsGid: 0
  db:
    type: sqlite-memory
  extraConfig:
    myConfig: |
      c.Spawner.args = ['--allow-root']
auth:
  type: dummy
  dummy:
    password: test
rbac:
  enabled: true
cull:
  enabled: true
scheduling:
  userScheduler:
    enabled: false
  podPriority:
    enabled: false
prePuller:
  hook:
    enabled: false
  continuous:
    enabled: false
EOF
```

Install Upstream JupyterHub with all required settings

```bash
helm upgrade --install --namespace jhub --values values.yaml --version=0.8.2 --recreate-pods jhub jupyterhub/jupyterhub
```

Access swan at cluster NodePort and login as `<username>:test`

```bash
http://<any-cluster-node-ip>:30080
```
