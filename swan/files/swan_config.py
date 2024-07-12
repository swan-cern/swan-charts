import logging

from kubernetes_asyncio.client.models import (
    V1EmptyDirVolumeSource,
    V1HostPathVolumeSource,
    V1PersistentVolumeClaimVolumeSource,
    V1Volume,
    V1VolumeMount,
)

"""
Class handling KubeSpawner.modify_pod_hook(spawner,pod) call
"""

class SwanPodHookHandler:
    def __init__(self, spawner, pod):
        """
        :type spawner: swanspawner.SwanKubeSpawner
        :type pod: V1Pod
        """
        self.spawner = spawner
        self.pod = pod

    def get_swan_user_pod(self):

        # pod labels
        if self.spawner.user_options[self.spawner.software_source] == self.spawner.lcg_special_type:
            pod_labels = dict(
                lcg_release = self.spawner.user_options[self.spawner.lcg_rel_field].split('/')[0]
            )
        elif self.spawner.user_options[self.spawner.software_source] == self.spawner.customenv_special_type:
            pod_labels = dict(
                lcg_release = f'customenv-{self.spawner.builder}_{self.spawner.builder_version}'
            )
        else:
            pod_labels = {}

        # update pod labels
        self.pod.metadata.labels.update(
            pod_labels
        )

        # Disable adding environment variables from Kubernetes services in the same namespace
        self.pod.spec.enable_service_links = False

        return self.pod

    def _get_pod_container(self, container_name):
        """
        :returns: required container from pod spec
        :rtype: V1Container
        """
        for container in self.pod.spec.containers:
            if container.name == container_name:
                return container

        return None

    def _add_or_replace_by_name(self, list, element):
        found = False
        for list_index in range(0, len(list)):
            if list[list_index].to_dict().get("name") == element.to_dict().get("name"):
                list[list_index] = element
                found = True
                break

        if not found:
            list.append(element)

        return list

# https://jupyterhub-kubespawner.readthedocs.io/en/latest/spawner.html
# This is defined in the configuration to allow overring iindependently 
# of which config file is loaded first
# c.SwanKubeSpawner.modify_pod_hook = swan_pod_hook
def swan_pod_hook(spawner, pod):
    """
    :param spawner: Swan Kubernetes Spawner
    :type spawner: swanspawner.SwanKubeSpawner
    :param pod: default pod definition set by jupyterhub
    :type pod: V1Pod

    :returns: dynamically customized pod specification for user session
    :rtype: V1Pod
    """
    pod_hook_handler = SwanPodHookHandler(spawner, pod)
    return pod_hook_handler.get_swan_user_pod()

"""
Configuration for JupyterHub
"""
c.SwanKubeSpawner.modify_pod_hook = swan_pod_hook


# Hub services
# FIXME port is not exposed so it cannot be accessed. Maybe we should run this separately?
# if get_config("custom.notificationsService", True):
#     c.JupyterHub.services.append(
#         {
#             'name': 'notifications',
#             'command': 'swannotificationsservice --port 8989'.split(),
#             'url': 'http://hub:8989'
#         }
#     )

# Culling of users and ticket refresh
if get_config("custom.cull.enabled", False):
    swan_idle_culler_role = {
        "name": "swan-idle-culler",
        "scopes": [
            "list:users",
            "read:users:activity",
            "read:servers",
            "delete:servers",
            # "admin:users", # dynamically added if --cull-users is passed
        ],
        # assign the role to a jupyterhub service, so it gains these permissions
        "services": ["swan-idle-culler"],
    }

    cull_cmd = ["swanculler"]
    base_url = c.JupyterHub.get("base_url", "/")
    cull_cmd.append("--url=http://localhost:8081" + url_path_join(base_url, "hub/api"))

    cull_timeout = get_config("custom.cull.timeout")
    if cull_timeout:
        cull_cmd.append("--timeout=%s" % cull_timeout)

    cull_every = get_config("custom.cull.every")
    if cull_every:
        cull_cmd.append("--cull-every=%s" % cull_every)

    if get_config("custom.cull.users"):
        cull_cmd.append("--cull-users=True")
        swan_idle_culler_role["scopes"].append("admin:users")

    if get_config("custom.cull.removeNamedServers"):
        cull_cmd.append("--remove-named-servers")

    cull_max_age = get_config("custom.cull.maxAge")
    if cull_max_age:
        cull_cmd.append("--max-age=%s" % cull_max_age)
    
    check_eos = get_config('custom.cull.checkEosAuth', False)
    if not check_eos:
        cull_cmd.append("--disable-hooks=True")
    
    hooks_dir = get_config('custom.cull.hooksDir')
    if hooks_dir:
        cull_cmd.append(f"--hooks-dir={hooks_dir}")

    c.JupyterHub.services.append(
        {
            "name": "swan-idle-culler",
            "admin": True,
            "command": cull_cmd,
            "environment": {'SWAN_DEV': os.environ.get('SWAN_DEV', 'false')}
        }
    )
    c.JupyterHub.load_roles.append(swan_idle_culler_role)


# Init lists for volumes and volume_mounts
c.SwanKubeSpawner.volumes = []
c.SwanKubeSpawner.volume_mounts = []

# add /dev/shm (for pyTorch and others)
c.SwanKubeSpawner.volumes.append(
    V1Volume(
        name='devshm',
       empty_dir=V1EmptyDirVolumeSource(
            medium='Memory'
        )
    )
)
c.SwanKubeSpawner.volume_mounts.append(
    V1VolumeMount(
        name='devshm',
        mount_path='/dev/shm',
    )
)

# Manage EOS access
if get_config("custom.eos.enabled", False):
    c.SwanKubeSpawner.volumes.append(
        V1Volume(
            name='eos',
            persistent_volume_claim=V1PersistentVolumeClaimVolumeSource(
                claim_name='eos'
            )
        )
    )
    c.SwanKubeSpawner.volume_mounts.append(
        V1VolumeMount(
            name='eos',
            mount_path='/eos',
            mount_propagation='HostToContainer'
        )
    )
else:
    # No access to EOS provided
    logging.warn("EOS access not provided. Make sure you use a scratch space as home directory (local_home: true)")
    pass

# Manage CVMFS access
c.SwanKubeSpawner.volumes.append(
    V1Volume(
        name='cvmfs',
        persistent_volume_claim=V1PersistentVolumeClaimVolumeSource(
            claim_name='cvmfs'
        )
    )
)
c.SwanKubeSpawner.volume_mounts.append(
    V1VolumeMount(
        name='cvmfs',
        mount_path='/cvmfs',
        mount_propagation='HostToContainer'
    )
)

# Required for swan systemuser.sh
c.SwanKubeSpawner.cmd = None
