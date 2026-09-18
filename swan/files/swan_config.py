from kubernetes_asyncio.client.models import (
    V1EmptyDirVolumeSource,
    V1PersistentVolumeClaimVolumeSource,
    V1Volume,
    V1VolumeMount,
)
from swanspawner.podhookhandler.swanpodhookhandler import SwanPodHookHandler


# https://jupyterhub-kubespawner.readthedocs.io/en/latest/spawner.html
# This is defined in the configuration to allow overring independently
# of which config file is loaded first
# c.SwanKubeSpawner.modify_pod_hook = swan_pod_hook
def swan_pod_hook(spawner, pod):
    """
    :param spawner: Swan Kubernetes Spawner
    :type spawner: swanspawner.swankubespawner.SwanKubeSpawner
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

eos_enabled = get_config("custom.eos.enabled", False)

# Propagate EOS availability to user pods
c.SwanKubeSpawner.environment.update({'EOS_ENABLED': str(eos_enabled).lower()})

# Manage EOS access
if eos_enabled:
    c.SwanKubeSpawner.eos_enabled = True
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
    # No access to EOS provided, congfigure HOME to point to /home/<user> instead of EOS HOME.
    c.SwanKubeSpawner.local_home = True
    c.SpawnHandlersConfigs.local_home = True

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
