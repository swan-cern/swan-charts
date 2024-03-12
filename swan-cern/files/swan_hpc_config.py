from kubernetes_asyncio.client.models import (
    V1Volume,
    V1VolumeMount,
    V1PersistentVolumeClaimVolumeSource
)


class SwanHPCPodHookHandler(SwanComputingPodHookHandler):

    async def get_swan_user_pod(self):
        await super().get_swan_user_pod()

        if self._hpc_enabled():
            self._init_hpc_volumes()

        return self.pod

    def _init_hpc_volumes(self):
        """
        Mount the CEPHFS share of HPC in the user container
        """
        for i, volume in enumerate(get_config('custom.hpc.cephVolumes', [])):
            self.pod.spec.volumes.append(
                V1Volume(
                    name=f'hpc-volume-{i}',
                    persistent_volume_claim=V1PersistentVolumeClaimVolumeSource(
                        claim_name=f'hpc-volume-{i}-pvc'
                    )
                )
            )

            notebook_container = self._get_pod_container('notebook')
            mount_path = volume['mountPath'] if 'mountPath' in volume else f'/hpc-{i}'
            notebook_container.volume_mounts.append(
                V1VolumeMount(
                    name=f'hpc-volume-{i}',
                    mount_path=mount_path
                )
            )

    def _hpc_enabled(self):
        """
        Check if the HPC cluster access should be enabled for this user.
        This is True is they belong to a special egroup and the deployment
        is active
        """

        user_roles = self.spawner.user_roles
        hpc_enabled = get_config('custom.hpc.enabled', False)
        hpc_role = get_config('custom.hpc.role', None)

        # TODO make this a form option?
        if hpc_enabled and hpc_role in user_roles:
            return True

        return False


def spark_modify_pod_hook(spawner, pod):
    """
    :param spawner: Swan Kubernetes Spawner
    :type spawner: swanspawner.SwanKubeSpawner
    :param pod: default pod definition set by jupyterhub
    :type pod: V1Pod

    :returns: dynamically customized pod specification for user session
    :rtype: V1Pod
    """
    spark_pod_hook_handler = SwanHPCPodHookHandler(spawner, pod)
    return spark_pod_hook_handler.get_swan_user_pod()


c.SwanKubeSpawner.modify_pod_hook = spark_modify_pod_hook
