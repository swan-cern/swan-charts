from swanspawner.podhookhandler import SwanSparkCondorPodHookHandler


def computing_modify_pod_hook(spawner, pod):
    """
    :param spawner: Swan Kubernetes Spawner
    :type spawner: swanspawner.swankubespawner.SwanKubeSpawner
    :param pod: default pod definition set by jupyterhub
    :type pod: V1Pod

    :returns: dynamically customized pod specification for user session
    :rtype: V1Pod
    """
    computing_pod_hook_handler = SwanSparkCondorPodHookHandler(spawner, pod)
    return computing_pod_hook_handler.get_swan_user_pod()

c.SwanKubeSpawner.modify_pod_hook = computing_modify_pod_hook
