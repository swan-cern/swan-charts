import os, subprocess

from kubernetes import client
from kubernetes.client.rest import ApiException

"""
Class handling KubeSpawner.modify_pod_hook(spawner,pod) call
"""


class SwanPodHookHandler:
    def __init__(self, spawner, pod):
        """
        :type spawner: swanspawner.SwanKubeSpawner
        :type pod: client.V1Pod
        """
        self.spawner = spawner
        self.pod = pod

    def get_swan_user_pod(self):

        # pod labels
        pod_labels = dict(
            lcg_release = self.spawner.user_options[self.spawner.lcg_rel_field].split('/')[0],
            swan_user = self.spawner.user.name
        )

        # update pod labels
        self.pod.metadata.labels.update(
            pod_labels
        )

        # get eos token
        eos_secret_name = self._init_eos_secret()

        if self._gpu_enabled():
            # currently no cern customisation required
            self.pod.spec.volumes.append(
                client.V1Volume(
                    host_path=client.V1HostPathVolumeSource(path="/opt/nvidia-driver"),
                    name='nvidia-driver'
                )
            )

            notebook_container = self._get_pod_container('notebook')

            notebook_container.volume_mounts.append(
                client.V1VolumeMount(
                name='nvidia-driver',
                mount_path='/opt/nvidia-driver'
                )
            )

            notebook_container.env = self._add_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='NVIDIA_LIB_PATH',
                    value='/opt/nvidia-driver/lib64'
                ),
            )

            notebook_container.env = self._add_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='NVIDIA_PATH',
                    value='/opt/nvidia-driver/bin'
                ),
            )

        # init pod affinity
        self.pod.spec.affinity = self._init_pod_affinity(pod_labels)

        # init user containers (notebook and side-container)
        self._init_user_containers(eos_secret_name)

        return self.pod

    def _init_eos_secret(self):
        username = self.spawner.user.name
        user_uid = self.spawner.user_uid
        eos_secret_name ='eos-tokens-%s' % username

        try:
            # Retrieve eos token for user
            eos_token_base64 = subprocess.check_output(
                ['sudo', '/srv/jupyterhub/private/eos_token.sh', username], timeout=60
            ).decode('ascii')
        except Exception as e:
            raise ValueError("Could not create required user credential")


        # ITHADOOP-819 - Ports need to be opened using service creation, and later assigning allocated service nodeport to a pod 
        # Create V1Secret with eos token
        try:
            secret_data = client.V1Secret()

            secret_meta = client.V1ObjectMeta()
            secret_meta.name = eos_secret_name
            secret_meta.namespace = swan_container_namespace
            secret_data.metadata = secret_meta
            secret_data.data = {}
            secret_data.data['krb5cc'] = eos_token_base64

            try:
                self.spawner.api.read_namespaced_secret(eos_secret_name, swan_container_namespace)
                exists = True
            except ApiException:
                exists = False

            if exists:
                self.spawner.api.replace_namespaced_secret(eos_secret_name, swan_container_namespace, secret_data)
            else:
                self.spawner.api.create_namespaced_secret(swan_container_namespace, secret_data)
        except ApiException as e:
            raise Exception("Could not create required eos secret: %s\n" % e)

        return eos_secret_name

    def _init_user_containers(self, eos_secret_name):
        """
        Define cern related secrets for spark and eos
        """
        notebook_container = self._get_pod_container('notebook')
        username = self.spawner.user.name

        pod_spec_containers = []
        side_container_volume_mounts = []

        # Shared directory between notebook and side-container for tokens with correct privileges
        self.pod.spec.volumes.append(
            client.V1Volume(
                name='shared-pod-volume',
                empty_dir=client.V1EmptyDirVolumeSource(
                    medium='Memory'
                )
            )
        )
        side_container_volume_mounts.append(
            client.V1VolumeMount(
                name='shared-pod-volume',
                mount_path='/srv/notebook'
            )
        )

        # Mount shared tokens volume that contains tokens with correct permissions
        notebook_container.volume_mounts.append(
            client.V1VolumeMount(
                name='shared-pod-volume',
                mount_path='/srv/notebook'
            )
        )

        # pod volume to mount generated eos tokens and
        # side-container volume mount with generated tokens
        self.pod.spec.volumes.append(
            client.V1Volume(
                name=eos_secret_name,
                secret=client.V1SecretVolumeSource(
                    secret_name='eos-tokens-%s' % username,
                )
            )
        )
        side_container_volume_mounts.append(
            client.V1VolumeMount(
                name=eos_secret_name,
                mount_path='/srv/side-container/eos'
            )
        )

        # define eos auth environment for the notebook container
        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            client.V1EnvVar(
                name='KRB5CCNAME',
                value='/srv/notebook/tokens/krb5cc'
            ),
        )

        # Set server hostname of the pod running jupyterhub
        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            client.V1EnvVar(
                name='SERVER_HOSTNAME',
                value_from=client.V1EnvVarSource(
                    field_ref=client.V1ObjectFieldSelector(
                        field_path='spec.nodeName'
                    )
                )
            )
        )

        # append as first (it will be first to spawn) side container which currently:
        #  - refreshes the kerberos token and adjust permissions for the user
        self.pod.spec.volumes.append(
            client.V1Volume(
                name='side-container-scripts',
                config_map=client.V1ConfigMapVolumeSource(
                    name='swan-scripts',
                    items=[
                        client.V1KeyToPath(
                            key='side_container_tokens_perm.sh',
                            path='side_container_tokens_perm.sh',
                        )
                    ],
                    default_mode=356
                ),
            )
        )
        side_container_volume_mounts.append(
            client.V1VolumeMount(
                name='side-container-scripts',
                mount_path='/srv/side-container/side_container_tokens_perm.sh',
                sub_path='side_container_tokens_perm.sh',
            )
        )

        env = self.spawner.get_env()
        pod_spec_containers.append(
            client.V1Container(
                name='side-container',
                image='cern/cc7-base:20181210',
                command=['/srv/side-container/side_container_tokens_perm.sh'],
                args=[
                    env['USER_ID'],
                    env['USER_ID'],
                    str(swan_cull_period)
                ],
                volume_mounts=side_container_volume_mounts
            )
        )

        # add the base containers after side container (to start after side container)
        existing_containers = self.pod.spec.containers
        pod_spec_containers.extend(existing_containers)

        # assigning pod spec containers
        self.pod.spec.containers = pod_spec_containers

    def _gpu_enabled(self):
        """
        Helper function to determine if gpu is allowed for given spawn
        raise exception if user has not access to the gpu
        return True if gpu is selected and user has access to gpu
        return False if gpu is not selected
        """

        user_roles = self.spawner.user_roles
        lcg_rel = self.spawner.user_options[self.spawner.lcg_rel_field]

        if "cu" in lcg_rel and "swan-gpu" not in user_roles:
            raise ValueError("Access to GPUs is not granted; please contact swan-admins@cern.ch")
        elif "cu" in lcg_rel:
            return True
        return False

    def _init_pod_affinity(self, pod_labels):
        """
        schedule pods to nodes that satisfy the specified label/affinity expressions 
        """
        try:
            del pod_labels["swan_user"]
        except KeyError:
            pass
        aff = client.V1Affinity()
        pod_affinity = client.V1PodAffinity(
            preferred_during_scheduling_ignored_during_execution=[client.V1WeightedPodAffinityTerm(
                pod_affinity_term=client.V1PodAffinityTerm(
                    label_selector=client.V1LabelSelector(
                        match_labels=pod_labels
                    ),
                    topology_key="kubernetes.io/hostname"
                ),
                weight=100
            )]
        )
        aff.pod_affinity = pod_affinity
        return aff

    def _get_pod_container(self, container_name):
        """
        :returns: required container from pod spec
        :rtype: client.V1Container
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

def modify_pod_hook(spawner, pod):
    """
    :param spawner: Swan Kubernetes Spawner
    :type spawner: swanspawner.SwanKubeSpawner
    :param pod: default pod definition set by jupyterhub
    :type pod: client.V1Pod

    :returns: dynamically customized pod specification for user session
    :rtype: client.V1Pod
    """
    pod_hook_handler = SwanPodHookHandler(spawner, pod)
    return pod_hook_handler.get_swan_user_pod()

"""
Configuration for JupyterHub
"""

# Get configuration parameters from environment variables
swan_container_namespace = os.environ.get('POD_NAMESPACE', 'default')

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

swan_cull_period = get_config('custom.cull.every', 600)

# Culling of users and ticket refresh
if get_config("custom.cull.enabled", False):
    cull_cmd = ["swanculler"]
    base_url = c.JupyterHub.get("base_url", "/")
    cull_cmd.append("--url=http://localhost:8081" + url_path_join(base_url, "hub/api"))

    cull_timeout = get_config("custom.cull.timeout")
    if cull_timeout:
        cull_cmd.append("--timeout=%s" % cull_timeout)

    cull_every = get_config("custom.cull.every")
    if cull_every:
        cull_cmd.append("--cull-every=%s" % cull_every)

    if get_config("ccustom.ull.users"):
        cull_cmd.append("--cull-users=True")

    if get_config("custom.cull.removeNamedServers"):
        cull_cmd.append("--remove-named-servers")

    cull_max_age = get_config("custom.cull.maxAge")
    if cull_max_age:
        cull_cmd.append("--max-age=%s" % cull_max_age)
    
    check_eos = get_config('custom.cull.checkEosAuth', False)
    if check_eos:
        cull_cmd.append("--disable-hooks=True")

    c.JupyterHub.services.append(
        {
            "name": "cull-idle",
            "admin": True,
            "command": cull_cmd,
        }
    )

# add EOS to notebook pods
c.SwanKubeSpawner.volume_mounts = [
    client.V1VolumeMount(
        name='eos',
        mount_path='/eos',
        mount_propagation='HostToContainer'
    ),
]

c.SwanKubeSpawner.volumes = [
    client.V1Volume(
        name='eos',
        host_path=client.V1HostPathVolumeSource(
            path='/var/eos'
        )
    ),
]

# add CVMFS to notebook pods
cvmfs_repos = get_config('custom.cvmfs.repositories', [])
for cvmfs_repo_path in cvmfs_repos:
    cvmfs_repo_id = cvmfs_repo_path.replace('.', '-')
    c.SwanKubeSpawner.volumes.append(
        client.V1Volume(
            name='cvmfs-'+cvmfs_repo_id,
            persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                claim_name='cvmfs-'+cvmfs_repo_id+'-pvc'
            )
        )
    )
    c.SwanKubeSpawner.volume_mounts.append(
        client.V1VolumeMount(
            name='cvmfs-'+cvmfs_repo_id,
            mount_path='/cvmfs/'+cvmfs_repo_path,
            read_only=True
        )
    )
