import os, subprocess

from kubernetes import client
from kubernetes.client.rest import ApiException

"""
Class handling KubeSpawner.modify_pod_hook(spawner,pod) call
"""


class SwanPodHookHandlerProd(SwanPodHookHandler):

    def get_swan_user_pod(self):
        super().get_swan_user_pod()

        # ATTENTION Spark requires this side container, so we need to create it!!
        # Check if we should add the EOS path in the firstplace
        # if hasattr(self.spawner, 'local_home') and \
        #     not self.spawner.local_home:

        # get eos token
        eos_secret_name = self._init_eos_secret()

        # init user containers (notebook and side-container)
        self._init_eos_containers(eos_secret_name)

        if self._gpu_enabled():
            # spc_t type is added as recommended by CM
            spc_t_selinux = client.V1SELinuxOptions(
                type = "spc_t"
            )
            security_context = client.V1PodSecurityContext(
                se_linux_options = spc_t_selinux
            )
            self.pod.spec.security_context = security_context

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

    def _init_eos_containers(self, eos_secret_name):
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
                    name='swan-scripts-cern',
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
            raise ValueError("""Access to GPUs is not granted;
    please <a href="https://cern.service-now.com/service-portal?id=functional_element&name=swan" target="_blank">open a Support Ticket</a>""")
        elif "cu" in lcg_rel:
            return True
        return False

# https://jupyterhub-kubespawner.readthedocs.io/en/latest/spawner.html
# This is defined in the configuration to allow overring iindependently 
# of which config file is loaded first
# c.SwanKubeSpawner.modify_pod_hook = swan_pod_hook
def swan_pod_hook_prod(spawner, pod):
    """
    :param spawner: Swan Kubernetes Spawner
    :type spawner: swanspawner.SwanKubeSpawner
    :param pod: default pod definition set by jupyterhub
    :type pod: client.V1Pod

    :returns: dynamically customized pod specification for user session
    :rtype: client.V1Pod
    """
    pod_hook_handler = SwanPodHookHandlerProd(spawner, pod)
    return pod_hook_handler.get_swan_user_pod()


swan_cull_period = get_config('custom.cull.every', 600)
# Get configuration parameters from environment variables
swan_container_namespace = os.environ.get('POD_NAMESPACE', 'default')

c.SwanKubeSpawner.modify_pod_hook = swan_pod_hook_prod

# Required for swan systemuser.sh
c.SwanKubeSpawner.cmd = None
