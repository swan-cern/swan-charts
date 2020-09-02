import os, subprocess, time, pwd, jwt

from kubernetes import client
from kubernetes.client.rest import ApiException

import swanspawner

"""
Class handling KubeSpawner.modify_pod_hook(spawner,pod) call
"""


class PodHookHandler:
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

        # get hadoop token
        hadoop_secret_name = None
        if self._spark_enabled():
            # cern customisation for spark clusters
            hadoop_secret_name = self._init_hadoop_secret()
            self._init_spark(pod_labels)

        if self._gpu_enabled():
            # currently no cern customisation required
            pass

        # init pod affinity
        self._init_pod_affinity(pod_labels)

        # init user containers (notebook and side-container)
        self._init_user_containers(eos_secret_name, hadoop_secret_name)

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

    def _init_hadoop_secret(self):

        cluster = self.spawner.user_options[self.spawner.spark_cluster_field]

        if cluster == 'none':
            return None

        username = self.spawner.user.name
        hadoop_secret_name ='hadoop-tokens-%s' % username

        hadoop_token_base64 = ''
        webhdfs_token_base64 = ''
        k8suser_config_base64 = ''

        if cluster == 'k8s':
            hdfs_cluster = 'analytix'
            try:
                # Setup the user and generate user kube config
                k8suser_config_base64 = subprocess.check_output(
                    ['sudo', '/srv/jupyterhub/private/sparkk8s_token.sh', username], timeout=60
                ).decode('ascii')
            except Exception as e:
                # if no access, all good for now
                raise ValueError("Could not setup user on k8s")
            try:
                # Retrieve HDFS, YARN token for user
                hadoop_token_base64 = subprocess.check_output(
                    ['sudo', '/srv/jupyterhub/private/hadoop_token.sh', hdfs_cluster, username], timeout=60
                ).decode('ascii')
            except Exception as e:
                # if no access, all good for now
                raise ValueError("Could not get spark tokens")
            try:
                # Retrieve hdfs token for user
                webhdfs_token_base64 = subprocess.check_output(
                    ['sudo', '/srv/jupyterhub/private/webhdfs_token.sh', hdfs_cluster, username], timeout=60
                ).decode('ascii')
            except Exception as e:
                # if no access, all good for now
                raise ValueError("Could not get webhdfs tokens")
        else:
            try:
                # Retrieve HDFS, YARN token for user
                hadoop_token_base64 = subprocess.check_output(
                    ['sudo', '/srv/jupyterhub/private/hadoop_token.sh', cluster, username], timeout=60
                ).decode('ascii')
            except Exception as e:
                # if no access, all good for now
                raise ValueError("Could not get spark tokens")
            try:
                # Retrieve hdfs token for user
                webhdfs_token_base64 = subprocess.check_output(
                    ['sudo', '/srv/jupyterhub/private/webhdfs_token.sh', cluster, username], timeout=60
                ).decode('ascii')
            except Exception as e:
                # if no access, all good for now
                raise ValueError("Could not get webhdfs tokens")

        # Create V1Secret with eos token
        try:
            secret_data = client.V1Secret()

            secret_meta = client.V1ObjectMeta()
            secret_meta.name = hadoop_secret_name
            secret_meta.namespace = swan_container_namespace
            secret_data.metadata = secret_meta
            secret_data.data = {}
            secret_data.data['k8s-user.config'] = k8suser_config_base64
            secret_data.data['hadoop.toks'] = hadoop_token_base64
            secret_data.data['webhdfs.toks'] = webhdfs_token_base64

            try:
                self.spawner.api.read_namespaced_secret(hadoop_secret_name, swan_container_namespace)
                exists = True
            except ApiException:
                exists = False

            if exists:
                self.spawner.api.replace_namespaced_secret(hadoop_secret_name, swan_container_namespace, secret_data)
            else:
                self.spawner.api.create_namespaced_secret(swan_container_namespace, secret_data)
        except ApiException as e:
            raise Exception("Could not create required hadoop secret: %s\n" % e)

        return hadoop_secret_name

    def _init_user_containers(self, eos_secret_name, hadoop_secret_name):
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

        if hadoop_secret_name:
            # pod volume to mount generated hadoop tokens and
            # side-container volume mount with generated tokens
            self.pod.spec.volumes.append(
                # V1Secret for tokens without adjusted permissions
                client.V1Volume(
                    name=hadoop_secret_name,
                    secret=client.V1SecretVolumeSource(
                        secret_name=hadoop_secret_name,
                    )
                )
            )
            side_container_volume_mounts.append(
                client.V1VolumeMount(
                    name=hadoop_secret_name,
                    mount_path='/srv/side-container/hadoop'
                )
            )

            # define hadoop auth environment for the notebook container
            notebook_container.env = self._add_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='HADOOP_TOKEN_FILE_LOCATION',
                    value='/srv/notebook/tokens/hadoop.toks'
                ),
            )
            notebook_container.env = self._add_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='KUBECONFIG',
                    value='/srv/notebook/tokens/k8s-user.config'
                ),
            )
            notebook_container.env = self._add_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='WEBHDFS_TOKEN',
                    value_from=client.V1EnvVarSource(
                        secret_key_ref=client.V1SecretKeySelector(
                            key='webhdfs.toks',
                            name=hadoop_secret_name
                        )
                    )
                ),
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

    def _spark_enabled(self):
        """
        Helper function to determine if spark related configuration is necessary
        raise exception if user has not access to the selected spark cluster
        return True if spark cluster is selected and user has access to the selected spark cluster
        return False if spark cluster is not selected
        """

        user_roles = self.spawner.user_roles
        cluster = self.spawner.user_options[self.spawner.spark_cluster_field]

        if cluster == "analytix" and "analytix" not in user_roles:
           raise ValueError(
              """
              Access to the Analytix cluster is not granted. 
              Please <a href="https://cern.service-now.com/service-portal/report-ticket.do?name=request&fe=Hadoop-Components" target="_blank">request access</a>
              """)
        elif cluster == "hadoop-nxcals" and "hadoop-nxcals" not in user_roles:
           raise ValueError(
              """
              Access to the NXCALS cluster is not granted. 
              Please <a href="https://wikis.cern.ch/display/NXCALS/Data+Access+User+Guide#DataAccessUserGuide-nxcals_access" target="_blank">request access</a>
              """)
        elif cluster != "none":
            return True
        return False

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

    def _init_spark(self, pod_labels):
        """
        Set cern related configuration for spark cluster and open ports
        """
        notebook_container = self._get_pod_container('notebook')
        username = self.spawner.user.name

        cluster = self.spawner.user_options[self.spawner.spark_cluster_field]
        max_mem = self.spawner.user_options[self.spawner.user_memory]

        if cluster == 'none':
            return

        spark_ports_service = "spark-ports" + "-" + username

        # add basic spark envs

        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            client.V1EnvVar(
                name='SPARK_CLUSTER_NAME',
                value=cluster
            )
        )
        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            client.V1EnvVar(
                name='SPARK_USER',
                value=username
            )
        )
        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            client.V1EnvVar(
                name='MAX_MEMORY',
                value=max_mem
            )
        )

        # add spark auth required env

        if cluster == 'hadoop-nxcals':
            auth_required = 'true'
        else:
            auth_required = 'false'

        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            client.V1EnvVar(
                name='SPARK_AUTH_REQUIRED',
                value=auth_required
            )
        )

        # add spark config env

        if cluster == 'k8s':
            spark_conf_script = '/cvmfs/sft.cern.ch/lcg/etc/hadoop-confext/hadoop-swan-setconf.sh'
        else:
            spark_conf_script = '/cvmfs/sft.cern.ch/lcg/etc/hadoop-confext/hadoop-swan-setconf.sh'

        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            client.V1EnvVar(
                name='SPARK_CONFIG_SCRIPT',
                value=spark_conf_script
            )
        )

        # configure spark ports
        try:
            spark_ports_env = []

            # Define some 6 random NodePorts on the cluster for spark using V1Service
            service_template_ports = []
            spark_ports_per_pod = 6
            for port_id in range(1, spark_ports_per_pod + 1):
                service_template_ports.append(
                    client.V1ServicePort(
                        name="spark-port-" + str(port_id),
                        port=port_id
                    )
                )
            service_template = client.V1Service(
                api_version="v1",
                kind="Service",
                metadata=client.V1ObjectMeta(
                    name=spark_ports_service
                ),
                spec=client.V1ServiceSpec(
                    selector=pod_labels,  # attach this service to the pod with label {spark_pod_label}
                    ports=service_template_ports,
                    type="NodePort"
                )
            )

            # Create V1Service which allocates random ports for spark in k8s cluster
            try:
                # use existing if possible
                self.spawner.api.delete_namespaced_service(spark_ports_service, swan_container_namespace)
                service = self.spawner.api.read_namespaced_service(spark_ports_service, swan_container_namespace)
            except ApiException:
                # not existing, create
                service = self.spawner.api.create_namespaced_service(swan_container_namespace, service_template)

            # Replace the service with allocated nodeports to map nodeport:targetport
            # and set these ports for the notebook container
            for port_id in range(len(service.spec.ports)):
                name = service.spec.ports[port_id].name
                node_port = service.spec.ports[port_id].node_port
                service.spec.ports[port_id] = client.V1ServicePort(
                    name=name,
                    node_port=node_port,
                    port=node_port,
                    target_port=node_port
                )

                # Construct ports env for spark
                spark_ports_env.append(str(node_port))

                # Open proper ports in the notebook container to map nodeport:targetport
                notebook_container.ports = self._add_or_replace_by_name(
                    notebook_container.ports,
                    client.V1ContainerPort(
                        name=name,
                        container_port=node_port,
                        # this is needed - hadoop-yarn webapp crashes on ApplicationProxy UI
                        host_port=node_port,
                    )
                )
            self.spawner.api.replace_namespaced_service(spark_ports_service, swan_container_namespace, service)

            # Add ports env for spark
            notebook_container.env = self._add_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='SPARK_PORTS',
                    value=','.join(spark_ports_env)
                )
            )
        except ApiException as e:
            raise Exception("Could not create required user ports: %s\n" % e)

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
        self.pod.spec.affinity = aff

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
    pod_hook_handler = PodHookHandler(spawner, pod)
    return pod_hook_handler.get_swan_user_pod()

"""
Configuration for JupyterHub
"""

# Spawn single-user's servers in the Kubernetes cluster
c.JupyterHub.spawner_class = swanspawner.SwanKubeSpawner

# Authenticator
c.JupyterHub.authenticator_class = 'keycloakauthenticator.KeyCloakAuthenticator'
c.KeyCloakAuthenticator.enable_auth_state = True
c.KeyCloakAuthenticator.username_key = 'preferred_username'
c.KeyCloakAuthenticator.logout_redirect_uri = 'https://cern.ch/swan'
c.KeyCloakAuthenticator.oauth_callback_url = os.environ.get('OAUTH_CALLBACK_URL')

def get_uid_hook(spawner, auth_state):
    spawner.user_uid = str(auth_state['oauth_user']['cern_uid'])
c.KeyCloakAuthenticator.get_uid_hook = get_uid_hook

c.KeyCloakAuthenticator.oidc_issuer = 'https://auth.cern.ch/auth/realms/cern'

c.KeyCloakAuthenticator.accepted_roles = set()
c.KeyCloakAuthenticator.auto_login = True
c.KeyCloakAuthenticator.admin_role = 'swan-admins'


# https://jupyterhub-kubespawner.readthedocs.io/en/latest/spawner.html
c.SwanKubeSpawner.modify_pod_hook = modify_pod_hook

# Get configuration parameters from environment variables
swan_container_namespace = os.environ.get('POD_NAMESPACE', 'default')

SPAWN_ERROR_MESSAGE = """SWAN could not start a session for your user, please try again. If the problem persists, please check:
<ul>
    <li>Do you have a CERNBox account? If not, click <a href="https://cernbox.cern.ch" target="_blank">here</a>.</li>
    <li>Is there a problem with the service? Find information <a href="https://cern.service-now.com/service-portal/ssb.do" target="_blank">here</a>.</li>
    <li>If none of the options apply, please open a <a href="https://cern.service-now.com/service-portal/function.do?name=swan" target="_blank">Support Ticket</a>.</li>
</ul>"""

# SWAN@CERN error message
c.SpawnHandlersConfigs.spawn_error_message = SPAWN_ERROR_MESSAGE

# disable some defaults of swanspawner that do now work for kube-spawner
c.SpawnHandlersConfigs.metrics_on = False
c.SpawnHandlersConfigs.local_home = True

# Add SWAN look&feel
c.JupyterHub.template_paths = ['/srv/jupyterhub/jh_gitlab/templates']
c.JupyterHub.logo_file = '/usr/local/share/jupyterhub/static/swan/logos/logo_swan_cloudhisto.png'

# Configure swan spawn form
c.SwanSpawner.options_form_config = '/srv/jupyterhub/options_form_config.json'

# Culling of users and ticket refresh
swan_cull_idle = get_config('custom.cull.enabled', False)
swan_cull_check_ticket = get_config('custom.cull.checkEosAuth.enabled', False)
swan_cull_period = get_config('custom.cull.period', 600)
swan_cull_timeout = get_config('custom.cull.timeout', 14400)
if swan_cull_idle:
    if swan_cull_check_ticket:
        cull_command_local_home = "False"
    else:
        cull_command_local_home = "True"

    cull_command = 'python3 /srv/jupyterhub/jh_gitlab/scripts/cull_idle_servers.py ' \
                   '--cull_every=%d ' \
                   '--timeout=%d ' \
                   '--local_home=%s ' \
                   '--cull_users=True' % (swan_cull_period, swan_cull_timeout, cull_command_local_home)
    print(cull_command)
    c.JupyterHub.services.append(
        {
            'name': 'cull-idle',
            'admin': True,
            'command': cull_command.split(),
        }
    )

# Give notebook 45s to start a webserver and max 60s for whole spawn process
c.SwanSpawner.http_timeout = 45
c.SwanSpawner.start_timeout = 60
c.SwanSpawner.consecutive_failure_limit = 0

# FIXME:
# remove when we move to jh.1.1 exception .jupyterhub_message, that is displayed in not_running.html (upstream)
# currently we customize spawnhandler to redirect to form
c.JupyterHub.tornado_settings = {
    'slow_spawn_timeout': 15
}

# Enble namedservers
c.JupyterHub.allow_named_servers = True

# Required for swan systemuser.sh
c.SwanKubeSpawner.cmd = None

# add EOS to notebook pods
c.SwanKubeSpawner.volume_mounts = [
    client.V1VolumeMount(
        name='eos',
        mount_path='/eos',
        mount_propagation='HostToContainer'
    ),
    client.V1VolumeMount(
        name='cvmfs',
        mount_path='/cvmfs',
        mount_propagation='HostToContainer'
    ),
]

# set home directory to EOS
c.SwanKubeSpawner.local_home = False

c.SwanKubeSpawner.volumes = [
    client.V1Volume(
        name='eos',
        host_path=client.V1HostPathVolumeSource(
            path='/var/eos'
        )
    ),
    client.V1Volume(
        name='cvmfs',
        host_path=client.V1HostPathVolumeSource(
            path='/var/cvmfs'
        )
    ),
]
