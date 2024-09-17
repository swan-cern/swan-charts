import subprocess

from kubernetes_asyncio.client.models import (
    V1Affinity,
    V1EnvVar,
    V1EnvVarSource,
    V1ContainerPort,
    V1NodeAffinity,
    V1NodeSelector,
    V1NodeSelectorRequirement,
    V1NodeSelectorTerm,
    V1ObjectMeta,
    V1Secret,
    V1SecretKeySelector,
    V1SecretVolumeSource,
    V1Service,
    V1ServicePort,
    V1ServiceSpec,
    V1Toleration,
    V1Volume,
    V1VolumeMount,
)

from kubernetes_asyncio.client.rest import ApiException

"""
Class handling KubeSpawner.modify_pod_hook(spawner,pod) call
"""


class SwanComputingPodHookHandler(SwanPodHookHandlerProd):

    _SPARK_REQUIRED_PORTS  = 18
    _CONDOR_REQUIRED_PORTS = 5

    async def get_swan_user_pod(self):
        await super().get_swan_user_pod()

        required_ports = 0

        if self._gpu_enabled():
            # Configure GPU allocation
            self._modify_pod_for_gpu()

        if self._spark_enabled():
            # Configure Spark clusters at CERN
            hadoop_secret_name = await self._init_hadoop_secret()
            await self._init_spark()

            # Modify user containers (notebook and side-container)
            self._modify_containers_for_spark(hadoop_secret_name)

            # Add required Spark ports
            required_ports += self._SPARK_REQUIRED_PORTS

        if self._condor_enabled():
            # Configure HTCondor pool at CERN
            required_ports += self._CONDOR_REQUIRED_PORTS

        if required_ports > 0:
            await self._open_ports(required_ports)

        return self.pod

    def _modify_pod_for_gpu(self):
        """
        Configure a pod that requested a GPU.

        Two scenarios are possible:
        - Regular user: we need to add resource requests and limits for a
        generic GPU resource to the notebook container.
        - User who participates in a SWAN event: we need to add resource
        requests and limits for the GPU resource that has been configured for
        the event. In addition, we need to add a node affinity and a taint
        toleration to the pod to ensure that event pods (and only them) are
        scheduled on resources that have been allocated for the event (and
        therefore have been labeled and tainted to host only event pods).
        """
        if events_role in self.spawner.user_roles:
            # The user is a participant of an event hosted by SWAN.
            # Their pod must be allocated on a node that has been
            # provisioned exclusively for the event

            # Get the GPU resource name in k8s that the user should be
            # mapped to
            gpu_resource_name = events_gpu_name

            # Add affinity to nodes that have been provisioned for the
            # event, i.e. labeled with the events role name
            node_selector_req = V1NodeSelectorRequirement(
                key = events_role,
                operator = 'Exists'
            )
            node_selector_term = V1NodeSelectorTerm(
                match_expressions = [ node_selector_req ]
            )
            node_selector = V1NodeSelector(
                node_selector_terms = [ node_selector_term ]
            )
            node_affinity = V1NodeAffinity(
                required_during_scheduling_ignored_during_execution = node_selector
            )
            self.pod.spec.affinity = V1Affinity(node_affinity = node_affinity)

            # Add toleration to nodes that have been provisioned for the
            # event, i.e. tainted with the events role name
            toleration = V1Toleration(
                key = events_role,
                operator = 'Exists',
                effect = 'NoSchedule'
            )
            self.pod.spec.tolerations = [ toleration ]

        else:
            # Regular user

            # Request generic GPU resource name
            gpu_resource_name = 'nvidia.com/gpu'

        # Add to notebook container the requests and limits for the GPU
        notebook_container = self._get_pod_container('notebook')
        resources = notebook_container.resources
        resources.requests[gpu_resource_name] = '1'
        resources.limits[gpu_resource_name] = '1'

        # Configure OpenCL to use NVIDIA backend
        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            V1EnvVar(
                name='OCL_ICD_FILENAMES',
                value='libnvidia-opencl.so.1'
            ),
        )

    async def _init_hadoop_secret(self):
        """
        Create secret for Spark/Hadoop
        """

        cluster = self.spawner.user_options[self.spawner.spark_cluster_field]

        username = self.spawner.user.name
        hadoop_secret_name = f'hadoop-tokens-{username}'

        k8suser_config_base64 = ''

        if cluster == 'k8s':
            hdfs_cluster = 'analytix'
            try:
                # Setup the user and generate user kube config
                k8suser_config_base64 = subprocess.check_output(
                    ['sudo', '--preserve-env=SWAN_DEV', '/srv/jupyterhub/private/sparkk8s_token.sh', username], timeout=60
                ).decode('ascii')
            except Exception as e:
                # if no access, all good for now
                raise ValueError("Could not setup user on k8s")

        # Create V1Secret with webdhfs token and k8s user config
        try:
            secret_data = V1Secret()

            secret_meta = V1ObjectMeta()
            secret_meta.name = hadoop_secret_name
            secret_meta.namespace = swan_container_namespace
            secret_data.metadata = secret_meta
            secret_data.data = {}
            secret_data.data['k8s-user.config'] = k8suser_config_base64

            try:
                await self.spawner.api.read_namespaced_secret(hadoop_secret_name, swan_container_namespace)
                exists = True
            except ApiException:
                exists = False

            if exists:
                await self.spawner.api.replace_namespaced_secret(hadoop_secret_name, swan_container_namespace, secret_data)
            else:
                await self.spawner.api.create_namespaced_secret(swan_container_namespace, secret_data)
        except ApiException as e:
            raise RuntimeError('Could not create required hadoop secret') from e

        return hadoop_secret_name

    def _modify_containers_for_spark(self, hadoop_secret_name):
        """
        Configure CERN-related secrets for Spark
        """

        notebook_container = self._get_pod_container('notebook')
        side_container = self._get_pod_container('side-container')

         # pod volume to mount generated hadoop tokens and
         # side-container volume mount with generated tokens
        self.pod.spec.volumes.append(
            # V1Secret for tokens without adjusted permissions
            V1Volume(
                name=hadoop_secret_name,
                secret=V1SecretVolumeSource(
                   secret_name=hadoop_secret_name,
                )
            )
        )
        side_container.volume_mounts.append(
            V1VolumeMount(
                name=hadoop_secret_name,
                mount_path='/srv/side-container/hadoop'
            )
        )

        # instruct sparkconnector to fetch delegation tokens from service
        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            V1EnvVar(
                name='SWAN_FETCH_HADOOP_TOKENS',
                value='true'
            ),
        )

        # hadoop token generator url
        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            V1EnvVar(
                name='SWAN_HADOOP_TOKEN_GENERATOR_URL',
                value='http://hadoop-token-generator:80'
            ),
        )

        # configuration to access Spark k8s cluster
        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            V1EnvVar(
                name='KUBECONFIG',
                value='/srv/notebook/tokens/k8s-user.config'
            ),
        )

    def _gpu_enabled(self):
        """
        return True if the user has requested a GPU
        """
        return "cu" in self.spawner.user_options.get(self.spawner.lcg_rel_field, '')

    def _spark_enabled(self):
        """
        Helper function to determine if spark related configuration is necessary
        raise exception if user has not access to the selected spark cluster
        return True if spark cluster is selected and user has access to the selected spark cluster
        return False if spark cluster is not selected
        """

        user_roles = self.spawner.user_roles
        cluster = self.spawner.user_options.get(self.spawner.spark_cluster_field, 'none')

        if cluster == "analytix" and "analytix" not in user_roles:
           raise ValueError(
              """
              Access to the Analytix cluster is not granted. 
              Please <a href="https://cern.service-now.com/service-portal?id=sc_cat_item&name=access-cluster-hadoop&se=Hadoop-Service" target="_blank">request access</a>
              """)
        elif cluster == "hadoop-nxcals" and "hadoop-nxcals" not in user_roles:
           raise ValueError(
              """
              Access to the NXCALS cluster is not granted. 
              Please <a href="http://nxcals-docs.web.cern.ch/current/user-guide/data-access/nxcals-access-request/" target="_blank">request access</a>
              """)
        elif cluster != "none":
            return True
        return False

    async def _init_spark(self):
        """
        Set CERN-related configuration for Spark clusters
        """

        notebook_container = self._get_pod_container('notebook')
        username = self.spawner.user.name

        cluster = self.spawner.user_options[self.spawner.spark_cluster_field]
        max_mem = self.spawner.user_options[self.spawner.user_memory]

        # add basic spark envs

        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            V1EnvVar(
                name='SPARK_CLUSTER_NAME',
                value=cluster
            )
        )
        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            V1EnvVar(
                name='SPARK_USER',
                value=username
            )
        )
        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            V1EnvVar(
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
            V1EnvVar(
                name='SPARK_AUTH_REQUIRED',
                value=auth_required
            )
        )

        # add spark config env
        conf_home = get_config('custom.spark.configurationPath')
        if cluster == 'k8s':
            spark_conf_script = f'{conf_home}/k8s-swan-setconf.sh'
        else:
            spark_conf_script = f'{conf_home}/hadoop-swan-setconf.sh'

        notebook_container.env = self._add_or_replace_by_name(
            notebook_container.env,
            V1EnvVar(
                name='SPARK_CONFIG_SCRIPT',
                value=spark_conf_script
            )
        )

    def _condor_enabled(self):
        """
        return True if the user has selected an HTCondor pool.
        """
        condor_pool = self.spawner.user_options.get(self.spawner.condor_pool, 'none')
        return condor_pool != 'none'

    async def _open_ports(self, num_ports):
        """
        Create a service that opens the necessary ports to integrate with external
        computing resources.
        """

        computing_ports_service = f'computing-ports-{self.spawner.user.name}'
        notebook_container = self._get_pod_container('notebook')

        try:
            # Define `num_ports` random NodePorts on the cluster using V1Service
            service_template_ports = []
            for port_id in range(1, num_ports + 1):
                service_template_ports.append(
                    V1ServicePort(
                        name=f'comp-port-{str(port_id)}',
                        port=port_id
                    )
                )
            service_template = V1Service(
                api_version="v1",
                kind="Service",
                metadata=V1ObjectMeta(
                    name=computing_ports_service
                ),
                spec=V1ServiceSpec(
                    selector=self.pod.metadata.labels,  # attach this service to the user pod
                    ports=service_template_ports,
                    type="NodePort"
                )
            )

            # Create V1Service which allocates random ports
            try:
                # use existing if possible
                service = await self.spawner.api.read_namespaced_service(computing_ports_service, swan_container_namespace)
            except ApiException:
                # not existing, create
                try:
                    service = await self.spawner.api.create_namespaced_service(swan_container_namespace, service_template)
                except ApiException as e:
                    raise RuntimeError('Could not create service that allocates random ports for computing integrations') from e

            # Replace the service with allocated nodeports to map nodeport:targetport
            # and set these ports for the notebook container
            ports = []
            for port_id in range(len(service.spec.ports)):
                name = service.spec.ports[port_id].name
                node_port = service.spec.ports[port_id].node_port
                service.spec.ports[port_id] = V1ServicePort(
                    name=name,
                    node_port=node_port,
                    port=node_port,
                    target_port=node_port
                )

                # Open proper ports in the notebook container to map nodeport:targetport
                notebook_container.ports = self._add_or_replace_by_name(
                    notebook_container.ports,
                    V1ContainerPort(
                        name=name,
                        container_port=node_port,
                        # this is needed - hadoop-yarn webapp crashes on ApplicationProxy UI
                        host_port=node_port,
                    )
                )

                ports.append(str(node_port))

            await self.spawner.api.replace_namespaced_service(computing_ports_service, swan_container_namespace, service)

            # Add ports env for computing integrations
            # Keep old SPARK_PORTS variable name for as long as we support the CentOS7 image, since the port
            # allocator version of such image expects a variable with that name
            ports_var_name = 'COMPUTING_PORTS' if 'swan-' in notebook_container.image else 'SPARK_PORTS'
            notebook_container.env = self._add_or_replace_by_name(
                notebook_container.env,
                V1EnvVar(
                    name=ports_var_name,
                    value=','.join(ports)
                )
            )
        except ApiException as e:
            raise RuntimeError('Could not create required user ports') from e


def computing_modify_pod_hook(spawner, pod):
    """
    :param spawner: Swan Kubernetes Spawner
    :type spawner: swanspawner.SwanKubeSpawner
    :param pod: default pod definition set by jupyterhub
    :type pod: V1Pod

    :returns: dynamically customized pod specification for user session
    :rtype: V1Pod
    """
    computing_pod_hook_handler = SwanComputingPodHookHandler(spawner, pod)
    return computing_pod_hook_handler.get_swan_user_pod()


# Custom configuration options
# Name of the role that is assigned to participants of events hosted by SWAN
events_role = get_config('custom.events.role', 'swan-events')
# Name in k8s of the GPU resource to be assigned to participants of an event in SWAN
events_gpu_name = get_config('custom.events.gpu_name', 'nvidia.com/gpu')


c.SwanKubeSpawner.modify_pod_hook = computing_modify_pod_hook
