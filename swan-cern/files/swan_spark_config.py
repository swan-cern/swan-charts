import os, subprocess, time, pwd, jwt

from kubernetes_asyncio.client.models import (
    V1EnvVar,
    V1EnvVarSource,
    V1ContainerPort,
    V1ObjectMeta,
    V1Secret,
    V1SecretKeySelector,
    V1SecretVolumeSource,
    V1Service,
    V1ServicePort,
    V1ServiceSpec,
    V1Volume,
    V1VolumeMount,
)

from kubernetes_asyncio.client.rest import ApiException

import swanspawner

"""
Class handling KubeSpawner.modify_pod_hook(spawner,pod) call
"""


class SwanSparkPodHookHandler(SwanPodHookHandlerProd):

    async def get_swan_user_pod(self):
        await super().get_swan_user_pod()

        # get hadoop token
        hadoop_secret_name = None
        if self._spark_enabled():
            # cern customisation for spark clusters
            hadoop_secret_name = await self._init_hadoop_secret()
            await self._init_spark(self.pod.metadata.labels)

        # init user containers (notebook and side-container)
        self._init_spark_containers(hadoop_secret_name)

        return self.pod

    async def _init_hadoop_secret(self):

        cluster = self.spawner.user_options[self.spawner.spark_cluster_field]

        if cluster == 'none':
            return None

        username = self.spawner.user.name
        hadoop_secret_name ='hadoop-tokens-%s' % username

        webhdfs_token_base64 = ''
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

            try:
                # Retrieve hdfs token for user
                webhdfs_token_base64 = subprocess.check_output(
                    ['sudo', '--preserve-env=SWAN_DEV', '/srv/jupyterhub/private/webhdfs_token.sh', hdfs_cluster, username], timeout=60
                ).decode('ascii')
            except Exception as e:
                # if no access, all good for now
                raise ValueError("Could not get webhdfs tokens")
        else:
            try:
                # Retrieve hdfs token for user
                webhdfs_token_base64 = subprocess.check_output(
                    ['sudo', '--preserve-env=SWAN_DEV', '/srv/jupyterhub/private/webhdfs_token.sh', cluster, username], timeout=60
                ).decode('ascii')
            except Exception as e:
                # if no access, all good for now
                raise ValueError("Could not get webhdfs tokens")

        # Create V1Secret with eos token
        try:
            secret_data = V1Secret()

            secret_meta = V1ObjectMeta()
            secret_meta.name = hadoop_secret_name
            secret_meta.namespace = swan_container_namespace
            secret_data.metadata = secret_meta
            secret_data.data = {}
            secret_data.data['k8s-user.config'] = k8suser_config_base64
            secret_data.data['webhdfs.toks'] = webhdfs_token_base64

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
            raise Exception("Could not create required hadoop secret: %s\n" % e)

        return hadoop_secret_name

    def _init_spark_containers(self, hadoop_secret_name):
        """
        Define cern related secrets for spark and eos
        """
        notebook_container = self._get_pod_container('notebook')
        side_container = self._get_pod_container('side-container')
        username = self.spawner.user.name

        pod_spec_containers = []
        side_container_volume_mounts = []

        if hadoop_secret_name:
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
            notebook_container.env = self._add_or_replace_by_name(
                notebook_container.env,
                V1EnvVar(
                    name='SWAN_HADOOP_TOKEN_GENERATOR_URL',
                    value='http://hadoop-token-generator:80'
                ),
            )
            notebook_container.env = self._add_or_replace_by_name(
                notebook_container.env,
                V1EnvVar(
                    name='KUBECONFIG',
                    value='/srv/notebook/tokens/k8s-user.config'
                ),
            )
            notebook_container.env = self._add_or_replace_by_name(
                notebook_container.env,
                V1EnvVar(
                    name='WEBHDFS_TOKEN',
                    value_from=V1EnvVarSource(
                        secret_key_ref=V1SecretKeySelector(
                            key='webhdfs.toks',
                            name=hadoop_secret_name
                        )
                    )
                ),
            )

    def _spark_enabled(self):
        """
        Helper function to determine if spark related configuration is necessary
        raise exception if user has not access to the selected spark cluster
        return True if spark cluster is selected and user has access to the selected spark cluster
        return False if spark cluster is not selected
        """

        user_roles = self.spawner.user_roles
        print(self.spawner.user_options)
        print(self.spawner.user_roles)
        cluster = self.spawner.user_options[self.spawner.spark_cluster_field]

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

    async def _init_spark(self, pod_labels):
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

        # configure spark ports
        try:
            spark_ports_env = []

            # Define some 18 random NodePorts on the cluster for spark using V1Service
            service_template_ports = []
            spark_ports_per_pod = 18
            for port_id in range(1, spark_ports_per_pod + 1):
                service_template_ports.append(
                    V1ServicePort(
                        name="spark-port-" + str(port_id),
                        port=port_id
                    )
                )
            service_template = V1Service(
                api_version="v1",
                kind="Service",
                metadata=V1ObjectMeta(
                    name=spark_ports_service
                ),
                spec=V1ServiceSpec(
                    selector=pod_labels,  # attach this service to the pod with label {spark_pod_label}
                    ports=service_template_ports,
                    type="NodePort"
                )
            )

            # Create V1Service which allocates random ports for spark in k8s cluster
            try:
                # use existing if possible
                await self.spawner.api.delete_namespaced_service(spark_ports_service, swan_container_namespace)
                service = await self.spawner.api.read_namespaced_service(spark_ports_service, swan_container_namespace)
            except ApiException:
                # not existing, create
                try:
                    service = await self.spawner.api.create_namespaced_service(swan_container_namespace, service_template)
                except ApiException as e:
                    raise Exception("Could not create service that allocates random ports for Spark in k8s cluster: %s\n" % e)

            # Replace the service with allocated nodeports to map nodeport:targetport
            # and set these ports for the notebook container
            for port_id in range(len(service.spec.ports)):
                name = service.spec.ports[port_id].name
                node_port = service.spec.ports[port_id].node_port
                service.spec.ports[port_id] = V1ServicePort(
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
                    V1ContainerPort(
                        name=name,
                        container_port=node_port,
                        # this is needed - hadoop-yarn webapp crashes on ApplicationProxy UI
                        host_port=node_port,
                    )
                )

            await self.spawner.api.replace_namespaced_service(spark_ports_service, swan_container_namespace, service)

            # Add ports env for spark
            notebook_container.env = self._add_or_replace_by_name(
                notebook_container.env,
                V1EnvVar(
                    name='SPARK_PORTS',
                    value=','.join(spark_ports_env)
                )
            )
        except ApiException as e:
            raise Exception("Could not create required user ports: %s\n" % e)


def spark_modify_pod_hook(spawner, pod):
    """
    :param spawner: Swan Kubernetes Spawner
    :type spawner: swanspawner.SwanKubeSpawner
    :param pod: default pod definition set by jupyterhub
    :type pod: V1Pod

    :returns: dynamically customized pod specification for user session
    :rtype: V1Pod
    """
    spark_pod_hook_handler = SwanSparkPodHookHandler(spawner, pod)
    return spark_pod_hook_handler.get_swan_user_pod()


c.SwanKubeSpawner.modify_pod_hook = spark_modify_pod_hook
