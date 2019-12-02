import pwd, os, subprocess
from kubernetes import client
from kubernetes.client.rest import ApiException
from oauthenticator.generic import GenericOAuthenticator
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
import json

"""
Classes handling authentication for SWAN at CERN
"""


class CERNOAuthenticator(GenericOAuthenticator):

    CERN_OAUTH_ME_ENDPOINT = "https://oauthresource.web.cern.ch/api/Me"
    CERN_OAUTH_LDAP_UID_TYPE = "http://schemas.xmlsoap.org/claims/uidNumber"
    CERN_OAUTH_LDAP_GID_TYPE = "http://schemas.xmlsoap.org/claims/gidNumber"
    CERN_OAUTH_LDAP_USERNAME_TYPE = "http://schemas.xmlsoap.org/claims/CommonName"

    async def authenticate(self, handler, data=None):
        user_data = await super().authenticate(handler, data)

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Bearer {}".format(user_data['auth_state']['access_token'])
        }

        http_client = AsyncHTTPClient()
        req = HTTPRequest(self.CERN_OAUTH_ME_ENDPOINT,
                          method=self.userdata_method,
                          headers=headers,
                          validate_cert=self.tls_verify,
                          )
        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        user_data['auth_state']['ldap_uid'] = self.__get_oauth_response_value(self.CERN_OAUTH_LDAP_UID_TYPE, resp_json)

        self.log.info("Retrieved LDAP user %s(%s) info from OAuth"
                      % (user_data['auth_state']['ldap_uid'], user_data['name']))

        return user_data

    async def pre_spawn_start(self, user, spawner):
        auth_state = await user.get_auth_state()
        os.system("groupadd " + user.name + " -g " + auth_state['ldap_uid'])
        os.system("useradd " + user.name + " -u " + auth_state['ldap_uid'] + " -g " + auth_state['ldap_uid'])

        self.log.info("Added user %s(%s) to pwd" % (auth_state['ldap_uid'], user.name))

    @staticmethod
    def __get_oauth_response_value(type, response):
        for field in response:
            if field['Type'] == type:
                return field['Value']
        return None


"""
Class handling KubeSpawner.modify_pod_hook_call(spawner,pod) call
"""


class PodHookHandler:
    def __init__(self, **kwargs):
        pass

    @staticmethod
    def modify_pod_hook(spawner, pod_definition):
        """
        :param spawner: Swan Kubernetes Spawner (swanspawner.SwanKubeSpawner)
        :type spawner: kubespawner.KubeSpawner
        :param pod_definition: default pod definition set by jupyterhub
        :type pod_definition: client.V1Pod
        :returns: dynamically customized pod specification for user session
        :rtype: client.V1Pod
        """

        if spawner.get_spark_cluster() != 'none':
            pod_definition = PodHookHandler._init_spark(spawner, pod_definition)
        pod_definition = PodHookHandler._init_resource_requirements(spawner, pod_definition)
        pod_definition = PodHookHandler._init_swan_container_env(spawner, pod_definition)
        pod_definition = PodHookHandler._init_swan_secrets(spawner, pod_definition)
        # pod_definition = PodHookHandler._init_pod_affinity(spawner, pod_definition)

        return pod_definition

    @staticmethod
    def _init_pod_affinity(spawner, pod):
        spec = client.V1PodSpec()
        aff = client.V1Affinity()
        aff.node_affinity
        spec.affinity(aff)
        return pod.spec(spec)


    @staticmethod
    def _init_swan_container_env(spawner, pod):
        """
        Customize base notebook environment variables of systemuser container
        https://gitlab.cern.ch/swan/jupyterhub/tree/swan_k8s/SwanSpawner#swanspawner-jupyter-notebook-environment-variables
        """
        notebook_container = PodHookHandler.__get_pod_container(pod, 'notebook')
        username = spawner.user.name

        # Set server hostname of the pod running jupyterhub
        notebook_container.env = PodHookHandler.__append_or_replace_by_name(
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

        # Set server hostname of the pod running jupyterhub
        notebook_container.env = PodHookHandler.__append_or_replace_by_name(
            notebook_container.env,
            client.V1EnvVar(
                name='HOME',
                value="/eos/home-%s/%s" % (username[0], username)
            )
        )

        return pod

    @staticmethod
    def _init_resource_requirements(spawner, pod):
        """
        Customize notebook resource requirements from the form
        """
        notebook_container = PodHookHandler.__get_pod_container(pod, 'notebook')

        limits = {
            "cpu": spawner.get_user_cores(),
            "memory": spawner.get_user_memory()
        }

        # in demo cluster, request always 1cpu and 2G regardless of the form
        requests = {
            "cpu": 1,
            "memory": '2G'
        }

        # add resource requirements for GPUs if available (this cluster has nvidia gpu's)
        if "cu" in spawner.get_lcg_release():
            requests["nvidia.com/gpu"] = "1"
            limits["nvidia.com/gpu"] = "1"

            # We are making visible all the devices, if the host has more that one can be used.
            notebook_container.env = PodHookHandler.__append_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='NVIDIA_VISIBLE_DEVICES',
                    value='all'
                )
            )
            notebook_container.env = PodHookHandler.__append_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='NVIDIA_DRIVER_CAPABILITIES',
                    value='compute,utility'
                )
            )
            notebook_container.env = PodHookHandler.__append_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='NVIDIA_REQUIRE_CUDA',
                    value='cuda>=10.0 driver>=410'
                )
            )

        notebook_container.resources = client.V1ResourceRequirements(
            limits=limits,
            requests=requests
        )

        return pod

    @staticmethod
    def _init_spark(spawner, pod):
        """
        Set cern related configuration for spark cluster and open ports
        """
        username = spawner.user.name
        notebook_container = PodHookHandler.__get_pod_container(pod, SWAN_CONTAINER_NAME)

        spark_ports_service = "spark-ports" + "-" + username
        spark_ports_label = {'spark-ports-pod': username}
        pod.metadata.labels.update(
            spark_ports_label
        )

        cluster = spawner.get_spark_cluster()
        # Add spark config env
        if cluster == 'k8s':
            notebook_container.env = PodHookHandler.__append_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='SPARK_CONFIG_SCRIPT',
                    value='/cvmfs/sft.cern.ch/lcg/etc/hadoop-confext/k8s-swan-setconf.sh'
                )
            )
        else:
            notebook_container.env = PodHookHandler.__append_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='SPARK_CONFIG_SCRIPT',
                    value='/cvmfs/sft.cern.ch/lcg/etc/hadoop-confext/hadoop-swan-setconf.sh'
                )
            )

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
                    selector=spark_ports_label,  # attach this service to the pod with label {spark_pod_label}
                    ports=service_template_ports,
                    type="NodePort"
                )
            )

            # Create V1Service which allocates random ports for spark in k8s cluster
            try:
                # use existing if possible
                spawner.api.delete_namespaced_service(spark_ports_service, SWAN_CONTAINER_NAMESPACE)
                service = spawner.api.read_namespaced_service(spark_ports_service, SWAN_CONTAINER_NAMESPACE)
            except ApiException:
                # not existing, create
                service = spawner.api.create_namespaced_service(SWAN_CONTAINER_NAMESPACE, service_template)

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
                notebook_container.ports = PodHookHandler.__append_or_replace_by_name(
                    notebook_container.ports,
                    client.V1ContainerPort(
                        name=name,
                        container_port=node_port,
                        # this is needed - hadoop-yarn webapp crashes on ApplicationProxy UI
                        host_port=node_port,
                    )
                )
            spawner.api.replace_namespaced_service(spark_ports_service, SWAN_CONTAINER_NAMESPACE, service)

            # Add ports env for spark
            notebook_container.env = PodHookHandler.__append_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='SPARK_PORTS',
                    value=','.join(spark_ports_env)
                )
            )
        except ApiException as e:
            raise Exception("Could not create required user ports: %s\n" % e)

        return pod

    @staticmethod
    def _init_swan_secrets(spawner, pod):
        """
        Define cern related secrets for spark and eos
        """
        username = spawner.user.name
        user_tokens_secret = 'user-tokens-' + username
        notebook_container = PodHookHandler.__get_pod_container(pod, SWAN_CONTAINER_NAME)
        pod_shared_tokens_volume_name = 'user-secrets'
        pod_spec_containers = []
        eos_token_base64 = ''
        hadoop_token_base64 = ''
        webhdfs_token_base64 = ''
        k8suser_config_base64 = ''

        try:
            # Retrieve eos token for user
            eos_token_base64 = subprocess.check_output(
                ['sudo', '/srv/jupyterhub/private/eos_token.sh', username], timeout=60
            ).decode('ascii')
        except Exception as e:
            notebook_container.env = PodHookHandler.__append_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='HOME',
                    value="/scratch/%s" % (username)
                )
            )
            raise ValueError("Could not create required user credential")

        cluster = spawner.get_spark_cluster()

        if cluster != 'none' and cluster == 'k8s':
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
        elif cluster != 'none':
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
            secret_meta.name = user_tokens_secret
            secret_meta.namespace = SWAN_CONTAINER_NAMESPACE
            secret_data.metadata = secret_meta
            secret_data.data = {}
            secret_data.data['eosToken'] = eos_token_base64
            secret_data.data['hadoopToken'] = hadoop_token_base64
            secret_data.data['webhdfsToken'] = webhdfs_token_base64
            secret_data.data['k8sToken'] = k8suser_config_base64

            try:
                spawner.api.read_namespaced_secret(user_tokens_secret, SWAN_CONTAINER_NAMESPACE)
                exists = True
            except ApiException:
                exists = False

            if exists:
                spawner.api.replace_namespaced_secret(user_tokens_secret, SWAN_CONTAINER_NAMESPACE, secret_data)
            else:
                spawner.api.create_namespaced_secret(SWAN_CONTAINER_NAMESPACE, secret_data)
        except ApiException as e:
            raise Exception("Could not create required user secret: %s\n" % e)

        pod.spec.volumes.append(
            # V1Secret for tokens without adjusted permissions
            client.V1Volume(
                name=user_tokens_secret,
                secret=client.V1SecretVolumeSource(
                    secret_name=user_tokens_secret,
                    items=[
                        client.V1KeyToPath(
                            key='eosToken',
                            path='krb5cc'
                        ),
                        client.V1KeyToPath(
                            key='hadoopToken',
                            path='hadoop.toks'
                        ),
                        client.V1KeyToPath(
                            key='k8sToken',
                            path='k8s-user.config'
                        ),
                    ]
                )
            )
        )
        pod.spec.volumes.append(
            # Shared V1EmptyDir between notebook and side-container for tokens with correct privileges
            client.V1Volume(
                name=pod_shared_tokens_volume_name,
                empty_dir=client.V1EmptyDirVolumeSource(
                    medium='Memory'
                )
            )
        )

        # Append as first (it will be first to spawn) side container which currently:
        #  - refreshes the kerberos token and adjust permissions for the user
        user_id = str(pwd.getpwnam(username).pw_uid)
        user_gid = str(pwd.getpwnam(username).pw_gid)
        krb_token_name = "krb5cc_%s" % user_id
        pod_spec_containers.append(
            client.V1Container(
                name='side-container',
                image='cern/cc7-base:20181210',
                command=['/bin/sh', '-c'],
                args=[
                    'cp /tokens-secret/hadoop.toks /tmp/hadoop.toks; ' +
                    'chmod 400 /tmp/hadoop.toks; chown ' + user_id + ':' + user_gid + ' /tmp/hadoop.toks; ' +
                    'mv /tmp/hadoop.toks /tokens/hadoop.toks; ' +
                    'cp /tokens-secret/k8s-user.config /tmp/k8s-user.config; ' +
                    'chmod 400 /tmp/k8s-user.config; chown ' + user_id + ':' + user_gid + ' /tmp/k8s-user.config; ' +
                    'mv /tmp/k8s-user.config /tokens/k8s-user.config; ' +
                    # in a loop - use mounted token secret, adjust permissions and move to /tokens pod volume
                    'while true; do ' +
                    'cp /tokens-secret/krb5cc /tmp/krb5cc; ' +
                    'chmod 400 /tmp/krb5cc; chown '+ user_id + ':' + user_gid + ' /tmp/krb5cc; ' +
                    'mv /tmp/krb5cc /tokens/' + krb_token_name + '; ' +
                    'sleep 60; ' +
                    'done;'
                ],
                volume_mounts=[
                    client.V1VolumeMount(
                        name=user_tokens_secret,
                        mount_path='/tokens-secret'
                    ),
                    client.V1VolumeMount(
                        name=pod_shared_tokens_volume_name,
                        mount_path='/tokens'
                    ),
                ]
            )
        )

        # Mount user-exposed tokens and set KRB5CCNAME for the user to point to the krb5 token
        notebook_container.volume_mounts.append(
            client.V1VolumeMount(
                name=pod_shared_tokens_volume_name,
                mount_path='/tokens'
            )
        )
        notebook_container.env = PodHookHandler.__append_or_replace_by_name(
            notebook_container.env,
            client.V1EnvVar(
                name='KRB5CCNAME',
                value='/tokens/' + krb_token_name
            ),
        )
        notebook_container.env = PodHookHandler.__append_or_replace_by_name(
            notebook_container.env,
            client.V1EnvVar(
                name='HADOOP_TOKEN_FILE_LOCATION',
                value='/tokens/hadoop.toks'
            ),
        )
        notebook_container.env = PodHookHandler.__append_or_replace_by_name(
            notebook_container.env,
            client.V1EnvVar(
                name='WEBHDFS_TOKEN',
                value_from=client.V1EnvVarSource(
                    secret_key_ref=client.V1SecretKeySelector(
                        key='webhdfsToken',
                        name=user_tokens_secret
                    )
                )
            ),
        )
        notebook_container.env = PodHookHandler.__append_or_replace_by_name(
            notebook_container.env,
            client.V1EnvVar(
                name='KUBECONFIG',
                value='/tokens/k8s-user.config'
            ),
        )

        # add the base containers after side container (to start after side container)
        existing_containers = pod.spec.containers
        pod_spec_containers.extend(existing_containers)

        # assigning pod spec containers
        pod.spec.containers = pod_spec_containers

        return pod

    @staticmethod
    def __get_pod_container(pod, container_name):
        """
        :param pod: pod definition
        :type pod: client.V1Pod
        :returns: required container from pod spec
        :rtype: client.V1Container
        """
        for container in pod.spec.containers:
            if container.name == container_name:
                return container

        return None

    @staticmethod
    def __append_or_replace_by_name(list, element):
        found = False
        for list_index in range(0, len(list)):
            if list[list_index].to_dict().get("name") == element.to_dict().get("name"):
                list[list_index] = element
                found = True
                break

        if not found:
            list.append(element)

        return list

"""
Configuration for JupyterHub - variables 
"""

# Get configuration parameters from environment variables
SWAN_CONTAINER_NAMESPACE = os.environ.get('POD_NAMESPACE', 'default')
SWAN_CONTAINER_NAME = 'notebook'
USER_TOKENS_SECRET_PREFIX = 'user-tokens-'
USER_TOKENS_SECRET_KEY = 'eosToken'
SPAWN_ERROR_MESSAGE = """SWAN could not start a session for your user, please try again. If the problem persists, please check:
<ul>
    <li>Do you have a CERNBox account? If not, click <a href="https://cernbox.cern.ch" target="_blank">here</a>.</li>
    <li>Is there a problem with the service? Find information <a href="https://cern.service-now.com/service-portal/ssb.do" target="_blank">here</a>.</li>
    <li>If none of the options apply, please open a <a href="https://cern.service-now.com/service-portal/function.do?name=swan" target="_blank">Support Ticket</a>.</li>
</ul>"""

"""
Configuration for JupyterHub - general
"""

# Spawn single-user's servers in the Kubernetes cluster
c.JupyterHub.spawner_class = 'swanspawner.SwanKubeSpawner'

# Add SWAN look&feel
c.JupyterHub.template_paths = ['/srv/jupyterhub/jh_gitlab/templates']
c.JupyterHub.logo_file = '/usr/local/share/jupyterhub/static/swan/logos/logo_swan_cloudhisto.png'
c.SwanSpawner.options_form = '/srv/jupyterhub/jupyterhub_form.html'

# SWAN@CERN error message
c.SpawnHandlersConfigs.spawn_error_message = SPAWN_ERROR_MESSAGE

# Culling of users and ticket refresh
c.JupyterHub.services = [
            {
                'name': 'cull-idle',
                'admin': True,
                'command': 'python3 /srv/jupyterhub/jh_gitlab/scripts/cull_idle_servers.py --cull_every=600 --timeout=14400 --local_home=False --cull_users=True'.split(),
            }
]

# Give notebook 45s to start a webserver and max 60 for whole spawn process
c.SwanSpawner.http_timeout = 45
c.SwanSpawner.start_timeout = 60
c.SwanSpawner.consecutive_failure_limit = 0
c.JupyterHub.tornado_settings = {
    'slow_spawn_timeout': 15
}


# SwanKubeSpawner requires to add user to pwd after authentication
auth_type = get_config('auth.type', None)
if auth_type == 'custom':
    c.JupyterHub.authenticator_class = CERNOAuthenticator
    c.Authenticator.enable_auth_state = True
    c.Authenticator.auto_login = True

"""
Configuration for Jupyter Notebook - general
"""

c.SwanSpawner.cmd = None

# https://jupyterhub-kubespawner.readthedocs.io/en/latest/spawner.html
c.SwanSpawner.modify_pod_hook = PodHookHandler.modify_pod_hook

"""
Configuration for Jupyter Notebook - storage available to the user
"""

# add EOS home
c.SwanSpawner.volume_mounts = [
    client.V1VolumeMount(
        name='eos',
        mount_path='/eos',
    ),
]
c.SwanSpawner.volumes = [
    client.V1Volume(
        name='eos',
        host_path=client.V1HostPathVolumeSource(
            path='/var/eos'
        )
    ),
]

# add CVMFS
cvmfs_repos = get_config('custom.cvmfs.repositories', [])
for cvmfs_repo_path in cvmfs_repos:
    cvmfs_repo_id = cvmfs_repo_path.replace('.', '-')
    c.SwanSpawner.volumes.append(
        client.V1Volume(
            name='cvmfs-'+cvmfs_repo_id,
            persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                claim_name='cvmfs-'+cvmfs_repo_id+'-pvc'
            )
        )
    )
    c.SwanSpawner.volume_mounts.append(
        client.V1VolumeMount(
            name='cvmfs-'+cvmfs_repo_id,
            mount_path='/cvmfs/'+cvmfs_repo_path,
            read_only=True
        )
    )

