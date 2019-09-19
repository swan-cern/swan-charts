import os
import pwd
import socket
import subprocess
from kubernetes import client
from kubernetes.client.rest import ApiException

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

        return pod_definition

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
        notebook_container = PodHookHandler.__get_pod_container(pod, 'notebook')

        spark_ports_service = "spark-ports" + "-" + username
        spark_ports_label = {'spark-ports-pod': username}
        pod.metadata.labels.update(
            spark_ports_label
        )

        # Add spark config env
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
            for port_id in range(1, c.SwanSpawner.spark_ports_per_pod + 1):
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
                spawner.api.delete_namespaced_service(spark_ports_service, NAMESPACE)
                service = spawner.api.read_namespaced_service(spark_ports_service, NAMESPACE)
            except ApiException:
                # not existing, create
                service = spawner.api.create_namespaced_service(NAMESPACE, service_template)

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
            spawner.api.replace_namespaced_service(spark_ports_service, NAMESPACE, service)

            # Add ports env for spark
            notebook_container.env = PodHookHandler.__append_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='SPARK_PORTS',
                    value=','.join(spark_ports_env)
                )
            )
        except ApiException as e:
            # FIXME: Exception message should be c.SpawnHandlersConfigs.spawn_error_message and the exception should be only logged
            raise Exception("Could not create required user ports: %s\n" % e)

        return pod

    @staticmethod
    def _init_swan_secrets(spawner, pod):
        """
        Define cern related secrets for spark and eos
        """
        username = spawner.user.name
        user_tokens_secret = USER_TOKENS_SECRET_PREFIX + username
        notebook_container = PodHookHandler.__get_pod_container(pod, 'notebook')
        pod_shared_tokens_volume_name = 'user-secrets'
        pod_spec_containers = []

        # Retrieve eos token for user
        try:
            eos_token_base64 = subprocess.check_output(
                ['sudo', '/srv/jupyterhub/private/eos_token.sh', username], timeout=60
            ).decode('ascii')
        except Exception:
            # FIXME: Exception message should be c.SpawnHandlersConfigs.spawn_error_message and the exception should be only logged
            raise Exception("Could not create required user credential\n")

        # Create V1Secret with eos token
        try:
            secret_data = client.V1Secret()

            secret_meta = client.V1ObjectMeta()
            secret_meta.name = user_tokens_secret
            secret_meta.namespace = NAMESPACE
            secret_data.metadata = secret_meta
            secret_data.data = {}
            secret_data.data[USER_TOKENS_SECRET_KEY] = eos_token_base64

            try:
                spawner.api.read_namespaced_secret(user_tokens_secret, NAMESPACE)
                exists = True
            except ApiException:
                exists = False

            if exists:
                spawner.api.replace_namespaced_secret(user_tokens_secret, NAMESPACE, secret_data)
            else:
                spawner.api.create_namespaced_secret(NAMESPACE, secret_data)
        except ApiException as e:
            # FIXME: Exception message should be c.SpawnHandlersConfigs.spawn_error_message and the exception should be only logged
            raise Exception("Could not create required user secret: %s\n" % e)

        pod.spec.volumes.append(
            # V1Secret for tokens without adjusted permissions
            client.V1Volume(
                name=user_tokens_secret,
                secret=client.V1SecretVolumeSource(
                    secret_name=user_tokens_secret,
                    items=[
                        client.V1KeyToPath(
                            key=USER_TOKENS_SECRET_KEY,
                            path='krb5cc'
                        )
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
            )
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
LDAP_URI = os.environ['LDAP_URI']
LDAP_PORT = os.environ['LDAP_PORT']
LDAP_BASE_DN = os.environ['LDAP_BASE_DN']

NAMESPACE = os.environ['PODINFO_NAMESPACE']

SWAN_CONTAINER_NAME = 'notebook'
SWAN_CONTAINER_NAMSPACE = 'swan'
USER_TOKENS_SECRET_PREFIX = 'user-tokens-'
USER_TOKENS_SECRET_KEY = 'eosToken'

c = get_config()

"""
Configuration for JupyterHub - general
"""

# JupyterHub runtime configuration
jupyterhub_runtime_dir = '/srv/jupyterhub/jupyterhub_data/'
os.makedirs(jupyterhub_runtime_dir, exist_ok=True)
c.JupyterHub.cookie_secret_file = os.path.join(jupyterhub_runtime_dir, 'cookie_secret')
c.JupyterHub.db_url = os.path.join(jupyterhub_runtime_dir, 'jupyterhub.sqlite')

# Resume previous state if the Hub fails
c.JupyterHub.cleanup_proxy = True  # Kill the proxy if the hub fails
c.JupyterHub.cleanup_servers = False  # Do not kill single-user's servers (SQLite DB must be on persistent storage)

# Add SWAN look&feel
c.JupyterHub.template_paths = ['/srv/jupyterhub/jh_gitlab/templates']
c.JupyterHub.logo_file = '/usr/local/share/jupyterhub/static/swan/logos/logo_swan_cloudhisto.png'

# Reach the Hub from outside
c.JupyterHub.ip = "0.0.0.0"  # Listen on all IPs for HTTP traffic when in Kubernetes
c.JupyterHub.port = 8000  # You may end up in detecting the wrong IP address due to:

c.JupyterHub.cleanup_servers = False

c.JupyterHub.services = [
    {
        'name': 'cull-idle',
        'admin': True,
        'command': [
            'python3', '/srv/jupyterhub/jh_gitlab/scripts/cull_idle_servers.py',
            '--cull_every=600',
            '--timeout=14400',
            '--cull_users=True',
            '--local_home=False', # make sure to call check_ticket.sh and delete_ticket.sh scripts
            '--culler_dir=/srv/jupyterhub/culler' # path with check_ticket.sh and delete_ticket.sh scripts
        ],
    }
]

# Reach the Hub from Jupyter containers
# NOTE: The Hub IP must be known and rechable from spawned containers
# 	Leveraging on the FQDN makes the Hub accessible both when the JupyterHub Pod
#	uses the Kubernetes overlay network and the host network
try:
    hub_ip = socket.gethostbyname(socket.getfqdn())
except:
    print ("WARNING: Unable to identify iface IP from FQDN")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    hub_ip = s.getsockname()[0]
hub_port = 8080
c.JupyterHub.hub_ip = hub_ip
c.JupyterHub.hub_port = hub_port
c.KubeSpawner.hub_connect_ip = hub_ip
c.KubeSpawner.hub_connect_port = hub_port

# Proxy
# Wrap the start of the proxy to allow bigger headers in nodejs
c.ConfigurableHTTPProxy.command = '/srv/jupyterhub/jh_gitlab/scripts/start_proxy.sh'

# Load the list of users with admin privileges and enable access
admins = set(open(os.path.join(os.path.dirname(__file__), 'adminslist'), 'r').read().splitlines())
c.Authenticator.admin_users = admins
c.JupyterHub.admin_access = True

"""
Configuration for JupyterHub - user authentication
"""

if (os.environ['AUTH_TYPE'] == "shibboleth"):
    print ("Authenticator: Using user-defined authenticator")
    c.JupyterHub.authenticator_class = '%%%SHIBBOLETH_AUTHENTICATOR_CLASS%%%'
    # %%% Additional SHIBBOLETH_AUTHENTICATOR_CLASS parameters here %%% #

elif (os.environ['AUTH_TYPE'] == "local"):
    print ("Authenticator: Using LDAP")
    c.JupyterHub.authenticator_class = 'ldapauthenticator.LDAPAuthenticator'
    c.LDAPAuthenticator.server_address = LDAP_URI
    c.LDAPAuthenticator.use_ssl = False
    c.LDAPAuthenticator.server_port = int(LDAP_PORT)
    if (LDAP_URI[0:8] == "ldaps://"):
        c.LDAPAuthenticator.use_ssl = True
    c.LDAPAuthenticator.bind_dn_template = 'uid={username},' + LDAP_BASE_DN

else:
    print ("ERROR: Authentication type not specified.")
    print ("Cannot start JupyterHub.")

"""
Configuration for JupyterHub - single-user container customization
"""

# Spawn single-user's servers in the Kubernetes cluster
c.JupyterHub.spawner_class = 'swanspawner.SwanKubeSpawner'
c.SwanSpawner.image = "gitlab-registry.cern.ch/swan/docker-images/systemuser:v5.1.1"
c.SwanSpawner.image_pull_policy = 'IfNotPresent'
c.SwanSpawner.options_form = '/srv/jupyterhub/jupyterhub_form.html'
c.SwanSpawner.start_timeout = 90
c.SwanSpawner.namespace = NAMESPACE

c.SpawnHandlersConfigs.metrics_on = False

c.SpawnHandlersConfigs.spawn_error_message = """SWAN could not start a session for your user, please try again. If the problem persists, please check:
<ul>
    <li>Do you have a CERNBox account? If not, click <a href="https://cernbox.cern.ch" target="_blank">here</a>.</li>
    <li>Is there a problem with the service? Find information <a href="https://cern.service-now.com/service-portal/ssb.do" target="_blank">here</a>.</li>
    <li>If none of the options apply, please open a <a href="https://cern.service-now.com/service-portal/function.do?name=swan" target="_blank">Support Ticket</a>.</li>
</ul>"""

c.SwanSpawner.volume_mounts = [
    {
        'name': 'eos',
        'mountPath': '/eos',
        'mountPropagation': 'HostToContainer',
    },
    {
        'name': 'cvmfs-sft-cern-ch',
        'mountPath': '/cvmfs/sft.cern.ch',
        'readOnly': True
    }
]

c.SwanSpawner.volumes = [
    {
        'name': 'eos',
        'hostPath': {
            'path': '/var/eos'
        }
    },
    {
        'name': 'cvmfs-sft-cern-ch',
        'persistentVolumeClaim': {
            'claimName': 'cvmfs-sft-cern-ch-pvc'
        }
    },
]

c.SwanSpawner.port = 8888
c.SwanSpawner.spark_ports_per_pod = 6

c.SwanSpawner.extra_container_config = {
    'name': SWAN_CONTAINER_NAME
}

# https://jupyterhub-kubespawner.readthedocs.io/en/latest/spawner.html
c.SwanSpawner.modify_pod_hook = PodHookHandler.modify_pod_hook
