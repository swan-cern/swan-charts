###
# Remember to authorize the pod where JupyterHub runs to access the API
# of the cluster and to list pods in the namespace
#
# As temporary workaround:
# kubectl create clusterrolebinding add-on-cluster-admin --clusterrole=cluster-admin --serviceaccount=boxed:default
###

# Configuration file for JupyterHub
import os
import pwd
import socket
import subprocess
from kubernetes import client
from kubernetes.client.rest import ApiException

### VARIABLES ###
# Get configuration parameters from environment variables
CVMFS_FOLDER = os.environ['CVMFS_FOLDER']
EOS_USER_PATH = os.environ['EOS_USER_PATH']
CONTAINER_IMAGE = os.environ['CONTAINER_IMAGE']
LDAP_URI = os.environ['LDAP_URI']
LDAP_PORT = os.environ['LDAP_PORT']
LDAP_BASE_DN = os.environ['LDAP_BASE_DN']
NAMESPACE = os.environ['PODINFO_NAMESPACE']
SERVER_HOSTNAME = os.environ['PODINFO_NODE_NAME']

c = get_config()

### Configuration for JupyterHub ###
# JupyterHub runtime configuration
jupyterhub_runtime_dir = '/srv/jupyterhub/jupyterhub_data/'
os.makedirs(jupyterhub_runtime_dir, exist_ok=True)
c.JupyterHub.cookie_secret_file = os.path.join(jupyterhub_runtime_dir, 'cookie_secret')
c.JupyterHub.db_url = os.path.join(jupyterhub_runtime_dir, 'jupyterhub.sqlite')

# Resume previous state if the Hub fails
c.JupyterHub.cleanup_proxy = True  # Kill the proxy if the hub fails
c.JupyterHub.cleanup_servers = False  # Do not kill single-user's servers (SQLite DB must be on persistent storage)

# Logging
c.JupyterHub.log_level = 'DEBUG'
c.Spawner.debug = True
c.LocalProcessSpawner.debug = True

# Add SWAN look&feel
c.JupyterHub.template_paths = ['/srv/jupyterhub/jh_gitlab/templates']
c.JupyterHub.logo_file = '/usr/local/share/jupyterhub/static/swan/logos/logo_swan_cloudhisto.png'

# Reach the Hub from outside
c.JupyterHub.ip = "0.0.0.0"  # Listen on all IPs for HTTP traffic when in Kubernetes
c.JupyterHub.port = 8000  # You may end up in detecting the wrong IP address due to:
#       - Kubernetes services in front of Pods (headed//headless//clusterIPs)
#       - hostNetwork used by the JupyterHub Pod

c.JupyterHub.cleanup_servers = False
# Use local_home set to true to prevent calling the script that updates EOS tickets
c.JupyterHub.services = [
    {
        'name': 'cull-idle',
        'admin': True,
        'command': 'python3 /srv/jupyterhub/jh_gitlab/scripts/cull_idle_servers.py --cull_every=600 --timeout=14400 --local_home=True --cull_users=True'.split(),
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

### User Authentication ###
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

### Configuration for single-user containers ###
# c.KubeSpawner.image_pull_policy = 'Always'
# Spawn single-user's servers in the Kubernetes cluster
c.JupyterHub.spawner_class = 'swanspawner.SwanKubeSpawner'
c.SwanSpawner.image = CONTAINER_IMAGE
c.SwanSpawner.namespace = NAMESPACE
c.SwanSpawner.options_form = '/srv/jupyterhub/jupyterhub_form.html'
c.SwanSpawner.start_timeout = 90

# Single-user's servers extra config, CVMFS, EOS
c.SwanSpawner.local_home = False  # $HOME is on EOS
c.SwanSpawner.eos_path_prefix = EOS_USER_PATH

c.SwanSpawner.available_cores = ["1", "2"]
c.SwanSpawner.available_memory = ["2", "4"]
c.SwanSpawner.check_cvmfs_status = False  # For now it only checks if available in same place as Jupyterhub.

# local_home equal to true to hide the "always start with this config"
c.SpawnHandlersConfigs.local_home = True
c.SpawnHandlersConfigs.metrics_on = False  # For now the metrics are hardcoded for CERN
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
    },
    {
        'name': 'tmp-volume',
        'mountPath': '/tmp',
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
    {
        'name': 'tmp-volume',
        'emptyDir': {}
    }
]

c.SwanSpawner.port = 8888

c.SwanSpawner.spark_ports_per_pod = 6


def modify_pod_hook_call(spawner, pod):
    """
    :param spawner: todo
    :type spawner: kubespawner.KubeSpawner
    :param pod: todo
    :type pod: client.V1Pod
    :returns: todo
    :rtype: client.V1Pod
    """

    username = spawner.user.name
    user_tokens_secret = "user-tokens" + "-" + username
    spark_ports_service = "spark-ports" + "-" + username
    pod_label = {'swan': username}
    notebook_container = pod.spec.containers[0]

    # Add pod label for service selector
    pod.metadata.labels.update(
        pod_label
    )

    def append_or_replace_by_name(list, element):
        found = False
        for list_index in range(0, len(list)):
            spawner.log.warning(list[list_index])
            if list[list_index].to_dict().get("name") == element.to_dict().get("name"):
                list[list_index] = element
                found = True
                break

        if not found:
            list.append(element)

        return list

    def create_notebook_ports():
        # TODO: ports can be probably moved to kubespawner as this is infrastructure independent
        # FIXME: this might be needed in case hadoop-yarn 2.8.0 webapp still crashes on ApplicationProxy UI
        # pod.spec.host_network = True

        try:
            spark_ports_env = []

            # Allocate some 6 random NodePorts on the cluster for spark
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
                    selector=pod_label,  # attach this service to the pod with label {pod_label}
                    ports=service_template_ports,
                    type="NodePort"
                )
            )

            try:
                # use existing if possible
                service = spawner.api.read_namespaced_service(spark_ports_service, NAMESPACE)
            except ApiException:
                # not existing, create
                service = spawner.api.create_namespaced_service(NAMESPACE, service_template)

            for port_id in range(len(service.spec.ports)):
                # Adjust the service to map nodeport:targetport
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
                notebook_container.ports = append_or_replace_by_name(
                    notebook_container.ports,
                    client.V1ContainerPort(
                        name=name,
                        container_port=node_port
                    )
                )
            spawner.api.replace_namespaced_service(spark_ports_service, NAMESPACE, service)

            # Add ports env for spark
            notebook_container.env = append_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='SPARK_PORTS',
                    value=','.join(spark_ports_env)
                )
            )
            notebook_container.env = append_or_replace_by_name(
                notebook_container.env,
                client.V1EnvVar(
                    name='SERVER_HOSTNAME',
                    value=SERVER_HOSTNAME
                )
            )
        except ApiException as e:
            raise Exception("Could not create required user ports: %s\n" % e)

    def create_swan_secrets():
        # Create eos token
        try:
            eos_token_base64 = subprocess.check_output(
                ['sudo', '/srv/jupyterhub/private/eos-token.sh', username], timeout=60
            ).decode('ascii')
        except Exception:
            raise Exception("Could not create required user credential\n")

        # Create V1Secret with eos token
        try:
            secret_data = client.V1Secret()

            secret_meta = client.V1ObjectMeta()
            secret_meta.name = user_tokens_secret
            secret_meta.namespace = NAMESPACE
            secret_data.metadata = secret_meta
            secret_data.data = {}
            secret_data.data['eosToken'] = eos_token_base64

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
            raise Exception("Could not create required user secret: %s\n" % e)

        # Allocate V1 Secret volume to pod exlusivelly
        pod.spec.volumes.append(
            {
                'name': user_tokens_secret,
                'secret': {
                    'secretName': user_tokens_secret,
                    'items': [
                        {
                            'key': 'eosToken',
                            'path': 'krb5cc',
                        }
                    ],
                }
            }
        )

        # Start side container which currently:
        #  - refreshes the kerberos token
        side_container = {
            "name": "side-ontainer",
            "image": "busybox",
            "command": [
                "/bin/sh", "-c",
                "while true; do " +
                "cp /secrets/krb5cc /krb5cc_tmp; chmod 400 /krb5cc_tmp; chown $USER_ID:$USER_GID /krb5cc_tmp; mv /krb5cc_tmp /tmp/krb5cc_$USER_ID; sleep 60; " +
                "done;"
            ],
            "env": [
                {
                    "name": "USER_ID",
                    "value": str(pwd.getpwnam(username).pw_uid)
                },
                {
                    "name": "USER_GID",
                    "value": str(pwd.getpwnam(username).pw_gid)
                }
            ],
            "volumeMounts": [
                {
                    'name': user_tokens_secret,
                    'mountPath': '/secrets/',
                },
                {
                    'name': 'tmp-volume',
                    'mountPath': '/tmp',
                }
            ]
        }

        pod.spec.containers = [
            side_container,  # start first
            notebook_container  # start second
        ]

    create_notebook_ports()
    create_swan_secrets()

    return pod


c.SwanSpawner.modify_pod_hook = modify_pod_hook_call

