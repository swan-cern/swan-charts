import os

from swanspawner.podhookhandler import SwanSparkCondorPodHookHandler


# https://jupyterhub-kubespawner.readthedocs.io/en/latest/spawner.html
# This is defined in the configuration to allow overring independently
# of which config file is loaded first
# c.SwanKubeSpawner.modify_pod_hook = swan_pod_hook
async def swan_pod_hook_prod(spawner, pod):
    """
    :param spawner: Swan Kubernetes Spawner
    :type spawner: swanspawner.swankubespawner.SwanKubeSpawner
    :param pod: default pod definition set by jupyterhub
    :type pod: V1Pod

    :returns: dynamically customized pod specification for user session
    :rtype: V1Pod
    """
    pod_hook_handler = SwanSparkCondorPodHookHandler(spawner, pod)
    return await pod_hook_handler.get_swan_user_pod()


"""
Configuration for JupyterHub
"""
# Culling of users and ticket refresh
if get_config("custom.cull.enabled", False):
    swan_idle_culler_role = {
        "name": "swan-idle-culler",
        "scopes": [
            "list:users",
            "read:users:activity",
            "read:servers",
            "delete:servers",
            # "admin:users", # dynamically added if --cull-users is passed
        ],
        # assign the role to a jupyterhub service, so it gains these permissions
        "services": ["swan-idle-culler"],
    }

    base_url = c.JupyterHub.get("base_url", "/")
    cull_cmd = ["swanculler", f"--url=http://localhost:8081{url_path_join(base_url, 'hub/api')}"]

    cull_value_flags = {
        "--timeout": "custom.cull.timeout",
        "--cull-every": "custom.cull.every",
        "--max-age": "custom.cull.maxAge",
        "--hooks-dir": "custom.cull.hooksDir",
        "--audience": "custom.cull.audience",
        "--auth-url": "custom.cull.auth_url",
        "--authz-api-url": "custom.cull.authz_api_url",
        "--auth-check-interval": "custom.cull.auth_check_interval",
    }
    for flag, config_key in cull_value_flags.items():
        if value := get_config(config_key):
            cull_cmd.append(f"{flag}={value}")

    if get_config("custom.cull.users"):
        cull_cmd.append("--cull-users=True")
        swan_idle_culler_role["scopes"].append("admin:users")

    if not get_config("custom.cull.checkEosAuth", False):
        cull_cmd.append("--disable-hooks=True")

    c.JupyterHub.services.append(
        {
            "name": "swan-idle-culler",
            "admin": True,
            "command": cull_cmd,
            "environment": {
                "SWAN_DEV": os.environ.get("SWAN_DEV", "false"),
                "AUTH_CLIENT_ID": c.KeyCloakAuthenticator.client_id,
                "AUTH_CLIENT_SECRET": c.KeyCloakAuthenticator.client_secret,
            },
        }
    )
    c.JupyterHub.load_roles.append(swan_idle_culler_role)

c.SwanKubeSpawner.cull_period = get_config("custom.cull.every", 600)
c.SwanKubeSpawner.tn_enabled = get_config("hub.config.SpawnHandlersConfigs.tn_enabled", False)
c.SwanKubeSpawner.spark_configuration_path = get_config("custom.spark.configurationPath")
# Get configuration parameters from environment variables
c.SwanKubeSpawner.swan_container_namespace = os.environ.get("POD_NAMESPACE", "default")

c.SwanKubeSpawner.modify_pod_hook = swan_pod_hook_prod
