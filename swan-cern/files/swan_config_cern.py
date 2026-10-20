import os

from swanspawner.podhookhandler import SwanSparkCondorPodHookHandler


# https://jupyterhub-kubespawner.readthedocs.io/en/latest/spawner.html
# This is defined in the configuration to allow overriding independently
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


def build_service_cmd(script, *flags, flag_from_config):
    cmd = [script, *flags]
    for flag, config_key in flag_from_config.items():
        if value := get_config(config_key):
            cmd.append(f"{flag}={value}")
    return cmd


# Ticket refresh
if get_config("custom.ticketRefresher.enabled", False):
    ticket_refresher_role = {
        "name": "swan-ticket-refresher",
        "scopes": [
            "list:users",
            "read:servers",
        ],
        "services": ["swan-ticket-refresher"],
    }

    base_url = c.JupyterHub.get("base_url", "/")
    cmd = build_service_cmd(
        "swanticketrefresher",
        f"--url=http://localhost:8081{url_path_join(base_url, 'hub/api')}",
        flag_from_config={
            "--every": "custom.ticketRefresher.every",
            "--hooks-dir": "custom.ticketRefresher.hooksDir",
        },
    )

    c.JupyterHub.services.append(
        {
            "name": "swan-ticket-refresher",
            "command": cmd,
        }
    )
    c.JupyterHub.load_roles.append(ticket_refresher_role)

# Blocked users
if get_config("custom.blockedUsersCuller.enabled", False):
    swan_blocked_users_role = {
        "name": "swan-blocked-users-culler",
        "scopes": [
            "list:users",
            "read:users:activity",
            "read:servers",
            "delete:servers",
            "admin:users",
        ],
        "services": ["swan-blocked-users-culler"],
    }

    base_url = c.JupyterHub.get("base_url", "/")
    cmd = build_service_cmd(
        "swanblockedusersculler",
        f"--url=http://localhost:8081{url_path_join(base_url, 'hub/api')}",
        flag_from_config={
            "--audience": "custom.blockedUsersCuller.audience",
            "--auth-url": "custom.blockedUsersCuller.auth_url",
            "--authz-api-url": "custom.blockedUsersCuller.authz_api_url",
            "--auth-check-interval": "custom.blockedUsersCuller.auth_check_interval",
        },
    )

    c.JupyterHub.services.append(
        {
            "name": "swan-blocked-users-culler",
            "admin": True,  # required for jupyterhub < 2.0 to delete users
            "command": cmd,
            "environment": {
                "SWAN_DEV": os.environ.get("SWAN_DEV", "false"),
                "AUTH_CLIENT_ID": c.KeyCloakAuthenticator.client_id,
                "AUTH_CLIENT_SECRET": c.KeyCloakAuthenticator.client_secret,
            },
        }
    )
    c.JupyterHub.load_roles.append(swan_blocked_users_role)

c.SwanKubeSpawner.token_refresh_period = get_config("custom.cull.every", 600)
c.SwanKubeSpawner.tn_enabled = get_config("hub.config.SpawnHandlersConfigs.tn_enabled", False)
c.SwanKubeSpawner.spark_configuration_path = get_config("custom.spark.configurationPath")
# Get configuration parameters from environment variables
c.SwanKubeSpawner.swan_container_namespace = os.environ.get("POD_NAMESPACE", "default")

c.SwanKubeSpawner.modify_pod_hook = swan_pod_hook_prod
