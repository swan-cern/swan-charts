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

    cull_cmd = ["swanculler"]
    base_url = c.JupyterHub.get("base_url", "/")
    cull_cmd.append("--url=http://localhost:8081" + url_path_join(base_url, "hub/api"))

    cull_timeout = get_config("custom.cull.timeout")
    if cull_timeout:
        cull_cmd.append("--timeout=%s" % cull_timeout)

    cull_every = get_config("custom.cull.every")
    if cull_every:
        cull_cmd.append("--cull-every=%s" % cull_every)

    if get_config("custom.cull.users"):
        cull_cmd.append("--cull-users=True")
        swan_idle_culler_role["scopes"].append("admin:users")

    if get_config("custom.cull.removeNamedServers"):
        cull_cmd.append("--remove-named-servers")

    cull_max_age = get_config("custom.cull.maxAge")
    if cull_max_age:
        cull_cmd.append("--max-age=%s" % cull_max_age)

    check_eos = get_config('custom.cull.checkEosAuth', False)
    if not check_eos:
        cull_cmd.append("--disable-hooks=True")

    hooks_dir = get_config('custom.cull.hooksDir')
    if hooks_dir:
        cull_cmd.append(f"--hooks-dir={hooks_dir}")

    audience = get_config('custom.cull.audience')
    if audience:
        cull_cmd.append(f"--audience={audience}")

    auth_url = get_config('custom.cull.auth_url')
    if auth_url:
        cull_cmd.append(f"--auth_url={auth_url}")

    authz_api_url = get_config('custom.cull.authz_api_url')
    if authz_api_url:
        cull_cmd.append(f"--authz_api_url={authz_api_url}")

    auth_check_interval = get_config('custom.cull.auth_check_interval')
    if auth_check_interval:
        cull_cmd.append("--auth_check_interval=%s" % auth_check_interval)

    c.JupyterHub.services.append(
        {
            "name": "swan-idle-culler",
            "admin": True,
            "command": cull_cmd,
            "environment": {
                'SWAN_DEV': os.environ.get('SWAN_DEV', 'false'),
                'AUTH_CLIENT_ID': c.KeyCloakAuthenticator.client_id,
                'AUTH_CLIENT_SECRET': c.KeyCloakAuthenticator.client_secret,
            }
        }
    )
    c.JupyterHub.load_roles.append(swan_idle_culler_role)

c.SwanKubeSpawner.cull_period = get_config('custom.cull.every', 600)
c.SwanKubeSpawner.tn_enabled = get_config('hub.config.SpawnHandlersConfigs.tn_enabled', False)
c.SwanKubeSpawner.spark_configuration_path = get_config('custom.spark.configurationPath')
# Get configuration parameters from environment variables
c.SwanKubeSpawner.swan_container_namespace = os.environ.get('POD_NAMESPACE', 'default')

c.SwanKubeSpawner.modify_pod_hook = swan_pod_hook_prod

# Required for swan systemuser.sh
c.SwanKubeSpawner.cmd = None
