ROOT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )"; pwd;)

SWAN_ENV=""

while [[ "$#" -gt 0 ]]; do case $1 in
  --env) SWAN_ENV="$2"; shift;;
  *) echo "Unknown parameter passed: $1"; exit 1;;
esac; shift; done

AVAILABLE_SWAN_ENV=" prod qa "
if [[ -n "${SWAN_ENV}" && " ${AVAILABLE_SWAN_ENV[@]} " =~ " ${SWAN_ENV} " ]]; then
    # kubernetes access based on environment
    export KUBECONFIG=/srv/swan-k8s/private/swan.$SWAN_ENV.kubeconfig

    kubectl cluster-info
    kubectl get pods --all-namespaces | grep hub

    echo "Configured env $SWAN_ENV"
else
    echo "ERROR: ${SWAN_ENV} is not available swan deployment environment"
fi

