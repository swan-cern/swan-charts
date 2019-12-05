set -e

ROOT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )"; pwd;)

SWAN_ENV=$1

AVAILABLE_SWAN_ENV=" prod qa "
if ! [[ -n "${1}" && " ${AVAILABLE_SWAN_ENV[@]} " =~ " ${1} " ]]; then
    echo "ERROR: ${1} is not available swan deployment environment"
	exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
    echo "ERROR: Cannot proceed as repository has not commited changes"
    exit 1
fi

# allow to deploy to prod only from master
if [[ $SWAN_ENV == "prod" && $(git symbolic-ref -q HEAD) != "refs/heads/master" ]]; then
    echo "ERROR: Cannot deploy prod environment on branch other than master"
    exit 1
fi

# kubernetes access based on environment
export KUBECONFIG=/srv/swan-k8s/private/swan.$SWAN_ENV.kubeconfig

# values and secrets based on environment
SWAN_PROD_RELEASE_NAME=swan
SWAN_PROD_VALUES_PATH=$ROOT_DIR/swan-upstream-chart/swan.$SWAN_ENV.values.yaml
SWAN_SECRET_VALUES_PATH=/srv/swan-k8s/private/swan.$SWAN_ENV.secrets.yaml

# secret files
EOS_AUTH_KEYTAB_PATH=/srv/jupyterhub/private/constrdt.keytab
EOS_AUTH_KEYTAB_ENCODED=$(base64 -w 0 $EOS_AUTH_KEYTAB_PATH)
HADOOP_AUTH_KEYTAB_PATH=/srv/jupyterhub/private/hadoop.keytab
HADOOP_AUTH_KEYTAB_ENCODED=$(base64 -w 0 $HADOOP_AUTH_KEYTAB_PATH)
SPARKK8S_AUTH_TOKEN_PATH=/srv/swan-k8s/private/sparkk8s.kubeconfig
SPARKK8S_AUTH_TOKEN_ENCODED=$(base64 -w 0 $SPARKK8S_AUTH_TOKEN_PATH)

helm upgrade --install --namespace kube-system  \
eosxd $ROOT_DIR/swan-eosxd-config-chart

helm upgrade --install --namespace swan  \
--values $SWAN_PROD_VALUES_PATH \
--values $SWAN_SECRET_VALUES_PATH \
--set jupyterhub.hub.annotations.version="release-$(date +%s)" \
--set swan.secrets.hadoop.cred=$HADOOP_AUTH_KEYTAB_ENCODED \
--set swan.secrets.eos.cred=$EOS_AUTH_KEYTAB_ENCODED \
--set swan.secrets.sparkk8s.cred=$SPARKK8S_AUTH_TOKEN_ENCODED \
$SWAN_PROD_RELEASE_NAME $ROOT_DIR/swan-upstream-chart


