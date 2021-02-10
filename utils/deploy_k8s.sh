ROOT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.."; pwd;)

echo "# USAGE: ${ROOT_DIR}/utils/deploy_k8s.sh --env <qa/prod> (--upgrade-db)"
echo ""

SWAN_ENV=""
UPGRADE_DB="false"

while [[ "$#" -gt 0 ]]; do case $1 in
  --env) SWAN_ENV="$2"; shift;;
  --upgrade-db) UPGRADE_DB="true";;
  *) echo "Unknown parameter passed: $1"; exit 1;;
esac; shift; done

AVAILABLE_SWAN_ENV=" prod qa"
if ! [[ -n "${SWAN_ENV}" && " ${AVAILABLE_SWAN_ENV[@]} " =~ " ${SWAN_ENV} " ]]; then
    echo "ERROR: ${SWAN_ENV} is not available swan deployment environment"
    exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
    echo "ERROR: Cannot proceed as repository has not commited changes"
    exit 1
fi

if [ "${SWAN_ENV}" == 'qa' ] && [ $(git rev-parse --abbrev-ref HEAD) != 'qa' ]; then
    echo "ERROR: ${SWAN_ENV} can be deployed from qa branch"
    exit 1
fi  

if [ "${SWAN_ENV}" == 'prod' ] && [ $(git rev-parse --abbrev-ref HEAD) != 'master' ]; then
    echo "ERROR: ${SWAN_ENV} can be deployed from master branch"
    exit 1
fi

# kubernetes access based on environment
export KUBECONFIG=/srv/swan-k8s/private/swan.$SWAN_ENV.kubeconfig

# values and secrets based on environment
SWAN_PROD_RELEASE_NAME=swan
SWAN_PROD_VALUES_PATH=$ROOT_DIR/swan-upstream-chart/swan.values.yaml
SWAN_SECRET_VALUES_PATH=/srv/swan-k8s/private/swan.$SWAN_ENV.secrets.yaml

# secret files
EOS_AUTH_KEYTAB_PATH=/srv/swan-k8s/private/constrdt.keytab
EOS_AUTH_KEYTAB_ENCODED=$(base64 -w 0 $EOS_AUTH_KEYTAB_PATH)
HADOOP_AUTH_KEYTAB_PATH=/srv/swan-k8s/private/hswan.keytab
HADOOP_AUTH_KEYTAB_ENCODED=$(base64 -w 0 $HADOOP_AUTH_KEYTAB_PATH)
SPARKK8S_AUTH_TOKEN_PATH=/srv/swan-k8s/private/sparkk8s.kubeconfig
SPARKK8S_AUTH_TOKEN_ENCODED=$(base64 -w 0 $SPARKK8S_AUTH_TOKEN_PATH)

echo ""
echo "Updating eosxd"
echo ""

helm3 upgrade --install --namespace kube-system --disable-openapi-validation  \
eosxd $ROOT_DIR/swan-eosxd-config-chart

if [[ $? -ne 0 ]]
then
    echo "failed"
    exit 1
fi

echo ""
echo "Updating fluentd"
echo ""

helm3 upgrade --install --namespace kube-system  \
fluentd $ROOT_DIR/swan-fluentd-config-chart

if [[ $? -ne 0 ]]
then
    echo "failed"
    exit 1
fi

echo ""
echo "Updating cvmfs"
echo ""

helm3 upgrade --install --namespace kube-system  \
cvmfs $ROOT_DIR/swan-cvmfs-config-chart

if [[ $? -ne 0 ]]
then
    echo "failed"
    exit 1
fi

echo ""
echo "Updating swan env ${SWAN_ENV}, upgrade db ${UPGRADE_DB}"
echo ""

# Annotation is required in order to restart jupyterhub server on swan_config.py or jupyterhub_form.html changes
helm3 upgrade --install --namespace swan  \
--values $SWAN_PROD_VALUES_PATH \
--values $SWAN_SECRET_VALUES_PATH \
--set jupyterhub.hub.annotations.version="release-$(date +%s)" \
--set jupyterhub.hub.db.upgrade=$UPGRADE_DB \
--set swan.secrets.hadoop.cred=$HADOOP_AUTH_KEYTAB_ENCODED \
--set swan.secrets.eos.cred=$EOS_AUTH_KEYTAB_ENCODED \
--set swan.secrets.sparkk8s.cred=$SPARKK8S_AUTH_TOKEN_ENCODED \
$SWAN_PROD_RELEASE_NAME $ROOT_DIR/swan-upstream-chart

if [[ $? -ne 0 ]]
then
    echo "failed"
    exit 1
fi
