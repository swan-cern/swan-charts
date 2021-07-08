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
SWAN_SECRET_VALUES_PATH=/srv/swan-k8s/private/swan.$SWAN_ENV.secrets.yaml

# secret files
EOS_AUTH_KEYTAB_PATH=/srv/swan-k8s/private/constrdt.keytab
EOS_AUTH_KEYTAB_ENCODED=$(base64 -w 0 $EOS_AUTH_KEYTAB_PATH)
HADOOP_AUTH_KEYTAB_PATH=/srv/swan-k8s/private/hswan.keytab
HADOOP_AUTH_KEYTAB_ENCODED=$(base64 -w 0 $HADOOP_AUTH_KEYTAB_PATH)
SPARKK8S_AUTH_TOKEN_PATH=/srv/swan-k8s/private/sparkk8s.kubeconfig
SPARKK8S_AUTH_TOKEN_ENCODED=$(base64 -w 0 $SPARKK8S_AUTH_TOKEN_PATH)


echo ""
echo "Build chart dependencies"
echo ""

helm repo add swan https://registry.cern.ch/chartrepo/swan
helm repo add cern http://registry.cern.ch/chartrepo/cern
helm repo add eos https://registry.cern.ch/chartrepo/eos
helm repo add sciencebox https://registry.cern.ch/chartrepo/sciencebox
helm repo add jupyterhub https://jupyterhub.github.io/helm-chart/

# TODO remove this once we push this to Harbor
( cd $ROOT_DIR/swan && helm dependency build )
( cd $ROOT_DIR/swan-cern && helm dependency build )


echo ""
echo "Updating swan env ${SWAN_ENV}, upgrade db ${UPGRADE_DB}"
echo ""

# Annotation is required in order to restart jupyterhub server on swan_config.py or jupyterhub_form.html changes
helm upgrade --install --namespace swan  \
--values $SWAN_SECRET_VALUES_PATH \
--set jupyterhub.hub.annotations.version="release-$(date +%s)" \
--set jupyterhub.hub.db.upgrade=$UPGRADE_DB \
--set swanCern.secrets.hadoop.cred=$HADOOP_AUTH_KEYTAB_ENCODED \
--set swanCern.secrets.eos.cred=$EOS_AUTH_KEYTAB_ENCODED \
--set swanCern.secrets.sparkk8s.cred=$SPARKK8S_AUTH_TOKEN_ENCODED \
$SWAN_PROD_RELEASE_NAME $ROOT_DIR/swan-cern

if [[ $? -ne 0 ]]
then
    echo "failed"
    exit 1
fi
