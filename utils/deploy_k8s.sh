ROOT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.."; pwd;)

echo "# USAGE: ${ROOT_DIR}/utils/deploy_k8s.sh --env <qa/prod> (--options-form <path to releases json>) (--upgrade-db) (--no-clean-repo)"
echo ""

SWAN_ENV=""
UPGRADE_DB="false"
CLEAN_REPO=true
OPTIONS_FORM="swan-cern/options_form_config.json"

while [[ "$#" -gt 0 ]]; do case $1 in
  --env) SWAN_ENV="$2"; shift;;
  --options-form) OPTIONS_FORM="$2"; shift;;
  --upgrade-db) UPGRADE_DB="true";;
  --no-clean-repo) CLEAN_REPO=false;;
  *) echo "Unknown parameter passed: $1"; exit 1;;
esac; shift; done

AVAILABLE_SWAN_ENV=" prod qa"
if ! [[ -n "${SWAN_ENV}" && " ${AVAILABLE_SWAN_ENV[@]} " =~ " ${SWAN_ENV} " ]]; then
    echo "ERROR: ${SWAN_ENV} is not available swan deployment environment"
    exit 1
fi

if [ "$CLEAN_REPO" = true -a -n "$(git status --porcelain)" ]; then
    echo "ERROR: Cannot proceed as repository has not commited changes"
    exit 1
fi

if [ ! -f "$OPTIONS_FORM" ]; then
    echo "ERROR: the path you provided for the configuration options form does not exist"
    exit 1
fi

# kubernetes access 
KUBECONFIG=$(mktemp -p .)
tbag show --hg swan --file $KUBECONFIG swan_${SWAN_ENV}_k8s_kubeconfig
trap "rm -f $KUBECONFIG" EXIT

# values and secrets
SWAN_SECRET_VALUES_PATH=$(mktemp -p .)
tbag show --hg swan --file $SWAN_SECRET_VALUES_PATH swan_${SWAN_ENV}_k8s_secrets_yaml
trap "rm -f $SWAN_SECRET_VALUES_PATH" EXIT

# secret files
EOS_AUTH_KEYTAB_PATH=$(mktemp -p .)
tbag show --hg swan --file $EOS_AUTH_KEYTAB_PATH constrdt
EOS_AUTH_KEYTAB_ENCODED=$(base64 -w 0 $EOS_AUTH_KEYTAB_PATH)
trap "rm -f $EOS_AUTH_KEYTAB_PATH" EXIT
rm -f $EOS_AUTH_KEYTAB_PATH


HADOOP_AUTH_KEYTAB_PATH=$(mktemp -p .)
tbag show --hg swan --file $HADOOP_AUTH_KEYTAB_PATH hswan
HADOOP_AUTH_KEYTAB_ENCODED=$(base64 -w 0 $HADOOP_AUTH_KEYTAB_PATH)
trap "rm -f $HADOOP_AUTH_KEYTAB_PATH" EXIT
rm -f $HADOOP_AUTH_KEYTAB_PATH

SPARKK8S_AUTH_TOKEN_PATH=$(mktemp -p .)
tbag show --hg swan --file $SPARKK8S_AUTH_TOKEN_PATH spark_k8s_kubeconfig
SPARKK8S_AUTH_TOKEN_ENCODED=$(base64 -w 0 $SPARKK8S_AUTH_TOKEN_PATH)
trap "rm -f $SPARKK8S_AUTH_TOKEN_PATH" EXIT
rm -rf $SPARKK8S_AUTH_TOKEN_PATH

echo ""
echo "Build chart dependencies"
echo ""

helm repo add swan https://registry.cern.ch/chartrepo/swan
helm repo add cern http://registry.cern.ch/chartrepo/cern
helm repo add eos https://registry.cern.ch/chartrepo/eos
helm repo add sciencebox https://registry.cern.ch/chartrepo/sciencebox
helm repo add jupyterhub https://jupyterhub.github.io/helm-chart/

helm repo update

echo ""
echo "Updating swan env ${SWAN_ENV}, upgrade db ${UPGRADE_DB}"
echo ""

# Annotation is required in order to restart jupyterhub server on swan_config.py or jupyterhub_form.html changes
helm upgrade --install --namespace swan  \
--kubeconfig $KUBECONFIG \
--values $SWAN_SECRET_VALUES_PATH \
--set swan.jupyterhub.hub.annotations.version="release-$(date +%s)" \
--set swan.jupyterhub.hub.db.upgrade=$UPGRADE_DB \
--set swanCern.secrets.hadoop.cred=$HADOOP_AUTH_KEYTAB_ENCODED \
--set swanCern.secrets.eos.cred=$EOS_AUTH_KEYTAB_ENCODED \
--set swanCern.secrets.sparkk8s.cred=$SPARKK8S_AUTH_TOKEN_ENCODED \
--set-file optionsform=$OPTIONS_FORM \
swan swan/swan-cern

HELMRETURN=$?

rm -f $SWAN_SECRET_VALUES_PATH
rm -f $KUBECONFIG

if [[ $HELMRETURN -ne 0 ]]
then
    echo "failed"
    exit 1
fi


