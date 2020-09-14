#!/bin/bash
# Located at [/srv/jupyterhub/private/sparkk8s-token.sh]

function usage(){
  echo -e "usage: ${0} USERNAME \n"
  echo -e "USERNAME                      The username"
}

if [ "${1}" == "-h" ]; then
  usage
  exit
fi

if [[ -z "${1// }" ]]; then
  echo "ERROR: No username set"
  usage
  exit 1
fi
USERNAME="$1"
SERVICE_ACCOUNT="spark"

KUBECONFIG="/srv/jupyterhub/private/sparkk8s.cred"
SERVER=$(awk -F"server: " '{print $2}' ${KUBECONFIG} | sed '/^$/d')

helm init --client-only > /dev/null 2>&1

if user_exists=$(helm --kubeconfig "${KUBECONFIG}" ls "spark-user-${USERNAME}" > /dev/null 2>&1); then
    :
else
    echo "ERROR: cluster is not ready. Please initialize cluster with helm manually"
    exit 1
fi

if [[ -z "${user_exists// }" ]]; then
    # User not initialized
    helm install \
    --wait \
    --kubeconfig "${KUBECONFIG}" \
    --set namespace="${USERNAME}" \
    --set cvmfs.enable=true \
    --name "spark-user-${USERNAME}" https://gitlab.cern.ch/db/spark-service/spark-service-charts/raw/master/cern-spark-user-1.0.1.tgz > /dev/null 2>&1
fi

# Retrieve service account secret
SECRET=$(kubectl --kubeconfig="${KUBECONFIG}" \
--namespace "${USERNAME}" \
get serviceaccount "${SERVICE_ACCOUNT}" -o json | python -c 'import json,sys;obj=json.load(sys.stdin);print(obj["secrets"][0]["name"])')

if [[ -z "${SECRET// }" ]]; then
    echo "secret for SA ${SERVICE_ACCOUNT} is not found"
    exit 1
fi

TOKEN=$(kubectl --kubeconfig="${KUBECONFIG}" \
--namespace "${USERNAME}" \
get secret "${SECRET}" -o json \
| python -c 'import json,sys;obj=json.load(sys.stdin);print(obj["data"]["token"])' | base64 --decode)

CA=$(kubectl --kubeconfig="${KUBECONFIG}" \
--namespace "${USERNAME}" \
get secret "${SECRET}" -o json \
| python -c 'import json,sys;obj=json.load(sys.stdin);print(obj["data"]["ca.crt"])')

cat > /tmp/k8s-user.config.$USERNAME <<EOF
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: $CA
    server: $SERVER
  name: k8s-spark-gp
contexts:
- context:
    cluster: k8s-spark-gp
    namespace: $USERNAME
    user: spark
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: spark
  user:
    token: $TOKEN
EOF

echo $(cat /tmp/k8s-user.config.$USERNAME | base64 -w 0)

