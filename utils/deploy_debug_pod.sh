ROOT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.."; pwd;)

POD_PATH="/tmp/test-pod-$RANDOM.yaml"

USERNAME=""
NAMESPACE=""

while [[ "$#" -gt 0 ]]; do case $1 in
  --user) USERNAME="$2"; shift;;
  --namespace) NAMESPACE="$2"; shift;;
  *) echo "Unknown parameter passed: $1"; exit 1;;
esac; shift; done

if ! [[ -n "${KUBECONFIG}" && -n "${USERNAME}" && -n "${NAMESPACE}" ]]; then
    echo "ERROR: Make sure KUBECONFIG / --user [user] / --namespace [namespace] is set"
	exit 1
fi

cat <<EOF >$POD_PATH
apiVersion: v1
kind: Pod
metadata:
  name: swan-notebook-shell-${USERNAME}
  namespace: ${NAMESPACE}
spec:
  restartPolicy: Never
  containers:
  - name: shell-${USERNAME}
    image: gitlab-registry.cern.ch/swan/docker-images/systemuser:daily
    command: ["sleep"]
    args: ["3600"]
    env:
    - name: USER
      value: ${USERNAME}
    volumeMounts:
    - name: shared-data
      mountPath: /tmp
    - name: eos-tokens-${USERNAME}
      mountPath: /eos-token
    - name: cvmfsd
      mountPath: /cvmfs
      mountPropagation: HostToContainer
    - name: eosd
      mountPath: /eos
      mountPropagation: HostToContainer
  volumes:
  - name: shared-data
    emptyDir: {}
  - name: eos-tokens-${USERNAME}
    secret:
      secretName: eos-tokens-${USERNAME}
  - name: eosd
    hostPath:
       path: /var/eos
  - name: cvmfsd
    hostPath:
       path: /var/cvmfs
EOF

kubectl delete --wait -f $POD_PATH
kubectl create -f $POD_PATH

rm $POD_PATH

kubectl get pods --all-namespaces | grep swan-notebook-shell-$USERNAME
