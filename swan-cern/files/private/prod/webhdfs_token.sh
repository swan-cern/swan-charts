#!/bin/bash
# Located at [/srv/jupyterhub/private/webhdfs-token.sh]

#Get the namenodes for the cluster. We need to convert from the cluster name to the HDFS namespace name for nxcals and hdpqa
function get_namenodes {
if [ "$1" == "hadoop-nxcals" ]; then HDFSNAMESPACE='nxcals'
elif [ "$1" == "hadoop-qa" ]; then HDFSNAMESPACE='hdpqa'
else HDFSNAMESPACE=$1
fi
NAMENODES=$(xmllint --xpath '/configuration//property[name="dfs.ha.namenodes.'"$HDFSNAMESPACE"'"]/value/text()' /cvmfs/sft.cern.ch/lcg/etc/hadoop-confext/conf/etc/$1/hadoop.$1/hdfs-site.xml)
}

CLUSTER=$1
USER=$2

# Generate HDFS, YARN, HIVE tokens
export KRB5CCNAME=$(mktemp /tmp/hswan.XXXXXXXXX)
kinit -V -kt /srv/jupyterhub/private/hadoop.cred hswan@CERN.CH -c $KRB5CCNAME >/dev/null 2>&1

# Generate web-hdfs tokens
if [ "$1" == "hadoop-qa" ];
then HTTP='https'
else HTTP='http'
fi

NAMENODES=$(get_namenodes $1)
OIFS=$IFS
IFS=','
for namenode in $NAMENODES
do
      #to detect active NN. we cannot use jmx, we have to rely on the exit code of the list action
      if [ $(curl -s --negotiate -u : "$HTTP://$namenode:50070/webhdfs/v1/?op=LISTSTATUS" -o /dev/null -s -w "%{http_code}") -eq 200 ];
        then
          WEBHDFS_TOKEN=$(curl -s --negotiate -u : "$HTTP://$namenode:50070/webhdfs/v1/?doas=$2&op=GETDELEGATIONTOKEN&renewer=yarn" | python -c 'import json,sys;obj=json.load(sys.stdin);print(obj["Token"]["urlString"])')
        fi
done

echo $(echo $WEBHDFS_TOKEN | base64 -w 0)
IFS=$OIFS
kdestroy -c $KRB5CCNAME
