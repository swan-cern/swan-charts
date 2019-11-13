#!/bin/bash
# Located at [/srv/jupyterhub/private/get_hdfs_tokens.sh]

#Determine the active namenode, this is required as the webHDFS implementation doesn't redirect to active namenode
function get_active_namenode {
PYTHON_ARG="$1" python - <<END
import os
import json
import xml.etree.ElementTree as ET
from urllib2 import urlopen
cluster = os.environ['PYTHON_ARG']
conf = '/cvmfs/sft.cern.ch/lcg/etc/hadoop-confext/conf/etc/' + cluster + '/hadoop.' \
    + cluster + '/hdfs-site.xml'
if cluster == 'hadoop-qa':
    property = 'dfs.ha.namenodes.hdpqa'
elif cluster == 'hadoop-nxcals':
    property = 'dfs.ha.namenodes.nxcals'
else:
    property = 'dfs.ha.namenodes.' + cluster
tree = ET.parse(conf)
root = tree.getroot()
for elem in root.iter('property'):
    if elem[0].text == property:
        namenodes = elem[1].text
        break

for namenode in namenodes.split(','):
    try:
        if json.loads(urlopen('http://' + namenode
                      + ':50070/jmx?get=Hadoop:service=NameNode,name=NameNodeStatus::State'
                      , timeout=10).read())['beans'][0]['State'] \
            == 'active':
            print namenode
    except Exception, ex:
        pass
END
}

CLUSTER=$1
USER=$2

# Generate HDFS, YARN, HIVE tokens
export KRB5CCNAME=$(mktemp /tmp/hswan.XXXXXXXXX)
kinit -V -kt /srv/jupyterhub/private/hadoop.keytab hswan@CERN.CH -c $KRB5CCNAME >/dev/null 2>&1

# Generate web-hdfs tokens
namenode=$(get_active_namenode $CLUSTER)
if [ ! -z "$namenode" ];
then
	WEBHDFS_TOKEN=$(curl -s --negotiate -u : "http://$namenode:50070/webhdfs/v1/?doas=$USER&op=GETDELEGATIONTOKEN&renewer=yarn"| python -c 'import json,sys;obj=json.load(sys.stdin);print(obj["Token"]["urlString"])')
fi

echo $(echo $WEBHDFS_TOKEN | base64 -w 0)
kdestroy -c $KRB5CCNAME
