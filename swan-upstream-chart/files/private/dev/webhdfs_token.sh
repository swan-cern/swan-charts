#!/bin/bash

# generation of webhdfs is currently not supported
# one can however insert here correct value just for development of some feature

USER=$2

echo "dummy" > /tmp/webhdfs_$2
echo $(cat /tmp/webhdfs_$2 | base64 -w 0)
rm /tmp/webhdfs_$2