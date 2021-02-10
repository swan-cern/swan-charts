#!/bin/bash
# set swan k8s env.

PS3='Choose SWAN k8s environment: '
options=("SWAN Prod" "SWAN QA" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "SWAN Prod")
            export KUBECONFIG=/srv/swan-k8s/private/swan.prod.kubeconfig
            ;;
        "SWAN QA")
            export KUBECONFIG=/srv/swan-k8s/private/swan.qa.kubeconfig
            ;;
        "Quit")
            break
            ;;
        *) echo "invalid option $REPLY";;
    esac
    break
done
