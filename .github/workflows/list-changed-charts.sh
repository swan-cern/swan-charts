#!/bin/bash

set -euxo pipefail
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" || exit; pwd;)"

cd ${script_dir}/../../ # cd to the root of the repo

CHARTS=("swan" "swan-cern")

for CHART_NAME in "${CHARTS[@]}"; do

    # Determine last tag on the chart
    LAST_CHART_TAG="$(git tag --list --sort -version:refname ${CHART_NAME}@* | head -n 1)"

    # Determine if there are any changes on the chart/ folder since last tag
    HAS_CHANGED="$(git diff --quiet HEAD ${LAST_CHART_TAG} -- ./${CHART_NAME} || echo true)"

    # print output
    echo "${CHART_NAME}_has_changed=${HAS_CHANGED}"
    
done