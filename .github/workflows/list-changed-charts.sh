#!/bin/bash
# Prints a line "${CHART_NAME}_has_changed=<true|false>" for every chart (swan, swan-cern) that has changed since last tag ${CHART_NAME}@x.y.z

set -euxo pipefail
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" || exit; pwd;)"

cd "${script_dir}/../../" # cd to the root of the repo

CHARTS=("swan" "swan-cern" "swan-cern-system")

for CHART_NAME in "${CHARTS[@]}"; do

    # Determine last tag on the chart
    LAST_CHART_TAG="$(git tag --list --sort -version:refname ${CHART_NAME}@* | head -n 1)"

    # Determine if there are any changes on the chart/ folder since last tag
    if git diff --quiet HEAD "${LAST_CHART_TAG}" -- ./"${CHART_NAME}"; then
         echo "${CHART_NAME}_has_changed=false" # git diff exited with 0, there are no changes
    else
         echo "${CHART_NAME}_has_changed=true" # git diff exited with 1, there are changes
    fi
done