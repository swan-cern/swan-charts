#!/bin/bash

log_info() {
    echo "[INFO $(date '+%Y-%m-%d %T.%3N') $(basename $0)] $1"
}
log_error() {
    echo "[INFO $(date '+%Y-%m-%d %T.%3N') $(basename $0)] $1"
}

log_info "Started cvmfs lcg prefetching.."

while true; do
    source /cvmfs/sft.cern.ch/lcg/views/LCG_96/x86_64-centos7-gcc8-opt/setup.sh && ( timeout 10s python -m ipykernel > /dev/null 2>&1 || true )
    if [ $? -ne 0 ]; then
        log_error "Getting ipykernel failed"
        exit 1
    fi

    source /cvmfs/sft.cern.ch/lcg/views/LCG_96/x86_64-centos7-gcc8-opt/setup.sh && ( timeout 20s python -m JupyROOT.kernel.rootkernel > /dev/null 2>&1 || true )
    if [ $? -ne 0 ]; then
        log_error "Getting JupyROOT.kernel.rootkernel failed"
        exit 1
    fi

    sleep 15m
done

log_info "Stopped cvmfs lcg prefetching.."

exit 1