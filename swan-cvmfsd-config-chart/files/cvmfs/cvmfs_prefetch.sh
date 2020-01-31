#!/bin/bash

log_info() {
    echo "[INFO $(date '+%Y-%m-%d %T.%3N') $(basename $0)] $1"
}
log_error() {
    echo "[INFO $(date '+%Y-%m-%d %T.%3N') $(basename $0)] $1"
}

log_info "Started cvmfs lcg prefetching.."

LCG_96_SETUP="/cvmfs/sft.cern.ch/lcg/views/LCG_96/x86_64-centos7-gcc8-opt/setup.sh"
if [ -f "$LCG_96_SETUP" ]; then
    # Get ipykernel in subshell and get return code
    (source $LCG_96_SETUP && (timeout 10s python -m ipykernel > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LCG_96_SETUP ipykernel failed"
    fi

    # Get JupyROOT.kernel.rootkernel in subshell and get return code
    (source $LCG_96_SETUP && ( timeout 20s python -m JupyROOT.kernel.rootkernel > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LCG_96_SETUP JupyROOT.kernel.rootkernel failed"
    fi

    # Get Spark in subshell and get return code
    (source $LCG_96_SETUP && ( timeout 20s python -c "import pyspark" > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LCG_96_SETUP pyspark failed"
    fi
else
    log_error "Sourcing $LCG_96_SETUP failed, path not accessible"
fi

LCG_96Python3_SETUP="/cvmfs/sft.cern.ch/lcg/views/LCG_96python3/x86_64-centos7-gcc8-opt/setup.sh"
if [ -f "$LCG_96Python3_SETUP" ]; then
    # Get ipykernel in subshell and get return code
    (source $LCG_96Python3_SETUP && (timeout 10s python -m ipykernel > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LCG_96Python3_SETUP ipykernel failed"
    fi

    # Get JupyROOT.kernel.rootkernel in subshell and get return code
    (source $LCG_96Python3_SETUP && ( timeout 20s python -m JupyROOT.kernel.rootkernel > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LCG_96Python3_SETUP JupyROOT.kernel.rootkernel failed"
    fi

    # Get Spark in subshell and get return code
    (source $LCG_96Python3_SETUP && ( timeout 20s python -c "import pyspark" > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LCG_96Python3_SETUP pyspark failed"
    fi
else
    log_error "Sourcing $LCG_96Python3_SETUP failed, path not accessible"
fi

LCG_NXCALS_SETUP="/cvmfs/sft.cern.ch/lcg/views/LCG_95apython3_nxcals/x86_64-centos7-gcc7-opt/setup.sh"
if [ -f "$LCG_NXCALS_SETUP" ]; then
    # Get ipykernel in subshell and get return code
    (source $LCG_NXCALS_SETUP && (timeout 10s python -m ipykernel > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LCG_NXCALS_SETUP ipykernel failed"
    fi

    # Get JupyROOT.kernel.rootkernel in subshell and get return code
    (source $LCG_NXCALS_SETUP && ( timeout 20s python -m JupyROOT.kernel.rootkernel > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LCG_NXCALS_SETUP JupyROOT.kernel.rootkernel failed"
    fi

    # Get Spark in subshell and get return code
    (source $LCG_NXCALS_SETUP && ( timeout 20s python -c "import pyspark" > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LCG_NXCALS_SETUP pyspark failed"
    fi
else
    log_error "Sourcing $LCG_NXCALS_SETUP failed, path not accessible"
fi

log_info "Stopped cvmfs lcg prefetching.."

exit 1