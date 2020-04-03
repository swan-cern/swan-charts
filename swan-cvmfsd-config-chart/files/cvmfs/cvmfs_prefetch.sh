#!/bin/bash

log_info() {
    echo "[INFO $(date '+%Y-%m-%d %T.%3N') $(basename $0)] $1"
}
log_error() {
    echo "[INFO $(date '+%Y-%m-%d %T.%3N') $(basename $0)] $1"
}

log_info "Started cvmfs lcg prefetching.."

LATEST_LCG="/cvmfs/sft.cern.ch/lcg/views/LCG_97/x86_64-centos7-gcc8-opt/setup.sh"
if [ -f "$LATEST_LCG" ]; then
    # Get ipykernel in subshell and get return code
    (source $LATEST_LCG && (timeout 10s python -m ipykernel > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LATEST_LCG ipykernel failed"
    fi

    # Get JupyROOT.kernel.rootkernel in subshell and get return code
    (source $LATEST_LCG && ( timeout 20s python -m JupyROOT.kernel.rootkernel > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LATEST_LCG JupyROOT.kernel.rootkernel failed"
    fi

    # Get Spark in subshell and get return code
    (source $LATEST_LCG && ( timeout 20s python -c "import pyspark" > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LATEST_LCG pyspark failed"
    fi
else
    log_error "Sourcing $LATEST_LCG failed, path not accessible"
fi

LATEST_LCGPython3="/cvmfs/sft.cern.ch/lcg/views/LCG_97python3/x86_64-centos7-gcc8-opt/setup.sh"
if [ -f "$LATEST_LCGPython3" ]; then
    # Get ipykernel in subshell and get return code
    (source $LATEST_LCGPython3 && (timeout 10s python -m ipykernel > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LATEST_LCGPython3 ipykernel failed"
    fi

    # Get JupyROOT.kernel.rootkernel in subshell and get return code
    (source $LATEST_LCGPython3 && ( timeout 20s python -m JupyROOT.kernel.rootkernel > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LATEST_LCGPython3 JupyROOT.kernel.rootkernel failed"
    fi

    # Get Spark in subshell and get return code
    (source $LATEST_LCGPython3 && ( timeout 20s python -c "import pyspark" > /dev/null 2>&1 || true ))
    if [ $? -ne 0 ]; then
        log_error "Getting $LATEST_LCGPython3 pyspark failed"
    fi
else
    log_error "Sourcing $LATEST_LCGPython3 failed, path not accessible"
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
