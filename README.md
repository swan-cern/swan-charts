# SWAN Helm Charts

This repository contains the Helm charts of the SWAN web-based analysis service. Two charts are provided:
- `swan`: generic SWAN k8s resources and settings, which can be used to deploy SWAN on premises.
- `swan-cern`: CERN-specific k8s resources and settings, used for the central instance of SWAN at CERN.
- `swan-cern-system`: CERN-specific k8s resources that support the SWAN main application, to be deployed cluster wide.
