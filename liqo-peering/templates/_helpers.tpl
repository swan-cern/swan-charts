{{- define "liqo.tenantNamespace" -}}
liqo-tenant-{{ .Values.remoteCluster.clusterId }}
{{- end }}
