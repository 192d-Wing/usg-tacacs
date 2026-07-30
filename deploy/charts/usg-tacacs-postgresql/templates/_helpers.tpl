{{- define "usg-tacacs-postgresql.labels" -}}
app.kubernetes.io/name: usg-tacacs-postgresql
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "usg-tacacs-postgresql.migrationName" -}}
{{- printf "%s-migrate-%s" .Values.cluster.name ((.Files.Get "files/0001_jit_leases.sql" | sha256sum) | trunc 10) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

