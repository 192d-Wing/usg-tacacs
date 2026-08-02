{{- define "usg-tacacs-postgresql.labels" -}}
app.kubernetes.io/name: usg-tacacs-postgresql
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "usg-tacacs-postgresql.migrationName" -}}
{{- $content := printf "%s%s%s%s"
      (.Files.Get "files/0001_jit_leases.sql")
      (.Files.Get "files/0002_management_nads.sql")
      (.Files.Get "files/0003_nad_audit_hash_v2.sql")
      (.Files.Get "files/0004_management_operations.sql") -}}
{{- printf "%s-migrate-%s" .Values.cluster.name (($content | sha256sum) | trunc 10) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

