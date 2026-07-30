{{- define "usg-tacacs.name" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "usg-tacacs.managedNads" -}}
{{- range $index, $nad := .Values.nads -}}
{{- if $index }},{{ end -}}{{ $nad.identity }}
{{- end -}}
{{- end -}}

{{- define "usg-tacacs.legacyNads" -}}
{{- $first := true -}}
{{- range $nad := .Values.nads -}}
{{- if eq $nad.mode "legacy" -}}
{{- if not $first }},{{ end -}}{{ $nad.sourceIp }}={{ $nad.identity }}
{{- $first = false -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "usg-tacacs.labels" -}}
app.kubernetes.io/name: usg-tacacs
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "usg-tacacs.selectorLabels" -}}
app.kubernetes.io/name: usg-tacacs
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "usg-tacacs.image" -}}
{{- if .Values.image.digest -}}
{{ printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else -}}
{{ printf "%s:%s" .Values.image.repository .Values.image.tag }}
{{- end -}}
{{- end -}}
