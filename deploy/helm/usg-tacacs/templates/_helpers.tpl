{{/*
Helper templates for the usg-tacacs chart.
*/}}

{{- define "usg-tacacs.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "usg-tacacs.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "usg-tacacs.name" . | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "usg-tacacs.namespace" -}}
{{- default .Release.Namespace .Values.namespace.name -}}
{{- end -}}

{{/*
Common labels (Kubernetes recommended set + any commonLabels override).
*/}}
{{- define "usg-tacacs.labels" -}}
app.kubernetes.io/name: {{ include "usg-tacacs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: usg-tacacs
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Selector labels — stable across upgrades. `app: tacacs` is kept for parity with
the existing NetworkPolicies and Service selectors.
*/}}
{{- define "usg-tacacs.selectorLabels" -}}
app: tacacs
app.kubernetes.io/name: {{ include "usg-tacacs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "usg-tacacs.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "usg-tacacs.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the full server image ref, preferring digest over tag (immutability).
*/}}
{{- define "usg-tacacs.image" -}}
{{- $i := .Values.image -}}
{{- $repo := printf "%s/%s" $i.registry $i.repository -}}
{{- if $i.digest -}}
{{- printf "%s@%s" $repo $i.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (toString $i.tag) -}}
{{- end -}}
{{- end -}}

{{- define "usg-tacacs.redisImage" -}}
{{- $i := .Values.redis.image -}}
{{- $repo := printf "%s/%s" $i.registry $i.repository -}}
{{- if $i.digest -}}
{{- printf "%s@%s" $repo $i.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (toString $i.tag) -}}
{{- end -}}
{{- end -}}
