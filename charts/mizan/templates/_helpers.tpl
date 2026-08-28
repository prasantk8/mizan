{{- define "mizan.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mizan.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "mizan.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mizan.image" -}}
{{- printf "%s@%s" .Values.image.repository (required "image.digest is required; deploy releases by digest" .Values.image.digest) -}}
{{- end -}}

{{- define "mizan.labels" -}}
app.kubernetes.io/name: {{ include "mizan.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
