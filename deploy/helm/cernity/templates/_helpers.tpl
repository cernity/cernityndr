{{- define "cernity.image" -}}
{{ .Values.image.registry }}/{{ .Values.image.repository }}/{{ .name }}:{{ .Values.image.tag }}
{{- end -}}

{{- define "cernity.labels" -}}
app.kubernetes.io/name: cernity
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
