{{/* Names. Standard Helm shape so the chart behaves like any other. */}}
{{- define "config-portal.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "config-portal.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "config-portal.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "config-portal.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "config-portal.selectorLabels" -}}
app.kubernetes.io/name: {{ include "config-portal.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "config-portal.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "config-portal.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The image reference: a digest wins over a tag, and an empty tag follows
     appVersion so the chart and the portal cannot drift apart. */}}
{{- define "config-portal.image" -}}
{{- $repo := .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* The assistant's model runtime is a second workload in this release, so it
     gets its own name and selector — one release, two services. */}}
{{- define "config-portal.ollamaName" -}}
{{- printf "%s-ollama" (include "config-portal.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "config-portal.ollamaSelectorLabels" -}}
app.kubernetes.io/name: {{ printf "%s-ollama" (include "config-portal.name" .) }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: model-runtime
{{- end -}}

{{/* Where the portal should look for a model. An explicit assistant.url wins;
     otherwise the in-cluster Ollama this chart installed. */}}
{{- define "config-portal.assistantUrl" -}}
{{- if .Values.assistant.url -}}
{{- .Values.assistant.url -}}
{{- else if .Values.ollama.enabled -}}
{{- printf "http://%s:%d" (include "config-portal.ollamaName" .) (int .Values.ollama.service.port) -}}
{{- end -}}
{{- end -}}
