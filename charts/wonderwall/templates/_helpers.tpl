{{/*
Expand the name of the chart.
*/}}
{{- define "wonderwall.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "wonderwall.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "wonderwall.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "wonderwall.labels" -}}
helm.sh/chart: {{ include "wonderwall.chart" . }}
{{ include "wonderwall.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
team: nais
{{- end }}

{{/*
Common labels for forward auth
*/}}
{{- define "wonderwall.labelsForwardAuth" -}}
{{ include "wonderwall.labels" . }}
app: wonderwall-fa
{{- end }}

{{/*
Common labels for ID-porten
*/}}
{{- define "wonderwall.labelsIdporten" -}}
{{ include "wonderwall.labels" . }}
app: wonderwall-idporten
{{- end }}

{{/*
Selector labels
*/}}
{{- define "wonderwall.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wonderwall.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels for forward auth
*/}}
{{- define "wonderwall.selectorLabelsForwardAuth" -}}
{{ include "wonderwall.selectorLabels" . }}
app: wonderwall-fa
{{- end }}

{{/*
Selector labels for ID-porten
*/}}
{{- define "wonderwall.selectorLabelsIdporten" -}}
{{ include "wonderwall.selectorLabels" . }}
app: wonderwall-idporten
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "wonderwall.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "wonderwall.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Azure SSO server URL.
*/}}
{{- define "wonderwall.azure.ssoServerURL" -}}
{{- if not .Values.azure.ssoDomain }}
{{- fail ".Values.azure.ssoDomain is required." }}
{{ else }}
{{- printf "https://%s" .Values.azure.ssoDomain }}
{{- end }}
{{- end }}

{{/*
ID-porten SSO server URL.
*/}}
{{- define "wonderwall.idporten.ssoServerURL" -}}
{{- if not .Values.idporten.ssoServerHost }}
{{- fail ".Values.idporten.ssoServerHost is required." }}
{{ else }}
{{- printf "https://%s" .Values.idporten.ssoServerHost }}
{{- end }}
{{- end }}

{{/*
Aiven instance name.
The last part of the fully qualified name (e.g. <instance> in `redis-<namespace>-<instance>`)
*/}}
{{- define "aiven.instanceName" -}}
{{- printf "wonderwall-%s" . }}
{{- end }}

{{/*
Aiven Redis fully qualified name.
Must follow Aivenator naming scheme: `redis-<namespace>-<instance>`
Expects a dict with the following keys:
- root: The root values, e.g "."
- provider: The identity provider, e.g. "azure" or "idporten"
*/}}
{{- define "aiven.redisName" -}}
{{- $root := .root }}
{{- $provider := .provider }}
{{- printf "redis-%s-%s" $root.Release.Namespace (include "aiven.instanceName" $provider) }}
{{- end }}

{{/*
Aiven ServiceIntegration fully qualified name.
Must follow Aivenator naming scheme: `serviceintegration-<namespace>-<instance>`
Expects a dict with the following keys:
- root: The root values, e.g "."
- provider: The identity provider, e.g. "azure" or "idporten"
*/}}
{{- define "aiven.serviceintegrationName" -}}
{{- $root := .root }}
{{- $provider := .provider }}
{{- printf "serviceintegration-%s-%s" $root.Release.Namespace (include "aiven.instanceName" $provider) }}
{{- end }}
