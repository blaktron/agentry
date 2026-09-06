{{/* Expand the name of the chart. */}}
{{- define "agentry.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name. */}}
{{- define "agentry.fullname" -}}
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

{{- define "agentry.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels */}}
{{- define "agentry.labels" -}}
helm.sh/chart: {{ include "agentry.chart" . }}
{{ include "agentry.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels */}}
{{- define "agentry.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentry.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* ServiceAccount name */}}
{{- define "agentry.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "agentry.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Secret name (created or existing) */}}
{{- define "agentry.secretName" -}}
{{- if .Values.secret.existingSecret }}
{{- .Values.secret.existingSecret }}
{{- else }}
{{- printf "%s-secrets" (include "agentry.fullname" .) }}
{{- end }}
{{- end }}

{{/* agentryd image ref */}}
{{- define "agentry.agentrydImage" -}}
{{- $tag := default .Chart.AppVersion .Values.image.agentryd.tag -}}
{{- printf "%s:%s" .Values.image.agentryd.repository $tag }}
{{- end }}

{{/*
  Shared env for agentryd containers: non-secret AGENTRY_* from config plus
  secret refs. Include with: {{- include "agentry.agentrydEnv" . | nindent 12 }}
*/}}
{{- define "agentry.agentrydEnv" -}}
- name: AGENTRY_CONFIG
  value: /etc/agentry/agentry.yaml
- name: AGENTRY_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "agentry.secretName" . }}
      key: AGENTRY_DATABASE_URL
- name: AGENTRY_AUTH_SEALING_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "agentry.secretName" . }}
      key: AGENTRY_AUTH_SEALING_KEY
{{- if or .Values.secret.redisUrl .Values.secret.existingSecret }}
- name: AGENTRY_REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "agentry.secretName" . }}
      key: AGENTRY_REDIS_URL
      optional: true
{{- end }}
{{- if or .Values.secret.smtpPassword .Values.secret.existingSecret }}
- name: AGENTRY_SMTP_PASS
  valueFrom:
    secretKeyRef:
      name: {{ include "agentry.secretName" . }}
      key: AGENTRY_SMTP_PASS
      optional: true
{{- end }}
{{- if or .Values.secret.authentikClientSecret .Values.secret.existingSecret }}
- name: AGENTRY_SOCIAL_AUTHENTIK_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "agentry.secretName" . }}
      key: AGENTRY_SOCIAL_AUTHENTIK_CLIENT_SECRET
      optional: true
{{- end }}
{{- if or .Values.secret.idpAdminToken .Values.secret.existingSecret }}
- name: AGENTRY_IDP_ADMIN_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "agentry.secretName" . }}
      key: AGENTRY_IDP_ADMIN_TOKEN
      optional: true
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}
