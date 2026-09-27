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

{{/* The roles that run under a ServiceAccount of their own (agentry#627):
serviceaccount.yaml makes one for each, and a Deployment may name no other. */}}
{{- define "agentry.serviceAccountRoles" -}}
api worker git
{{- end }}

{{/* A role's ServiceAccount name: (dict "ctx" $ "role" "api").
With serviceAccount.create (the default) each role has its own,
<fullname>-<role>, so a pod's token names the role presenting it (OpenBao's
Kubernetes auth binds the encrypt policy to the api's and the decrypt policy
to the worker's; plan hosted-credentials-vault.md D6). With create: false,
every role runs under the one existing account serviceAccount.name. */}}
{{- define "agentry.serviceAccountName" -}}
{{- $ctx := .ctx -}}
{{- if not (has .role (splitList " " (include "agentry.serviceAccountRoles" $ctx))) -}}
{{- fail (printf "no ServiceAccount is made for the role %q: the chart makes one for api, worker and git" .role) -}}
{{- end -}}
{{- if $ctx.Values.serviceAccount.create -}}
{{- if $ctx.Values.serviceAccount.name -}}
{{- fail "serviceAccount.name names an existing account, and needs serviceAccount.create=false: with create, the chart makes one account per role (<release>-agentry-api, -worker and -git)" -}}
{{- end -}}
{{- /* The fullname is cut to leave room for "-worker", the longest role, so
truncation never makes two roles' names one. */ -}}
{{- printf "%s-%s" (include "agentry.fullname" $ctx | trunc 56 | trimSuffix "-") .role -}}
{{- else -}}
{{- default "default" $ctx.Values.serviceAccount.name -}}
{{- end -}}
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
{{- if or .Values.secret.knowledgeSealingKey .Values.secret.existingSecret }}
- name: AGENTRY_KNOWLEDGE_SEALING_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "agentry.secretName" . }}
      key: AGENTRY_KNOWLEDGE_SEALING_KEY
      optional: true
{{- end }}
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
{{- if or .Values.secret.idpTrustCheckToken .Values.secret.existingSecret }}
- name: AGENTRY_IDP_TRUST_CHECK_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "agentry.secretName" . }}
      key: AGENTRY_IDP_TRUST_CHECK_TOKEN
      optional: true
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
  Object-store credentials from objectStoreCredentials.existingSecret, in the api
  and worker containers only: the git role never touches the store.
*/}}
{{- define "agentry.storageCredentialsEnv" -}}
{{- with .Values.objectStoreCredentials.existingSecret }}
- name: AWS_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: {{ . }}
      key: AWS_ACCESS_KEY_ID
- name: AWS_SECRET_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ . }}
      key: AWS_SECRET_ACCESS_KEY
{{- end }}
{{- end }}

{{/*
  The database CA volume (every role) and the signing key volume (the worker
  only), when their Secrets are named. Each projects one key of its Secret to
  a fixed file name, so a Secret whose key is named differently is a
  render-time value, not a crash loop. Their directories sit beside
  /etc/agentry, never under it: the config mount is read-only and a mount
  nested inside it cannot be created.

  The key is the worker's alone (agentry#479, PLAN §13.3): the api and git
  roles start without it and never sign, so the pods that terminate
  untrusted traffic hold no private key.
*/}}
{{- define "agentry.signingKeyVolume" -}}
{{- with .Values.signingKey.existingSecret }}
- name: signing-key
  secret:
    secretName: {{ . }}
    defaultMode: 0400
    items:
      - key: {{ $.Values.signingKey.key }}
        path: {{ base $.Values.config.signing.keyFile }}
{{- end }}
{{- end }}

{{- define "agentry.signingKeyVolumeMount" -}}
{{- if .Values.signingKey.existingSecret }}
{{- $dir := dir .Values.config.signing.keyFile }}
{{- if or (not (hasPrefix "/" $dir)) (hasPrefix "/etc/agentry/" (printf "%s/" $dir)) }}
{{- fail "config.signing.keyFile must be an absolute path outside /etc/agentry (the read-only config mount)" }}
{{- end }}
- name: signing-key
  mountPath: {{ $dir }}
  readOnly: true
{{- end }}
{{- end }}

{{- define "agentry.extraVolumes" -}}
{{- with .Values.databaseCA.existingSecret }}
- name: db-ca
  secret:
    secretName: {{ . }}
    items:
      - key: {{ $.Values.databaseCA.key }}
        path: ca.crt
{{- end }}
{{- end }}

{{- define "agentry.extraVolumeMounts" -}}
{{- if .Values.databaseCA.existingSecret }}
- name: db-ca
  mountPath: /etc/agentry-db-ca
  readOnly: true
{{- end }}
{{- end }}

{{/* The git role's SSH port number, from config.git.sshAddr (":2222" → 2222). */}}
{{- define "agentry.gitSSHPort" -}}
{{- $addr := .Values.config.git.sshAddr | default "" -}}
{{- if $addr }}{{ (splitList ":" $addr) | last }}{{ end -}}
{{- end }}
