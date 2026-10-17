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

{{/* The roles that run under a ServiceAccount of their own:
serviceaccount.yaml makes one for each, and a Deployment may name no other. */}}
{{- define "agentry.serviceAccountRoles" -}}
api worker git
{{- end }}

{{/* A role's ServiceAccount name: (dict "ctx" $ "role" "api").
With serviceAccount.create (the default) each role has its own,
<fullname>-<role>, so a pod's token names the role presenting it (OpenBao's
Kubernetes auth binds the encrypt policy to the api's and the decrypt policy
to the worker's). With create: false,
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
  The env of one role's agentryd container: non-secret AGENTRY_* from config
  plus the secret references that role uses, and nothing more.
  Every role holds the database URL and the auth sealing key (config
  validation requires the key outside dev, and git keys its tag-push hash from
  it). The api and the worker also send mail and unwrap the knowledge scan;
  the api alone exchanges the sign-in provider's OIDC code and reports
  features.redis. So the git role, which takes untrusted pushes, holds no
  mail, knowledge or sign-in credential, and the worker none of the api's
  OIDC ones.
  Include with: {{- include "agentry.agentrydEnv" (dict "ctx" . "role" "api") | nindent 12 }}
*/}}
{{- define "agentry.agentrydEnv" -}}
{{- $ctx := .ctx -}}
{{- $role := .role -}}
{{- $secret := include "agentry.secretName" $ctx -}}
{{- $existing := $ctx.Values.secret.existingSecret -}}
{{- if not (has $role (list "api" "git" "worker")) -}}
{{- fail (printf "agentry.agentrydEnv has no role %q: the chart's roles are api, worker and git" $role) -}}
{{- end -}}
{{- $api := eq $role "api" -}}
{{- $apiOrWorker := has $role (list "api" "worker") -}}
- name: AGENTRY_CONFIG
  value: /etc/agentry/agentry.yaml
- name: AGENTRY_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: AGENTRY_DATABASE_URL
- name: AGENTRY_AUTH_SEALING_KEY
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: AGENTRY_AUTH_SEALING_KEY
{{- if and $apiOrWorker (or $ctx.Values.secret.knowledgeSealingKey $existing) }}
- name: AGENTRY_KNOWLEDGE_SEALING_KEY
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: AGENTRY_KNOWLEDGE_SEALING_KEY
      optional: true
{{- end }}
{{- if and $api (or $ctx.Values.secret.redisUrl $existing) }}
- name: AGENTRY_REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: AGENTRY_REDIS_URL
      optional: true
{{- end }}
{{- if and $apiOrWorker (or $ctx.Values.secret.smtpPassword $existing) }}
- name: AGENTRY_SMTP_PASS
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: AGENTRY_SMTP_PASS
      optional: true
{{- end }}
{{- if and $api (or $ctx.Values.secret.oidcClientSecret $existing) }}
- name: AGENTRY_AUTH_OIDC_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: AGENTRY_AUTH_OIDC_CLIENT_SECRET
      optional: true
{{- end }}
{{- with $ctx.Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
  One role's extra pod annotations: the chart-wide podAnnotations with the
  role's own over them, less the chart's checksum/config.
  Empty renders nothing, so the pod template is unchanged when neither is set.
  Include with: {{- with include "agentry.podAnnotations" (dict "ctx" . "role" "api") }}{{ . | nindent 8 }}{{ end }}
*/}}
{{- define "agentry.podAnnotations" -}}
{{- if not (has .role (list "api" "git" "worker")) -}}
{{- fail (printf "agentry.podAnnotations has no role %q: the chart's roles are api, worker and git" .role) -}}
{{- end -}}
{{- $role := index .ctx.Values .role -}}
{{- /* checksum/config is the chart's own, which rolls the pods on a config
change; an operator's copy would render the key twice. */ -}}
{{- with omit (merge (deepCopy ($role.podAnnotations | default dict)) (.ctx.Values.podAnnotations | default dict)) "checksum/config" -}}
{{ toYaml . }}
{{- end -}}
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

  The key is the worker's alone: the api and git
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
