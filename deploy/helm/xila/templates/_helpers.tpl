{{/* Chart name. */}}
{{- define "xila.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name (release-prefixed unless the release already says xila). */}}
{{- define "xila.fullname" -}}
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

{{- define "xila.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "xila.labels" -}}
helm.sh/chart: {{ include "xila.chart" . }}
{{ include "xila.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "xila.selectorLabels" -}}
app.kubernetes.io/name: {{ include "xila.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: app
{{- end }}

{{- define "xila.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "xila.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "xila.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{/* The Secret holding JWT_SECRET, INTEGRATION_SECRET_KEY and extras. */}}
{{- define "xila.secretName" -}}
{{- default (include "xila.fullname" .) .Values.existingSecret }}
{{- end }}

{{/* Bundled PostgreSQL. */}}
{{- define "xila.pg.fullname" -}}
{{- printf "%s-postgresql" (include "xila.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "xila.pg.selectorLabels" -}}
app.kubernetes.io/name: {{ include "xila.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgresql
{{- end }}

{{/* Where DB_PASSWORD comes from: {name, key}. */}}
{{- define "xila.db.passwordSecret" -}}
{{- if .Values.postgresql.enabled -}}
name: {{ include "xila.pg.fullname" . }}
key: password
{{- else if .Values.database.passwordSecret.name -}}
name: {{ .Values.database.passwordSecret.name }}
key: {{ .Values.database.passwordSecret.key }}
{{- else -}}
name: {{ include "xila.fullname" . }}-db
key: password
{{- end -}}
{{- end }}

{{/*
A secret value that is generated once and then kept: the value from values if
set, else the one already stored in the live Secret, else a new random one.
Args: (list $ secretName key generator)
*/}}
{{- define "xila.persistentSecret" -}}
{{- $ := index . 0 -}}
{{- $name := index . 1 -}}
{{- $key := index . 2 -}}
{{- $gen := index . 3 -}}
{{- $existing := lookup "v1" "Secret" $.Release.Namespace $name -}}
{{- if and $existing $existing.data (hasKey $existing.data $key) -}}
{{- index $existing.data $key | b64dec -}}
{{- else -}}
{{- $gen -}}
{{- end -}}
{{- end }}

{{/* The UI's external URL. */}}
{{- define "xila.publicUrl" -}}
{{- if .Values.publicUrl -}}
{{- .Values.publicUrl -}}
{{- else if and .Values.ingress.enabled .Values.ingress.hosts -}}
{{- $host := (first .Values.ingress.hosts).host -}}
{{- $tls := false -}}
{{- range .Values.ingress.tls }}{{ if has $host .hosts }}{{ $tls = true }}{{ end }}{{ end -}}
{{- printf "%s://%s" (ternary "https" "http" $tls) $host -}}
{{- end -}}
{{- end }}

{{/* Fail early on configurations that cannot work. */}}
{{- define "xila.validate" -}}
{{- if and (not .Values.postgresql.enabled) (not .Values.database.host) -}}
{{- fail "database.host is required when postgresql.enabled=false" -}}
{{- end -}}
{{- if and (not .Values.postgresql.enabled) (not .Values.database.password) (not .Values.database.passwordSecret.name) (not .Values.existingSecret) -}}
{{- fail "set database.password, database.passwordSecret.name, or DB_PASSWORD in existingSecret" -}}
{{- end -}}
{{- if not (has .Values.appEnv (list "development" "production")) -}}
{{- fail "appEnv must be development or production" -}}
{{- end -}}
{{- end }}
