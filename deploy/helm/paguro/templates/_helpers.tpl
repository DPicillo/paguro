{{/* Common labels. Object names are fixed (not release-prefixed): the
controller looks them up by name (webhook config "paguro", secret
"paguro-webhook-tls", service "paguro-controller") and RBAC is scoped to
those names. Hence one Paguro installation per cluster. */}}

{{- define "paguro.labels" -}}
app.kubernetes.io/part-of: paguro
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end }}

{{/* image: (dict "root" $ "img" .Values.controller.image) */}}
{{- define "paguro.image" -}}
{{- $g := .root.Values.global -}}
{{- $repo := .img.repository | default (printf "%s/%s" (trimSuffix "/" $g.imageRegistry) .img.name) -}}
{{- $tag := .img.tag | default $g.imageTag | default .root.Chart.AppVersion -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end }}

{{- define "paguro.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/* true if an existing cluster object was created by this release (or does
not exist at all) – then the chart renders it; otherwise it is left alone. */}}
{{- define "paguro.ownedOrAbsent" -}}
{{- $obj := .obj -}}
{{- if not $obj -}}true
{{- else if eq (dig "metadata" "annotations" "meta.helm.sh/release-name" "" $obj) .root.Release.Name -}}true
{{- else -}}false
{{- end -}}
{{- end }}

{{- define "paguro.tokenSecretName" -}}
{{- .Values.agent.token.existingSecret | default "paguro-agent-token" -}}
{{- end }}

{{/*
kubelet's data directory. With a default here, not only in values.yaml:
`helm upgrade --reuse-values` from a release made with an older chart
does not pick up new values.yaml keys – an empty kubeletDir put the commit
gate's sockets where kubelet never looked.
*/}}
{{- define "paguro.kubeletDir" -}}
{{- .Values.agent.kubeletDir | default "/var/lib/kubelet" -}}
{{- end }}

{{/* Agones integration: "true" when enabled, or "auto" and the GameServer
API exists (Agones installed before Paguro), on Kubernetes >= 1.30
(admission policies). */}}
{{- define "paguro.agones" -}}
{{- $v := .Values.agones | default dict -}}
{{- $on := dig "enabled" "auto" $v -}}
{{- $vap := .Capabilities.APIVersions.Has "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy" -}}
{{- if and $vap (or (eq (toString $on) "true") (and (eq (toString $on) "auto") (.Capabilities.APIVersions.Has "agones.dev/v1/GameServer"))) -}}
true
{{- end -}}
{{- end -}}
