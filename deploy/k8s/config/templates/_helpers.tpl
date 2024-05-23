{{- define "list.listPubKeys" -}}
{{- $map := dict }}
{{- range .Values.global.auth }}
{{- $_ := set $map .F7T_AUTH_PUBLIC_KEYS ""}}
{{- end }}
{{- keys $map | join ";" }}
{{- end }}

{{- define "list.listPubKeyTypes" -}}
{{- $map := dict }}
{{- range .Values.global.auth }}
{{- $_ := set $map .F7T_AUTH_ALGORITHMS ""}}
{{- end }}
{{- keys $map | join ";" }}
{{- end }}