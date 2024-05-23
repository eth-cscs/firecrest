{{- define "list.listPubKeys" -}}
{{- $map := dict }}
{{- range .Values.global.auth }}
{{- $_ := set $map .F7T_AUTH_PUBKEY ""}}
{{- end }}
{{- keys $map | join ";" }}
{{- end }}

{{- define "list.listPubKeyTypes" -}}
{{- $map := dict }}
{{- range .Values.global.auth }}
{{- $_ := set $map .F7T_AUTH_ALGORITHM ""}}
{{- end }}
{{- keys $map | join ";" }}
{{- end }}