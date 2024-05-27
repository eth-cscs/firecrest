{{- define "list.listPubKeys" -}}
{{- $pubKeys := list -}}
{{- range .Values.global.auth -}}
{{- $pubKeys = append $pubKeys .F7T_AUTH_PUBKEY -}}
{{- end -}}
{{- join ";" $pubKeys -}}
{{- end -}}

{{- define "list.listPubKeyTypes" -}}
{{- $pubKeyTypes := list -}}
{{- range .Values.global.auth -}}
{{- $pubKeyTypes = append $pubKeyTypes .F7T_AUTH_ALGORITHM -}}
{{- end -}}
{{- join ";" $pubKeyTypes -}}
{{- end -}}