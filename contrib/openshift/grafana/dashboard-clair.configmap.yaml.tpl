apiVersion: v1
data:
  clair-dashboard.json: |
    GRAFANA_MANIFEST

kind: ConfigMap
metadata:
  creationTimestamp: null
  name: grafana-dashboard-clair
  labels:
    grafana_dashboard: "true"
  annotations:
    grafana-folder: /grafana-dashboard-definitions/Clair

