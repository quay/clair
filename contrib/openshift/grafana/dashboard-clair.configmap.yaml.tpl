# WARNING: This is generated from local-dev/grafana/data/dashboards/dashboard.json
# please modify there and run make contrib/openshift/grafana/dashboards/dashboard-clair.configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  creationTimestamp: null
  name: grafana-dashboard-clair
  labels:
    grafana_dashboard: "true"
  annotations:
    grafana-folder: /grafana-dashboard-definitions/Clair
data:
  clair-dashboard.json: |-
GRAFANA_MANIFEST
