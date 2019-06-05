# this make target is designed to be ran idempotently. each run deploys the latest code in the repository
# requires kubernetes. both minikube and docker desktop is supported.
.PHONY: deploy-local
deploy-local:
	./local-dev/build.sh
	-helm dependency update ./local-dev/helm/clair-pg
	-helm install --name clair-pg ./local-dev/helm/clair-pg
	-helm delete --purge clair
	helm install --name clair ./local-dev/helm/clair

# this make target tears down local dev environment deployed by the above target
.PHONY: teardown-local
teardown-local:
	-helm delete --purge clair
	-helm delete --purge clair-pg

