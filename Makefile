.PHONY: local-deploy
local-deploy:
	./local-dev/build.sh
	-helm install --name clair-pg ./local-dev/helm/clair-pg
	-helm delete --purge clair
	helm install --name clair ./local-dev/helm/clair

.PHONY: local-teardown
local-teardown:
	-helm delete --purge clair
	-helm delete --purge clair-pg

