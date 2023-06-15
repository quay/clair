check: github-workflow.json-schema yajsv yq
	for f in *.yml; do ./yq -o json "$$f" > "$${f%yml}json"; done
	./yajsv -s $< *.json
	rm *.json
	command -v yamllint >/dev/null 2>&1 && yamllint .

clean:
	rm -rf yq yajsv github-workflow.json-schema

.PHONY: check clean

yq:
	cd /tmp && GOBIN=$(PWD) go install github.com/mikefarah/yq/v4@latest

yajsv:
	cd /tmp && GOBIN=$(PWD) go install github.com/neilpa/yajsv@latest

github-workflow.json-schema:
	curl -sSLf https://github.com/SchemaStore/schemastore/raw/master/src/schemas/json/github-workflow.json > $@
