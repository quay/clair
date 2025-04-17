otelcollector: builder.yaml
	go run go.opentelemetry.io/collector/cmd/builder@v0.109.0 --config=builder.yaml
	cp _build/otelcollector .

.PHONY: clean
clean:
	rm -rf _build otelcollector
