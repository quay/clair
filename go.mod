module github.com/quay/clair/v4

go 1.16

require (
	github.com/go-stomp/stomp v2.0.6+incompatible
	github.com/google/go-cmp v0.5.7
	github.com/google/go-containerregistry v0.6.0
	github.com/google/uuid v1.2.0
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79
	github.com/jackc/pgx/v4 v4.13.0
	github.com/klauspost/compress v1.13.6
	github.com/ldelossa/responserecorder v1.0.2-0.20210711162258-40bec93a9325
	github.com/mattn/go-sqlite3 v1.11.0 // indirect
	github.com/prometheus/client_golang v1.9.0
	github.com/quay/clair/config v1.0.0
	github.com/quay/claircore v1.3.0
	github.com/quay/zlog v1.1.0
	github.com/remind101/migrate v0.0.0-20170729031349-52c1edff7319
	github.com/rs/zerolog v1.26.0
	github.com/streadway/amqp v1.0.0
	github.com/tomnomnom/linkheader v0.0.0-20180905144013-02ca5825eb80
	github.com/ugorji/go/codec v1.2.4
	github.com/urfave/cli/v2 v2.3.0
	go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace v0.29.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.29.0
	go.opentelemetry.io/otel v1.4.0
	go.opentelemetry.io/otel/exporters/jaeger v1.4.0
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.4.0
	go.opentelemetry.io/otel/sdk v1.4.0
	go.opentelemetry.io/otel/trace v1.4.0
	golang.org/x/net v0.0.0-20211015210444-4f30a5c0130f
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba
	gopkg.in/square/go-jose.v2 v2.5.1
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

replace github.com/quay/clair/config => ./config
