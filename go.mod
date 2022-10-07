module github.com/quay/clair/v4

go 1.16

require (
	github.com/go-stomp/stomp v2.0.6+incompatible
	github.com/google/go-cmp v0.5.7
	github.com/google/go-containerregistry v0.6.0
	github.com/google/uuid v1.3.0
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79
	github.com/jackc/pgconn v1.10.0
	github.com/jackc/pgx/v4 v4.13.0
	github.com/klauspost/compress v1.13.6
	github.com/ldelossa/responserecorder v1.0.2-0.20210711162258-40bec93a9325
	github.com/prometheus/client_golang v1.12.2
	github.com/quay/clair/config v1.1.3
	github.com/quay/claircore v1.4.7
	github.com/quay/zlog v1.1.3
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
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba
	gopkg.in/square/go-jose.v2 v2.5.1
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/docker/cli v20.10.16+incompatible // indirect
	github.com/docker/docker v20.10.16+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.6.4 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/jackc/puddle v1.1.4 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/ulikunitz/xz v0.5.10 // indirect
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e // indirect
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a // indirect
	golang.org/x/tools v0.1.10 // indirect
	golang.org/x/xerrors v0.0.0-20220517211312-f3a8303e98df // indirect
)
