module github.com/quay/clair/v4

go 1.17

require (
	github.com/go-stomp/stomp v2.0.6+incompatible
	github.com/google/go-cmp v0.5.7
	github.com/google/go-containerregistry v0.6.0
	github.com/google/uuid v1.2.0
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79
	github.com/jackc/pgconn v1.10.0
	github.com/jackc/pgx/v4 v4.13.0
	github.com/klauspost/compress v1.13.6
	github.com/ldelossa/responserecorder v1.0.2-0.20210711162258-40bec93a9325
	github.com/prometheus/client_golang v1.12.1
	github.com/quay/clair/config v1.0.0
	github.com/quay/claircore v1.3.2
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
	golang.org/x/net v0.0.0-20211015210444-4f30a5c0130f
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba
	gopkg.in/square/go-jose.v2 v2.5.1
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

require (
	github.com/aquasecurity/go-pep440-version v0.0.0-20210121094942-22b2f8951d46 // indirect
	github.com/aquasecurity/go-version v0.0.0-20210121072130-637058cfe492 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/docker/cli v20.10.7+incompatible // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v20.10.7+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.6.3 // indirect
	github.com/doug-martin/goqu/v8 v8.6.0 // indirect
	github.com/felixge/httpsnoop v1.0.2 // indirect
	github.com/go-logr/logr v1.2.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.1.1 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/pgtype v1.8.1 // indirect
	github.com/jackc/puddle v1.1.3 // indirect
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f // indirect
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d // indirect
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936 // indirect
	github.com/mattn/go-sqlite3 v1.11.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/quay/alas v1.0.1 // indirect
	github.com/quay/goval-parser v0.8.6 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/ulikunitz/xz v0.5.8 // indirect
	go.opentelemetry.io/otel/internal/metric v0.27.0 // indirect
	go.opentelemetry.io/otel/metric v0.27.0 // indirect
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/mod v0.5.1 // indirect
	golang.org/x/sys v0.0.0-20220209214540-3681064d5158 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/tools v0.1.9 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/protobuf v1.26.0 // indirect
)

replace github.com/quay/clair/config => ./config
