module github.com/quay/clair/v3

go 1.13

replace (
	github.com/containerd/containerd v1.3.0-0.20190507210959-7c1e88399ec0 => github.com/containerd/containerd v1.3.1-0.20191217142032-9b5581cc9c5b
	github.com/docker/docker v1.14.0-0.20190319215453-e7b5f7dbe98c => github.com/docker/docker v1.4.2-0.20191210192822-1347481b9eb5
	github.com/tonistiigi/fsutil v0.0.0-20190819224149-3d2716dd0a4d => github.com/tonistiigi/fsutil v0.0.0-20191018213012-0f039a052ca1
)

require (
	github.com/asottile/dockerfile v2.2.0+incompatible
	github.com/buildkite/interpolate v0.0.0-20181028012610-973457fa2b4c
	github.com/coreos/pkg v0.0.0-20160727233714-3ac0863d7acf
	github.com/deckarep/golang-set v1.7.1
	github.com/fernet/fernet-go v0.0.0-20151007213151-1b2437bc582b
	github.com/go-stomp/stomp v2.0.4+incompatible
	github.com/golang/protobuf v1.3.2
	github.com/grpc-ecosystem/go-grpc-prometheus v0.0.0-20170330212424-2500245aa611
	github.com/grpc-ecosystem/grpc-gateway v1.2.3-0.20170531022852-2a40dd79571b
	github.com/guregu/null v3.4.0+incompatible
	github.com/hashicorp/golang-lru v0.5.0
	github.com/julienschmidt/httprouter v1.2.0
	github.com/lib/pq v1.2.0
	github.com/mattn/go-sqlite3 v1.11.0 // indirect
	github.com/moby/buildkit v0.6.3 // indirect
	github.com/pborman/uuid v0.0.0-20180906182336-adf5a7427709
	github.com/prometheus/client_golang v0.9.2
	github.com/quay/claircore v0.0.22 // indirect
	github.com/remind101/migrate v0.0.0-20170729031349-52c1edff7319
	github.com/sirupsen/logrus v1.4.2
	github.com/soheilhy/cmux v0.1.4
	github.com/stretchr/testify v1.4.0
	golang.org/x/net v0.0.0-20191004110552-13f9640d40b9
	golang.org/x/sync v0.0.0-20190423024810-112230192c58
	google.golang.org/genproto v0.0.0-20180817151627-c66870c02cf8
	google.golang.org/grpc v1.24.0
	gopkg.in/yaml.v2 v2.2.4
)
