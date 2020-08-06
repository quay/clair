module github.com/quay/clair/v3

go 1.13

replace (
	github.com/containerd/containerd v1.3.0-0.20190507210959-7c1e88399ec0 => github.com/containerd/containerd v1.3.1-0.20191217142032-9b5581cc9c5b
	github.com/docker/docker v1.14.0-0.20190319215453-e7b5f7dbe98c => github.com/docker/docker v1.4.2-0.20191210192822-1347481b9eb5
	github.com/tonistiigi/fsutil v0.0.0-20190819224149-3d2716dd0a4d => github.com/tonistiigi/fsutil v0.0.0-20191018213012-0f039a052ca1
)

require (
	github.com/PuerkitoBio/goquery v1.5.1
	github.com/asottile/dockerfile v2.2.0+incompatible
	github.com/buildkite/interpolate v0.0.0-20181028012610-973457fa2b4c
	github.com/coreos/clair v1.2.6
	github.com/coreos/pkg v0.0.0-20160727233714-3ac0863d7acf
	github.com/deckarep/golang-set v1.7.1
	github.com/fernet/fernet-go v0.0.0-20151007213151-1b2437bc582b
	github.com/go-stomp/stomp v2.0.6+incompatible
	github.com/golang/protobuf v1.2.0
	github.com/google/go-cmp v0.3.0 // indirect
	github.com/google/uuid v1.1.0 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v0.0.0-20170330212424-2500245aa611
	github.com/grpc-ecosystem/grpc-gateway v1.2.3-0.20170531022852-2a40dd79571b
	github.com/guregu/null v3.4.0+incompatible
	github.com/hashicorp/golang-lru v0.5.0
	github.com/julienschmidt/httprouter v1.2.0
	github.com/lib/pq v0.0.0-20170603225454-8837942c3e09
	github.com/mattn/go-sqlite3 v1.11.0 // indirect
	github.com/moby/buildkit v0.6.3 // indirect
	github.com/pborman/uuid v0.0.0-20180906182336-adf5a7427709
	github.com/prometheus/client_golang v0.9.2
	github.com/remind101/migrate v0.0.0-20160423010909-d22d647232c2
	github.com/sirupsen/logrus v1.4.1
	github.com/soheilhy/cmux v0.1.4
	github.com/stretchr/testify v1.3.0
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b // indirect
	golang.org/x/net v0.0.0-20200226121028-0de0cce0169b
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/tools v0.0.0-20200601175630-2caf76543d99 // indirect
	google.golang.org/genproto v0.0.0-20180817151627-c66870c02cf8
	google.golang.org/grpc v1.23.0
	gopkg.in/yaml.v2 v2.2.2
)
