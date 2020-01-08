module github.com/quay/clair/v4

go 1.13

require (
	github.com/mattn/go-sqlite3 v1.11.0 // indirect
	github.com/quay/claircore v0.0.11
	github.com/rs/zerolog v1.16.0
	gocloud.dev v0.18.0 // indirect
	golang.org/x/sys v0.0.0-20191128015809-6d18c012aee9 // indirect
	golang.org/x/tools v0.0.0-20191210200704-1bcf67c9cb49 // indirect
	gopkg.in/yaml.v2 v2.2.5
)

replace github.com/quay/claircore => /home/louis/git/go/claircore
