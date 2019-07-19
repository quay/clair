# Running Clair

The following document outlines possible ways to deploy Clair both on your local machine and to a cluster of machines.

## Official Container Repositories

Clair is officially packaged and released as a container.

* [quay.io/coreos/clair] - Stable releases
* [quay.io/coreos/clair-jwt] - Stable releases with an embedded instance of [jwtproxy]
* [quay.io/coreos/clair-git] - Development releases

[quay.io/coreos/clair]: https://quay.io/repository/coreos/clair
[jwtproxy]: https://github.com/coreos/jwtproxy
[quay.io/coreos/clair-jwt]: https://quay.io/repository/coreos/clair-jwt
[quay.io/coreos/clair-git]: https://quay.io/repository/coreos/clair-git

## Common Architecture

### Registry Integration

Clair can be integrated directly into a container registry such that the registry is responsible for interacting with Clair on behalf of the user.
This type of setup avoids the manual scanning of images and creates a sensible location to which Clair's vulnerability notifications can be propagated.
The registry can also be used for authorization to avoid sharing vulnerability information about images to which one might not have access.

![Simple Clair Diagram](https://cloud.githubusercontent.com/assets/343539/21630809/c1adfbd2-d202-11e6-9dfe-9024139d0a28.png)

### CI/CD Integration

Clair can be integrated into a CI/CD pipeline such that when a container image is produced, the step after pushing the image to a registry is to compose a request for Clair to scan that particular image.
This type of integration is more flexible, but relies on additional components to be setup in order to secure.

## Deployment Strategies

**NOTE:** These instructions demonstrate running HEAD and not stable versions.

The following are community supported instructions to run Clair in a variety of ways.
A [PostgreSQL 9.4+] database instance is required for all instructions.

[PostgreSQL 9.4+]: https://www.postgresql.org

### Local

[Local Development]: ./local-development.md

See [Local Development] for our Kubernetes based local development environment.

### Docker

```sh
$ mkdir $PWD/clair_config
$ curl -L https://raw.githubusercontent.com/coreos/clair/master/config.yaml.sample -o $PWD/clair_config/config.yaml
$ docker run -d -e POSTGRES_PASSWORD="" -p 5432:5432 postgres:9.6
$ docker run --net=host -d -p 6060-6061:6060-6061 -v $PWD/clair_config:/config quay.io/coreos/clair-git:latest -config=/config/config.yaml
```

#### Source

Clair currently uses glide as it's package management solution.
The vendor folder is checked into this repository and running 'glide up' should not be necessary.
Find more information on glide here: [Glide]

[Glide]: https://github.com/Masterminds/glide

To build Clair, you need the latest stable version of [Go] and a working [Go environment].
In addition, Clair requires some additional binaries be installed on the system [$PATH] as runtime dependencies:

* [git]
* [rpm]
* [xz]

[Go]: https://github.com/golang/go/releases
[Go environment]: https://golang.org/doc/code.html
[git]: https://git-scm.com
[rpm]: http://www.rpm.org
[xz]: http://tukaani.org/xz
[$PATH]: https://en.wikipedia.org/wiki/PATH_(variable)

```sh
$ go get github.com/coreos/clair
$ go install github.com/coreos/clair/cmd/clair
$ $EDITOR config.yaml # Add the URI for your postgres database
$ ./$GOPATH/bin/clair -config=config.yaml
```

## Troubleshooting

### I just started up Clair and nothing appears to be working, what's the deal?

During the first run, Clair will bootstrap its database with vulnerability data from the configured data sources.
It can take several minutes before the database has been fully populated, but once this data is stored in the database, subsequent updates will take far less time.

### I'm seeing Linux kernel vulnerabilities in my image, that doesn't make any sense since containers share the host kernel!

Many container base images using Linux distributions as a foundation will install dummy kernel packages that do nothing but satisfy their package manager's dependency requirements.
The Clair developers have taken the stance that Clair should not filter results, providing the most accurate data as possible to user interfaces that can then apply filters that make sense for their users.
