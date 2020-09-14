# Testing Clair

We provide dev tooling in order to quickly get a fully configured Clair and Quay environment stood up locally. This environment can be used to test and develop Clair.

## Requirements

### Make

Make is used to stand up the the local dev environment. 
Make is readily available in just about every package manager you can think of.
It's very likely your workstation already has make on it.

### Docker and Docker Compose

Currently our local dev tooling is supported by docker and docker-compose. We are making strides to provide a podman native local dev environment but we are not quite there yet.

Docker version 19.03.11 and docker-compose version 1.25.4 are confirmed working. Our assumption is most recent versions will not have an issue running the local dev tooling.

See [Install Docker](https://docs.docker.com/get-docker/)

### Go Toolchain

Go v1.13 or higher is required.

See [Install Golang](https://golang.org/doc/install)

## Starting a cluster

```
git clone git@github.com:quay/clair.git
cd clair
make local-dev-up-with-quay
```

After the local development environment successfully starts, the following infrastructure is available to you:

```
localhost:8080 --- Quay (single node, local storage)

localhost:6060 --- Traefik which hosts all ClairV4 endpoints.
                   ClairV4 services are only accessible via this load balancer.

localhost:5432 --- ClairV4's Postgres DB
                   Login:
                      username: clair
                      database: clair

localhost:5433 --- Quay's Postgres DB
                   Login:
                     username: quay
                     database: quay

localhost:8082 --- OpenAPI Swagger Editor.
                   You can view ClairV4's public API here.

localhost:7000 --- Traefik Web UI.
                   Good for troubleshooting http issues.

localhost:9090 --- Prometheus
```

## Pushing to the Local Quay

As mentioned above ,Quay is present at `localhost:8080`. You may navigate to this address and create a account. Creating an account named `admin` will ensure you are a super user. An email is required, but is not validated.

Once inside, you will create an organization named "clairv4-org". Currently Quay has to explicitly enable Clair v4 security scanning, which is done via an organization allowlist. "Clairv4-org" is preconfigured in our local dev configuration.

The easiest way to push to Quay is using podman:

```
podman pull ubuntu:latest
podman login --tls-verify=false localhost:8080 # use account created in above steps
podman tag ubuntu:latest localhost:8080/clairv4-org/testing:latest
podman push --tls-verify=false localhost:8080/clairv4-org/testing:latest
```

Using docker to push is possible, however you will need to add "localhost:8080" as an insecure repository. See [Insecure Repository](https://docs.docker.com/registry/insecure/)

## Making changes to configuration

You may want to play with either Clair or Quay's configuration. 
If so, the configuration files can be found inside the repository at
`local-dev/quay/config.yaml` and `local-dev/clair.yaml`.

Any changes to the configs will require a restart of the relevant service. Take a look at the `Makefile` for the various restart targets.

## Tearing it down

```
make local-dev-down
```

will rip the entire environment down.


## Troubleshooting

The most common issue encountered when standing up the dev environment is port conflicts. Make sure that you do not have any other processes listening on any of the ports outlined above.

The second issue you may face is your Docker resource settings maybe too constrained to support the local dev stack. This is typically seen on Docker4Mac since a VM is used with a specific set of resources configured. See [Docker For Mac Manual](https://docs.docker.com/docker-for-mac/) for instructions on how to change these resources.
