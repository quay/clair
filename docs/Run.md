# Running Clair

## Configuration

Clair makes uses of a configuration file in YAML.

Copy [`config.example.yaml`](../config.example.yaml) to your choice of location, and update the values as required.
The example configuration file is commented and explains every available key.

## Docker

The easiest way to run Clair is with Docker.

```
$ docker pull quay.io/coreos/clair:latest
$ docker run -p 6060:6060 -p 6061:6061 -v <DIR_WITH_CONFIG>:/config:ro quay.io/coreos/clair:latest --config=/config/<CONFIG_FILENAME>.yaml
```

## Initial update & API

Right after Clair starts, it will update its vulnerability database.
The initial update can take quite a long time depending on the database backend in use.
Clair will announce the update completion.

As soon as Clair has started, you can start querying the API to interact with it.
Read the [API Documentation](API.md) to learn more.
The [`contrib`](../contrib) folder contains some tools that may help you to get started.
