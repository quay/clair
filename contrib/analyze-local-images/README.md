# Analyze local images

This is a basic tool that allow you to analyze your local Docker images with Clair.
It is intended to let everyone discover Clair and offer awareness around containers' security.
There are absolutely no guarantees and it only uses a minimal subset of Clair's features.

## Install

You need to install this tool:

    go get -u github.com/coreos/clair/contrib/analyze-local-images

You also need a working Clair instance, the bare minimal setup is to run Clair in a Docker instance without much configuration,
To learn more about how to run Clair, take a look at the [doc](https://github.com/coreos/clair/blob/master/docs/Run.md):

    docker run -it -v /tmp:/tmp -p 6060:6060 -p 6061:6061 -v <DIR_WITH_CONFIG>:/config:ro quay.io/coreos/clair:latest --config=/config/<CONFIG_FILENAME>.yaml

You will need to let it do its initial vulnerability update, which may take some time.

# Usage

If you are running Clair locally (ie. compiled or local Docker),

```
analyze-local-images <Docker Image ID>
```

Or, If you run Clair remotely (ie. boot2docker),

```
analyze-local-images -endpoint "http://<CLAIR-IP-ADDRESS>:6060" -my-address "<MY-IP-ADDRESS>" <Docker Image ID>
```

Clair needs access to the image files. If you run Clair locally, this tool will store the files in the system's temporary folder and Clair will find them there. It means if Clair is running in Docker, the host's temporary folder must be mounted in the Clair's container. If you run Clair remotely, this tool will run a small HTTP server to let Clair downloading them. It listens on the port 9279 and allows a single host: Clair's IP address, extracted from the `-endpoint` parameter. The `my-address` parameters defines the IP address of the HTTP server that Clair will use to download the images. With boot2docker, these parameters would be `-endpoint "http://192.168.99.100:6060" -my-address "192.168.99.1"`.

As it runs an HTTP server and not an HTTP**S** one, be sure to **not** expose sensitive data and container images.
