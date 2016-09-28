<!--[metadata]>
+++
title = "Use the Docker command line"
description = "Docker's CLI command description and usage"
keywords = ["Docker, Docker documentation, CLI,  command line"]
[menu.main]
parent = "smn_cli"
weight = -2
+++
<![end-metadata]-->

# Use the Docker command line

To list available commands, either run `docker` with no parameters
or execute `docker help`:

    $ docker
      Usage: docker [OPTIONS] COMMAND [arg...]
             docker daemon [ --help | ... ]
             docker [ --help | -v | --version ]

        -H, --host=[]: The socket(s) to talk to the Docker daemon in the format of tcp://host:port/path, unix:///path/to/socket, fd://* or fd://socketfd.

      A self-sufficient runtime for Linux containers.

      ...

Depending on your Docker system configuration, you may be required to preface
each `docker` command with `sudo`. To avoid having to use `sudo` with the
`docker` command, your system administrator can create a Unix group called
`docker` and add users to it.

For more information about installing Docker or `sudo` configuration, refer to
the [installation](../../installation/index.md) instructions for your operating system.

## Environment variables

For easy reference, the following list of environment variables are supported
by the `docker` command line:

* `DOCKER_API_VERSION` The API version to use (e.g. `1.19`)
* `DOCKER_CONFIG` The location of your client configuration files.
* `DOCKER_CERT_PATH` The location of your authentication keys.
* `DOCKER_DRIVER` The graph driver to use.
* `DOCKER_HOST` Daemon socket to connect to.
* `DOCKER_NOWARN_KERNEL_VERSION` Prevent warnings that your Linux kernel is
  unsuitable for Docker.
* `DOCKER_RAMDISK` If set this will disable 'pivot_root'.
* `DOCKER_TLS_VERIFY` When set Docker uses TLS and verifies the remote.
* `DOCKER_CONTENT_TRUST` When set Docker uses notary to sign and verify images.
  Equates to `--disable-content-trust=false` for build, create, pull, push, run.
* `DOCKER_CONTENT_TRUST_SERVER` The URL of the Notary server to use. This defaults
  to the same URL as the registry.
* `DOCKER_TMPDIR` Location for temporary Docker files.

Because Docker is developed using 'Go', you can also use any environment
variables used by the 'Go' runtime. In particular, you may find these useful:

* `HTTP_PROXY`
* `HTTPS_PROXY`
* `NO_PROXY`

These Go environment variables are case-insensitive. See the
[Go specification](http://golang.org/pkg/net/http/) for details on these
variables.

## Configuration files

By default, the Docker command line stores its configuration files in a
directory called `.docker` within your `HOME` directory. However, you can
specify a different location via the `DOCKER_CONFIG` environment variable
or the `--config` command line option. If both are specified, then the
`--config` option overrides the `DOCKER_CONFIG` environment variable.
For example:

    docker --config ~/testconfigs/ ps

Instructs Docker to use the configuration files in your `~/testconfigs/`
directory when running the `ps` command.

Docker manages most of the files in the configuration directory
and you should not modify them. However, you *can modify* the
`config.json` file to control certain aspects of how the `docker`
command behaves.

Currently, you can modify the `docker` command behavior using environment
variables or command-line options. You can also use options within
`config.json` to modify some of the same behavior. When using these
mechanisms, you must keep in mind the order of precedence among them. Command
line options override environment variables and environment variables override
properties you specify in a `config.json` file.

The `config.json` file stores a JSON encoding of several properties:

The property `HttpHeaders` specifies a set of headers to include in all messages
sent from the Docker client to the daemon. Docker does not try to interpret or
understand these header; it simply puts them into the messages. Docker does
not allow these headers to change any headers it sets for itself.

The property `psFormat` specifies the default format for `docker ps` output.
When the `--format` flag is not provided with the `docker ps` command,
Docker's client uses this property. If this property is not set, the client
falls back to the default table format. For a list of supported formatting
directives, see the
[**Formatting** section in the `docker ps` documentation](ps.md)

Once attached to a container, users detach from it and leave it running using
the using `CTRL-p CTRL-q` key sequence. This detach key sequence is customizable
using the `detachKeys` property. Specify a `<sequence>` value for the
property. The format of the `<sequence>` is a comma-separated list of either 
a letter [a-Z], or the `ctrl-` combined with any of the following:

* `a-z` (a single lowercase alpha character )
* `@` (at sign)
* `[` (left bracket)
* `\\` (two backward slashes)
*  `_` (underscore)
* `^` (caret)

Your customization applies to all containers started in with your Docker client.
Users can override your custom or the default key sequence on a per-container
basis. To do this, the user specifies the `--detach-keys` flag with the `docker
attach`, `docker exec`, `docker run` or `docker start` command.

The property `imagesFormat` specifies the default format for `docker images` output.
When the `--format` flag is not provided with the `docker images` command,
Docker's client uses this property. If this property is not set, the client
falls back to the default table format. For a list of supported formatting
directives, see the [**Formatting** section in the `docker images` documentation](images.md)

Following is a sample `config.json` file:

    {
      "HttpHeaders": {
        "MyHeader": "MyValue"
      },
      "psFormat": "table {{.ID}}\\t{{.Image}}\\t{{.Command}}\\t{{.Labels}}",
      "imagesFormat": "table {{.ID}}\\t{{.Repository}}\\t{{.Tag}}\\t{{.CreatedAt}}",
      "detachKeys": "ctrl-e,e"
    }

### Notary

If using your own notary server and a self-signed certificate or an internal
Certificate Authority, you need to place the certificate at
`tls/<registry_url>/ca.crt` in your docker config directory.

Alternatively you can trust the certificate globally by adding it to your system's
list of root Certificate Authorities.

## Help

To list the help on any command just execute the command, followed by the
`--help` option.

    $ docker run --help

    Usage: docker run [OPTIONS] IMAGE [COMMAND] [ARG...]

    Run a command in a new container

      -a, --attach=[]            Attach to STDIN, STDOUT or STDERR
      --cpu-shares=0             CPU shares (relative weight)
    ...

## Option types

Single character command line options can be combined, so rather than
typing `docker run -i -t --name test busybox sh`,
you can write `docker run -it --name test busybox sh`.

### Boolean

Boolean options take the form `-d=false`. The value you see in the help text is
the default value which is set if you do **not** specify that flag. If you
specify a Boolean flag without a value, this will set the flag to `true`,
irrespective of the default value.

For example, running `docker run -d` will set the value to `true`, so your
container **will** run in "detached" mode, in the background.

Options which default to `true` (e.g., `docker build --rm=true`) can only be
set to the non-default value by explicitly setting them to `false`:

    $ docker build --rm=false .

### Multi

You can specify options like `-a=[]` multiple times in a single command line,
for example in these commands:

    $ docker run -a stdin -a stdout -i -t ubuntu /bin/bash
    $ docker run -a stdin -a stdout -a stderr ubuntu /bin/ls

Sometimes, multiple options can call for a more complex value string as for
`-v`:

    $ docker run -v /host:/container example/mysql

> **Note:**
> Do not use the `-t` and `-a stderr` options together due to
> limitations in the `pty` implementation. All `stderr` in `pty` mode
> simply goes to `stdout`.

### Strings and Integers

Options like `--name=""` expect a string, and they
can only be specified once. Options like `-c=0`
expect an integer, and they can only be specified once.
