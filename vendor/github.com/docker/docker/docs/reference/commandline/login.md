<!--[metadata]>
+++
title = "login"
description = "The login command description and usage"
keywords = ["registry, login, image"]
[menu.main]
parent = "smn_cli"
+++
<![end-metadata]-->

# login

    Usage: docker login [OPTIONS] [SERVER]

    Log in to a Docker registry server, if no server is
	specified "https://index.docker.io/v1/" is the default.

      --help               Print usage
      -p, --password=""    Password
      -u, --username=""    Username

If you want to login to a self-hosted registry you can specify this by
adding the server name.

    example:
    $ docker login localhost:8080


`docker login` requires user to use `sudo` or be `root`, except when:

1.  connecting to a remote daemon, such as a `docker-machine` provisioned `docker engine`.
2.  user is added to the `docker` group.  This will impact the security of your system; the `docker` group is `root` equivalent.  See [Docker Daemon Attack Surface](https://docs.docker.com/security/security/#docker-daemon-attack-surface) for details.

You can log into any public or private repository for which you have
credentials.  When you log in, the command stores encoded credentials in
`$HOME/.docker/config.json` on Linux or `%USERPROFILE%/.docker/config.json` on Windows.

> **Note**:  When running `sudo docker login` credentials are saved in `/root/.docker/config.json`.
>

## Credentials store

The Docker Engine can keep user credentials in an external credentials store,
such as the native keychain of the operating system. Using an external store
is more secure than storing credentials in the Docker configuration file.

To use a credentials store, you need an external helper program to interact
with a specific keychain or external store. Docker requires the helper
program to be in the client's host `$PATH`.

This is the list of currently available credentials helpers and where
you can download them from:

- Apple OS X keychain: https://github.com/docker/docker-credential-helpers/releases
- Microsoft Windows Credential Manager: https://github.com/docker/docker-credential-helpers/releases

### Usage

You need to speficy the credentials store in `HOME/.docker/config.json`
to tell the docker engine to use it:

```json
{
	"credsStore": "osxkeychain"
}
```

If you are currently logged in, run `docker logout` to remove
the credentials from the file and run `docker login` again.

### Protocol

Credential helpers can be any program or script that follows a very simple protocol.
This protocol is heavily inspired by Git, but it differs in the information shared.

The helpers always use the first argument in the command to identify the action.
There are only three possible values for that argument: `store`, `get`, and `erase`.

The `store` command takes a JSON payload from the standard input. That payload carries
the server address, to identify the credential, the user name and the password.
This is an example of that payload:

```json
{
	"ServerURL": "https://index.docker.io/v1",
	"Username": "david",
	"Password": "passw0rd1"
}
```

The `store` command can write error messages to `STDOUT` that the docker engine
will show if there was an issue.

The `get` command takes a string payload from the standard input. That payload carries
the server address that the docker engine needs credentials for. This is
an example of that payload: `https://index.docker.io/v1`.

The `get` command writes a JSON payload to `STDOUT`. Docker reads the user name
and password from this payload:

```json
{
	"Username": "david",
	"Password": "passw0rd1"
}
```

The `erase` command takes a string payload from `STDIN`. That payload carries
the server address that the docker engine wants to remove credentials for. This is
an example of that payload: `https://index.docker.io/v1`.

The `erase` command can write error messages to `STDOUT` that the docker engine
will show if there was an issue.
