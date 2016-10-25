<!--[metadata]>
+++
title = "Run a simple application"
description = "Learn how to manage and operate Docker containers."
keywords = ["docker, the docker guide, documentation, docker.io, monitoring containers, docker top, docker inspect, docker port, ports, docker logs, log,  Logs"]
[menu.main]
parent="engine_learn"
weight=-5
+++
<![end-metadata]-->

# Run a simple application

In the ["*Hello world in a container*"](dockerizing.md) you launched your
first containers using the `docker run` command. You ran an *interactive container* that ran in the foreground.  You also ran a *detached container* that ran in the background. In the process you learned about several Docker commands:

* `docker ps` - Lists containers.
* `docker logs` - Shows us the standard output of a container.
* `docker stop` - Stops running containers.

## Learn about the Docker client

If you didn't realize it yet, you've been using the Docker client each time you
typed `docker` in your Bash terminal. The client is a simple command line client
also known as a command-line interface (CLI). Each action you can take with
the client is a command and each command can take a series of flags and arguments.

    # Usage:  [sudo] docker [subcommand] [flags] [arguments] ..
    # Example:
    $ docker run -i -t ubuntu /bin/bash

You can see this in action by using the `docker version` command to return
version information on the currently installed Docker client and daemon.

    $ docker version

This command will not only provide you the version of Docker client and
daemon you are using, but also the version of Go (the programming
language powering Docker).

    Client:
      Version:      1.8.1
      API version:  1.20
      Go version:   go1.4.2
      Git commit:   d12ea79
      Built:        Thu Aug 13 02:35:49 UTC 2015
      OS/Arch:      linux/amd64

    Server:
      Version:      1.8.1
      API version:  1.20
      Go version:   go1.4.2
      Git commit:   d12ea79
      Built:        Thu Aug 13 02:35:49 UTC 2015
      OS/Arch:      linux/amd64

## Get Docker command help

You can display the help for specific Docker commands. The help details the
options and their usage. To see a list of all the possible commands, use the
following:

    $ docker --help

To see usage for a specific command, specify the command with the `--help` flag:

    $ docker attach --help

    Usage: docker attach [OPTIONS] CONTAINER

    Attach to a running container

      --help              Print usage
      --no-stdin          Do not attach stdin
      --sig-proxy=true    Proxy all received signals to the process

> **Note:**
> For further details and examples of each command, see the
> [command reference](../../reference/commandline/cli.md) in this guide.

## Running a web application in Docker

So now you've learned a bit more about the `docker` client you can move onto
the important stuff: running more containers. So far none of the
containers you've run did anything particularly useful, so you can
change that by running an example web application in Docker.

For our web application we're going to run a Python Flask application.
Start with a `docker run` command.

    $ docker run -d -P training/webapp python app.py

Review what the command did. You've specified two flags: `-d` and
`-P`. You've already seen the `-d` flag which tells Docker to run the
container in the background. The `-P` flag is new and tells Docker to
map any required network ports inside our container to our host. This
lets us view our web application.

You've specified an image: `training/webapp`. This image is a
pre-built image you've created that contains a simple Python Flask web
application.

Lastly, you've specified a command for our container to run: `python app.py`. This launches our web application.

> **Note:**
> You can see more detail on the `docker run` command in the [command
> reference](../../reference/commandline/run.md) and the [Docker Run
> Reference](../../reference/run.md).

## Viewing our web application container

Now you can see your running container using the `docker ps` command.

    $ docker ps -l
    CONTAINER ID  IMAGE                   COMMAND       CREATED        STATUS        PORTS                    NAMES
    bc533791f3f5  training/webapp:latest  python app.py 5 seconds ago  Up 2 seconds  0.0.0.0:49155->5000/tcp  nostalgic_morse

You can see you've specified a new flag, `-l`, for the `docker ps`
command. This tells the `docker ps` command to return the details of the
*last* container started.

> **Note:**
> By default, the `docker ps` command only shows information about running
> containers. If you want to see stopped containers too use the `-a` flag.

We can see the same details we saw [when we first Dockerized a
container](dockerizing.md) with one important addition in the `PORTS`
column.

    PORTS
    0.0.0.0:49155->5000/tcp

When we passed the `-P` flag to the `docker run` command Docker mapped any
ports exposed in our image to our host.

> **Note:**
> We'll learn more about how to expose ports in Docker images when
> [we learn how to build images](dockerimages.md).

In this case Docker has exposed port 5000 (the default Python Flask
port) on port 49155.

Network port bindings are very configurable in Docker. In our last example the
`-P` flag is a shortcut for `-p 5000` that maps port 5000 inside the container
to a high port (from *ephemeral port range* which typically ranges from 32768
to 61000) on the local Docker host. We can also bind Docker containers to
specific ports using the `-p` flag, for example:

    $ docker run -d -p 80:5000 training/webapp python app.py

This would map port 5000 inside our container to port 80 on our local
host. You might be asking about now: why wouldn't we just want to always
use 1:1 port mappings in Docker containers rather than mapping to high
ports? Well 1:1 mappings have the constraint of only being able to map
one of each port on your local host.

Suppose you want to test two Python applications: both bound to port 5000 inside
their own containers. Without Docker's port mapping you could only access one at
a time on the Docker host.

So you can now browse to port 49155 in a web browser to
see the application.

![Viewing the web application](webapp1.png).

Our Python application is live!

> **Note:**
> If you have been using a virtual machine on OS X, Windows or Linux,
> you'll need to get the IP of the virtual host instead of using localhost.
> You can do this by running the `docker-machine ip your_vm_name` from your  command line or terminal application, for example:
>
>     $ docker-machine ip my-docker-vm
>     192.168.99.100
>
> In this case you'd browse to `http://192.168.99.100:49155` for the above example.

## A network port shortcut

Using the `docker ps` command to return the mapped port is a bit clumsy so
Docker has a useful shortcut we can use: `docker port`. To use `docker port` we
specify the ID or name of our container and then the port for which we need the
corresponding public-facing port.

    $ docker port nostalgic_morse 5000
    0.0.0.0:49155

In this case you've looked up what port is mapped externally to port 5000 inside
the container.

## Viewing the web application's logs

You can also find out a bit more about what's happening with our application and
use another of the commands you've learned, `docker logs`.

    $ docker logs -f nostalgic_morse
    * Running on http://0.0.0.0:5000/
    10.0.2.2 - - [23/May/2014 20:16:31] "GET / HTTP/1.1" 200 -
    10.0.2.2 - - [23/May/2014 20:16:31] "GET /favicon.ico HTTP/1.1" 404 -

This time though you've added a new flag, `-f`. This causes the `docker
logs` command to act like the `tail -f` command and watch the
container's standard out. We can see here the logs from Flask showing
the application running on port 5000 and the access log entries for it.

## Looking at our web application container's processes

In addition to the container's logs we can also examine the processes
running inside it using the `docker top` command.

    $ docker top nostalgic_morse
    PID                 USER                COMMAND
    854                 root                python app.py

Here we can see our `python app.py` command is the only process running inside
the container.

## Inspecting our web application container

Lastly, we can take a low-level dive into our Docker container using the
`docker inspect` command. It returns a JSON document containing useful
configuration and status information for the specified container.

    $ docker inspect nostalgic_morse

You can see a sample of that JSON output.

    [{
        "ID": "bc533791f3f500b280a9626688bc79e342e3ea0d528efe3a86a51ecb28ea20",
        "Created": "2014-05-26T05:52:40.808952951Z",
        "Path": "python",
        "Args": [
           "app.py"
        ],
        "Config": {
           "Hostname": "bc533791f3f5",
           "Domainname": "",
           "User": "",
    . . .

We can also narrow down the information we want to return by requesting a
specific element, for example to return the container's IP address we would:

    $ docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' nostalgic_morse
    172.17.0.5

## Stopping our web application container

Okay you've seen web application working. Now you can stop it using the
`docker stop` command and the name of our container: `nostalgic_morse`.

    $ docker stop nostalgic_morse
    nostalgic_morse

We can now use the `docker ps` command to check if the container has
been stopped.

    $ docker ps -l

## Restarting our web application container

Oops! Just after you stopped the container you get a call to say another
developer needs the container back. From here you have two choices: you
can create a new container or restart the old one. Look at
starting your previous container back up.

    $ docker start nostalgic_morse
    nostalgic_morse

Now quickly run `docker ps -l` again to see the running container is
back up or browse to the container's URL to see if the application
responds.

> **Note:**
> Also available is the `docker restart` command that runs a stop and
> then start on the container.

## Removing our web application container

Your colleague has let you know that they've now finished with the container
and won't need it again. Now, you can remove it using the `docker rm` command.

    $ docker rm nostalgic_morse
    Error: Impossible to remove a running container, please stop it first or use -f
    2014/05/24 08:12:56 Error: failed to remove one or more containers

What happened? We can't actually remove a running container. This protects
you from accidentally removing a running container you might need. You can try
this again by stopping the container first.

    $ docker stop nostalgic_morse
    nostalgic_morse
    $ docker rm nostalgic_morse
    nostalgic_morse

And now our container is stopped and deleted.

> **Note:**
> Always remember that removing a container is final!

# Next steps

Until now you've only used images that you've downloaded from Docker Hub. Next,
you can get introduced to building and sharing our own images.

Go to [Working with Docker Images](dockerimages.md).
