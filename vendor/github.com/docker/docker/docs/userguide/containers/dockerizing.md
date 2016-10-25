<!--[metadata]>
+++
aliases = ["/engine/userguide/dockerizing/"]
title = "Hello world in a container"
description = "A simple 'Hello world' exercise that introduced you to Docker."
keywords = ["docker guide, docker, docker platform, how to, dockerize, dockerizing apps, dockerizing applications, container,  containers"]
[menu.main]
parent="engine_learn"
weight=-6
+++
<![end-metadata]-->

# Hello world in a container

*So what's this Docker thing all about?*

Docker allows you to run applications, worlds you create, inside containers.
Running an application inside a container takes a single command: `docker run`.

>**Note**: Depending on your Docker system configuration, you may be required to
>preface each `docker` command on this page with `sudo`. To avoid this behavior,
>your system administrator can create a Unix group called `docker` and add users
>to it.

## Run a Hello world

Let's try it now.

    $ docker run ubuntu /bin/echo 'Hello world'
    Hello world

And you just launched your first container!

So what just happened? Let's step through what the `docker run` command
did.

First we specified the `docker` binary and the command we wanted to
execute, `run`. The `docker run` combination *runs* containers.

Next we specified an image: `ubuntu`. This is the source of the container
we ran. Docker calls this an image. In this case we used the Ubuntu
operating system image.

When you specify an image, Docker looks first for the image on your
Docker host. If it can't find it then it downloads the image from the public
image registry: [Docker Hub](https://hub.docker.com).

Next we told Docker what command to run inside our new container:

    /bin/echo 'Hello world'

When our container was launched Docker created a new Ubuntu
environment and then executed the `/bin/echo` command inside it. We saw
the result on the command line:

    Hello world

So what happened to our container after that? Well Docker containers
only run as long as the command you specify is active. Here, as soon as
`Hello world` was echoed, the container stopped.

## An interactive container

Let's try the `docker run` command again, this time specifying a new
command to run in our container.

    $ docker run -t -i ubuntu /bin/bash
    root@af8bae53bdd3:/#

Here we've again specified the `docker run` command and launched an
`ubuntu` image. But we've also passed in two flags: `-t` and `-i`.
The `-t` flag assigns a pseudo-tty or terminal inside our new container
and the `-i` flag allows us to make an interactive connection by
grabbing the standard in (`STDIN`) of the container.

We've also specified a new command for our container to run:
`/bin/bash`. This will launch a Bash shell inside our container.

So now when our container is launched we can see that we've got a
command prompt inside it:

    root@af8bae53bdd3:/#

Let's try running some commands inside our container:

    root@af8bae53bdd3:/# pwd
    /
    root@af8bae53bdd3:/# ls
    bin boot dev etc home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var

You can see we've run the `pwd` to show our current directory and can
see we're in the `/` root directory. We've also done a directory listing
of the root directory which shows us what looks like a typical Linux
file system.

You can play around inside this container and when you're done you can
use the `exit` command or enter Ctrl-D to finish.

    root@af8bae53bdd3:/# exit

As with our previous container, once the Bash shell process has
finished, the container is stopped.

## A daemonized Hello world

Now a container that runs a command and then exits has some uses but
it's not overly helpful. Let's create a container that runs as a daemon,
like most of the applications we're probably going to run with Docker.

Again we can do this with the `docker run` command:

    $ docker run -d ubuntu /bin/sh -c "while true; do echo hello world; sleep 1; done"
    1e5535038e285177d5214659a068137486f96ee5c2e85a4ac52dc83f2ebe4147

Wait, what? Where's our "hello world" output? Let's look at what we've run here.
It should look pretty familiar. We ran `docker run` but this time we
specified a flag: `-d`. The `-d` flag tells Docker to run the container
and put it in the background, to daemonize it.

We also specified the same image: `ubuntu`.

Finally, we specified a command to run:

    /bin/sh -c "while true; do echo hello world; sleep 1; done"

This is the (hello) world's silliest daemon: a shell script that echoes
`hello world` forever.

So why aren't we seeing any `hello world`'s? Instead Docker has returned
a really long string:

    1e5535038e285177d5214659a068137486f96ee5c2e85a4ac52dc83f2ebe4147

This really long string is called a *container ID*. It uniquely
identifies a container so we can work with it.

> **Note:**
> The container ID is a bit long and unwieldy. A bit later,
> we'll see a shorter ID and ways to name our containers to make
> working with them easier.

We can use this container ID to see what's happening with our `hello world` daemon.

Firstly let's make sure our container is running. We can
do that with the `docker ps` command. The `docker ps` command queries
the Docker daemon for information about all the containers it knows
about.

    $ docker ps
    CONTAINER ID  IMAGE         COMMAND               CREATED        STATUS       PORTS NAMES
    1e5535038e28  ubuntu  /bin/sh -c 'while tr  2 minutes ago  Up 1 minute        insane_babbage

Here we can see our daemonized container. The `docker ps` has returned some useful
information about it, starting with a shorter variant of its container ID:
`1e5535038e28`.

We can also see the image we used to build it, `ubuntu`, the command it
is running, its status and an automatically assigned name,
`insane_babbage`.

> **Note:**
> Docker automatically generates names for any containers started.
> We'll see how to specify your own names a bit later.

Okay, so we now know it's running. But is it doing what we asked it to do? To
see this we're going to look inside the container using the `docker logs`
command. Let's use the container name Docker assigned.

    $ docker logs insane_babbage
    hello world
    hello world
    hello world
    . . .

The `docker logs` command looks inside the container and returns its standard
output: in this case the output of our command `hello world`.

Awesome! Our daemon is working and we've just created our first
Dockerized application!

Now we've established we can create our own containers let's tidy up
after ourselves and stop our detached container. To do this we use the
`docker stop` command.

    $ docker stop insane_babbage
    insane_babbage

The `docker stop` command tells Docker to politely stop the running
container. If it succeeds it will return the name of the container it
has just stopped.

Let's check it worked with the `docker ps` command.

    $ docker ps
    CONTAINER ID  IMAGE         COMMAND               CREATED        STATUS       PORTS NAMES

Excellent. Our container has been stopped.

# Next steps

So far, you launched your first containers using the `docker run` command. You
ran an *interactive container* that ran in the foreground. You also ran a
*detached container* that ran in the background. In the process you learned
about several Docker commands:

* `docker ps` - Lists containers.
* `docker logs` - Shows us the standard output of a container.
* `docker stop` - Stops running containers.

Now, you have the basis learn more about Docker and how to do some more advanced
tasks. Go to ["*Run a simple application*"](usingdocker.md) to actually build a
web application with the Docker client.
