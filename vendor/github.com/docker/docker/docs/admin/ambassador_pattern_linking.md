<!--[metadata]>
+++
aliases = ["/engine/articles/ambassador_pattern_linking/"]
title = "Link via an ambassador container"
description = "Using the Ambassador pattern to abstract (network) services"
keywords = ["Examples, Usage, links, docker, documentation, examples, names, name,  container naming"]
[menu.main]
parent = "engine_admin"
weight = 6
+++
<![end-metadata]-->

# Link via an ambassador container

Rather than hardcoding network links between a service consumer and
provider, Docker encourages service portability, for example instead of:

    (consumer) --> (redis)

Requiring you to restart the `consumer` to attach it to a different
`redis` service, you can add ambassadors:

    (consumer) --> (redis-ambassador) --> (redis)

Or

    (consumer) --> (redis-ambassador) ---network---> (redis-ambassador) --> (redis)

When you need to rewire your consumer to talk to a different Redis
server, you can just restart the `redis-ambassador` container that the
consumer is connected to.

This pattern also allows you to transparently move the Redis server to a
different docker host from the consumer.

Using the `svendowideit/ambassador` container, the link wiring is
controlled entirely from the `docker run` parameters.

## Two host example

Start actual Redis server on one Docker host

    big-server $ docker run -d --name redis crosbymichael/redis

Then add an ambassador linked to the Redis server, mapping a port to the
outside world

    big-server $ docker run -d --link redis:redis --name redis_ambassador -p 6379:6379 svendowideit/ambassador

On the other host, you can set up another ambassador setting environment
variables for each remote port we want to proxy to the `big-server`

    client-server $ docker run -d --name redis_ambassador --expose 6379 -e REDIS_PORT_6379_TCP=tcp://192.168.1.52:6379 svendowideit/ambassador

Then on the `client-server` host, you can use a Redis client container
to talk to the remote Redis server, just by linking to the local Redis
ambassador.

    client-server $ docker run -i -t --rm --link redis_ambassador:redis relateiq/redis-cli
    redis 172.17.0.160:6379> ping
    PONG

## How it works

The following example shows what the `svendowideit/ambassador` container
does automatically (with a tiny amount of `sed`)

On the Docker host (192.168.1.52) that Redis will run on:

    # start actual redis server
    $ docker run -d --name redis crosbymichael/redis

    # get a redis-cli container for connection testing
    $ docker pull relateiq/redis-cli

    # test the redis server by talking to it directly
    $ docker run -t -i --rm --link redis:redis relateiq/redis-cli
    redis 172.17.0.136:6379> ping
    PONG
    ^D

    # add redis ambassador
    $ docker run -t -i --link redis:redis --name redis_ambassador -p 6379:6379 alpine:3.2 sh

In the `redis_ambassador` container, you can see the linked Redis
containers `env`:

    / # env
    REDIS_PORT=tcp://172.17.0.136:6379
    REDIS_PORT_6379_TCP_ADDR=172.17.0.136
    REDIS_NAME=/redis_ambassador/redis
    HOSTNAME=19d7adf4705e
    SHLVL=1
    HOME=/root
    REDIS_PORT_6379_TCP_PORT=6379
    REDIS_PORT_6379_TCP_PROTO=tcp
    REDIS_PORT_6379_TCP=tcp://172.17.0.136:6379
    TERM=xterm
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    PWD=/
    / # exit

This environment is used by the ambassador `socat` script to expose Redis
to the world (via the `-p 6379:6379` port mapping):

    $ docker rm redis_ambassador
    $ CMD="apk update && apk add socat && sh"
    $ docker run -t -i --link redis:redis --name redis_ambassador -p 6379:6379 alpine:3.2 sh -c "$CMD"
    [...]
    / # socat -t 100000000 TCP4-LISTEN:6379,fork,reuseaddr TCP4:172.17.0.136:6379

Now ping the Redis server via the ambassador:

Now go to a different server:

    $ CMD="apk update && apk add socat && sh"
    $ docker run -t -i --expose 6379 --name redis_ambassador alpine:3.2 sh -c "$CMD"
    [...]
    / # socat -t 100000000 TCP4-LISTEN:6379,fork,reuseaddr TCP4:192.168.1.52:6379

And get the `redis-cli` image so we can talk over the ambassador bridge.

    $ docker pull relateiq/redis-cli
    $ docker run -i -t --rm --link redis_ambassador:redis relateiq/redis-cli
    redis 172.17.0.160:6379> ping
    PONG

## The svendowideit/ambassador Dockerfile

The `svendowideit/ambassador` image is based on the `alpine:3.2` image with
`socat` installed. When you start the container, it uses a small `sed`
script to parse out the (possibly multiple) link environment variables
to set up the port forwarding. On the remote host, you need to set the
variable using the `-e` command line option.

    --expose 1234 -e REDIS_PORT_1234_TCP=tcp://192.168.1.52:6379

Will forward the local `1234` port to the remote IP and port, in this
case `192.168.1.52:6379`.

    #
    # do
    #   docker build -t svendowideit/ambassador .
    # then to run it (on the host that has the real backend on it)
    #   docker run -t -i -link redis:redis -name redis_ambassador -p 6379:6379 svendowideit/ambassador
    # on the remote host, you can set up another ambassador
    #    docker run -t -i -name redis_ambassador -expose 6379 -e REDIS_PORT_6379_TCP=tcp://192.168.1.52:6379 svendowideit/ambassador sh
    # you can read more about this process at https://docs.docker.com/articles/ambassador_pattern_linking/

    # use alpine because its a minimal image with a package manager.
    # prettymuch all that is needed is a container that has a functioning env and socat (or equivalent)
    FROM	alpine:3.2
    MAINTAINER	SvenDowideit@home.org.au

    RUN apk update && \
    	apk add socat && \
    	rm -r /var/cache/

    CMD	env | grep _TCP= | (sed 's/.*_PORT_\([0-9]*\)_TCP=tcp:\/\/\(.*\):\(.*\)/socat -t 100000000 TCP4-LISTEN:\1,fork,reuseaddr TCP4:\2:\3 \&/' && echo wait) | sh
