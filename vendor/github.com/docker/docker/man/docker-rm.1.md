% DOCKER(1) Docker User Manuals
% Docker Community
% JUNE 2014
# NAME
docker-rm - Remove one or more containers

# SYNOPSIS
**docker rm**
[**-f**|**--force**]
[**-l**|**--link**]
[**-v**|**--volumes**]
CONTAINER [CONTAINER...]

# DESCRIPTION

**docker rm** will remove one or more containers from the host node. The
container name or ID can be used. This does not remove images. You cannot
remove a running container unless you use the **-f** option. To see all
containers on a host use the **docker ps -a** command.

# OPTIONS
**--help**
  Print usage statement

**-f**, **--force**=*true*|*false*
   Force the removal of a running container (uses SIGKILL). The default is *false*.

**-l**, **--link**=*true*|*false*
   Remove the specified link and not the underlying container. The default is *false*.

**-v**, **--volumes**=*true*|*false*
   Remove the volumes associated with the container. The default is *false*.

# EXAMPLES

## Removing a container using its ID

To remove a container using its ID, find either from a **docker ps -a**
command, or use the ID returned from the **docker run** command, or retrieve
it from a file used to store it using the **docker run --cidfile**:

    docker rm abebf7571666

## Removing a container using the container name

The name of the container can be found using the **docker ps -a**
command. The use that name as follows:

    docker rm hopeful_morse

## Removing a container and all associated volumes

    $ docker rm -v redis
    redis

This command will remove the container and any volumes associated with it.
Note that if a volume was specified with a name, it will not be removed.

    $ docker create -v awesome:/foo -v /bar --name hello redis
    hello
    $ docker rm -v hello

In this example, the volume for `/foo` will remain in tact, but the volume for
`/bar` will be removed. The same behavior holds for volumes inherited with
`--volumes-from`.

# HISTORY
April 2014, Originally compiled by William Henry (whenry at redhat dot com)
based on docker.com source material and internal work.
June 2014, updated by Sven Dowideit <SvenDowideit@home.org.au>
July 2014, updated by Sven Dowideit <SvenDowideit@home.org.au>
August 2014, updated by Sven Dowideit <SvenDowideit@home.org.au>
