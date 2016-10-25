<!--[metadata]>
+++
title = "ps"
description = "The ps command description and usage"
keywords = ["container, running, list"]
[menu.main]
parent = "smn_cli"
+++
<![end-metadata]-->

# ps

    Usage: docker ps [OPTIONS]

    List containers

      -a, --all             Show all containers (default shows just running)
      -f, --filter=[]       Filter output based on these conditions:
                            - exited=<int> an exit code of <int>
                            - label=<key> or label=<key>=<value>
                            - status=(created|restarting|running|paused|exited)
                            - name=<string> a container's name
                            - id=<ID> a container's ID
                            - before=(<container-name>|<container-id>)
                            - since=(<container-name>|<container-id>)
                            - ancestor=(<image-name>[:tag]|<image-id>|<image@digest>) - containers created from an image or a descendant.
      --format=[]           Pretty-print containers using a Go template
      --help                Print usage
      -l, --latest          Show the latest created container (includes all states)
      -n=-1                 Show n last created containers (includes all states)
      --no-trunc            Don't truncate output
      -q, --quiet           Only display numeric IDs
      -s, --size            Display total file sizes

Running `docker ps --no-trunc` showing 2 linked containers.

    $ docker ps
    CONTAINER ID        IMAGE                        COMMAND                CREATED              STATUS              PORTS               NAMES
    4c01db0b339c        ubuntu:12.04                 bash                   17 seconds ago       Up 16 seconds       3300-3310/tcp       webapp
    d7886598dbe2        crosbymichael/redis:latest   /redis-server --dir    33 minutes ago       Up 33 minutes       6379/tcp            redis,webapp/db

`docker ps` will show only running containers by default. To see all containers:
`docker ps -a`

`docker ps` will group exposed ports into a single range if possible. E.g., a container that exposes TCP ports `100, 101, 102` will display `100-102/tcp` in the `PORTS` column.

## Filtering

The filtering flag (`-f` or `--filter`) format is a `key=value` pair. If there is more
than one filter, then pass multiple flags (e.g. `--filter "foo=bar" --filter "bif=baz"`)

The currently supported filters are:

* id (container's id)
* label (`label=<key>` or `label=<key>=<value>`)
* name (container's name)
* exited (int - the code of exited containers. Only useful with `--all`)
* status (created|restarting|running|paused|exited|dead)
* ancestor (`<image-name>[:<tag>]`,  `<image id>` or `<image@digest>`) - filters containers that were created from the given image or a descendant.
* before (container's id or name) - filters containers created before given id or name
* since (container's id or name) - filters containers created since given id or name
* isolation (default|process|hyperv)   (Windows daemon only)
* volume (volume name or mount point) - filters containers that mount volumes.


#### Label

The `label` filter matches containers based on the presence of a `label` alone or a `label` and a
value.

The following filter matches containers with the `color` label regardless of its value.

    $ docker ps --filter "label=color"
    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
    673394ef1d4c        busybox             "top"               47 seconds ago      Up 45 seconds                           nostalgic_shockley
    d85756f57265        busybox             "top"               52 seconds ago      Up 51 seconds                           high_albattani

The following filter matches containers with the `color` label with the `blue` value.

    $ docker ps --filter "label=color=blue"
    CONTAINER ID        IMAGE               COMMAND             CREATED              STATUS              PORTS               NAMES
    d85756f57265        busybox             "top"               About a minute ago   Up About a minute                       high_albattani

#### Name

The `name` filter matches on all or part of a container's name.

The following filter matches all containers with a name containing the `nostalgic_stallman` string.

    $ docker ps --filter "name=nostalgic_stallman"
    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
    9b6247364a03        busybox             "top"               2 minutes ago       Up 2 minutes                            nostalgic_stallman

You can also filter for a substring in a name as this shows:

    $ docker ps --filter "name=nostalgic"
    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
    715ebfcee040        busybox             "top"               3 seconds ago       Up 1 seconds                            i_am_nostalgic
    9b6247364a03        busybox             "top"               7 minutes ago       Up 7 minutes                            nostalgic_stallman
    673394ef1d4c        busybox             "top"               38 minutes ago      Up 38 minutes                           nostalgic_shockley

#### Exited

The `exited` filter matches containers by exist status code. For example, to filter for containers
that have exited successfully:

    $ docker ps -a --filter 'exited=0'
    CONTAINER ID        IMAGE             COMMAND                CREATED             STATUS                   PORTS                      NAMES
    ea09c3c82f6e        registry:latest   /srv/run.sh            2 weeks ago         Exited (0) 2 weeks ago   127.0.0.1:5000->5000/tcp   desperate_leakey
    106ea823fe4e        fedora:latest     /bin/sh -c 'bash -l'   2 weeks ago         Exited (0) 2 weeks ago                              determined_albattani
    48ee228c9464        fedora:20         bash                   2 weeks ago         Exited (0) 2 weeks ago                              tender_torvalds

#### Status

The `status` filter matches containers by status. You can filter using `created`, `restarting`, `running`, `paused`, `exited` and `dead`. For example, to filter for `running` containers:

    $ docker ps --filter status=running
    CONTAINER ID        IMAGE                  COMMAND             CREATED             STATUS              PORTS               NAMES
    715ebfcee040        busybox                "top"               16 minutes ago      Up 16 minutes                           i_am_nostalgic
    d5c976d3c462        busybox                "top"               23 minutes ago      Up 23 minutes                           top
    9b6247364a03        busybox                "top"               24 minutes ago      Up 24 minutes                           nostalgic_stallman

To filter for `paused` containers:

    $ docker ps --filter status=paused
    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS                      PORTS               NAMES
    673394ef1d4c        busybox             "top"               About an hour ago   Up About an hour (Paused)                       nostalgic_shockley

#### Ancestor

The `ancestor` filter matches containers based on its image or a descendant of it. The filter supports the
following image representation:

- image
- image:tag
- image:tag@digest
- short-id
- full-id

If you don't specify a `tag`, the `latest` tag is used. For example, to filter for containers that use the
latest `ubuntu` image:

    $ docker ps --filter ancestor=ubuntu
    CONTAINER ID        IMAGE               COMMAND             CREATED              STATUS              PORTS               NAMES
    919e1179bdb8        ubuntu-c1           "top"               About a minute ago   Up About a minute                       admiring_lovelace
    5d1e4a540723        ubuntu-c2           "top"               About a minute ago   Up About a minute                       admiring_sammet
    82a598284012        ubuntu              "top"               3 minutes ago        Up 3 minutes                            sleepy_bose
    bab2a34ba363        ubuntu              "top"               3 minutes ago        Up 3 minutes                            focused_yonath

Match containers based on the `ubuntu-c1` image which, in this case, is a child of `ubuntu`:

    $ docker ps --filter ancestor=ubuntu-c1
    CONTAINER ID        IMAGE               COMMAND             CREATED              STATUS              PORTS               NAMES
    919e1179bdb8        ubuntu-c1           "top"               About a minute ago   Up About a minute                       admiring_lovelace

Match containers based on the `ubuntu` version `12.04.5` image:

    $ docker ps --filter ancestor=ubuntu:12.04.5
    CONTAINER ID        IMAGE               COMMAND             CREATED              STATUS              PORTS               NAMES
    82a598284012        ubuntu:12.04.5      "top"               3 minutes ago        Up 3 minutes                            sleepy_bose

The following matches containers based on the layer `d0e008c6cf02` or an image that have this layer
in it's layer stack.

    $ docker ps --filter ancestor=d0e008c6cf02
    CONTAINER ID        IMAGE               COMMAND             CREATED              STATUS              PORTS               NAMES
    82a598284012        ubuntu:12.04.5      "top"               3 minutes ago        Up 3 minutes                            sleepy_bose

#### Before

The `before` filter shows only containers created before the container with given id or name. For example, 
having these containers created:

    $ docker ps
    CONTAINER ID        IMAGE       COMMAND       CREATED              STATUS              PORTS              NAMES
    9c3527ed70ce        busybox     "top"         14 seconds ago       Up 15 seconds                          desperate_dubinsky
    4aace5031105        busybox     "top"         48 seconds ago       Up 49 seconds                          focused_hamilton
    6e63f6ff38b0        busybox     "top"         About a minute ago   Up About a minute                      distracted_fermat

Filtering with `before` would give:

    $ docker ps -f before=9c3527ed70ce
    CONTAINER ID        IMAGE       COMMAND       CREATED              STATUS              PORTS              NAMES
    4aace5031105        busybox     "top"         About a minute ago   Up About a minute                      focused_hamilton
    6e63f6ff38b0        busybox     "top"         About a minute ago   Up About a minute                      distracted_fermat

#### Since

The `since` filter shows only containers created since the container with given id or name. For example,
with the same containers as in `before` filter:

    $ docker ps -f since=6e63f6ff38b0
    CONTAINER ID        IMAGE       COMMAND       CREATED             STATUS              PORTS               NAMES
    9c3527ed70ce        busybox     "top"         10 minutes ago      Up 10 minutes                           desperate_dubinsky
    4aace5031105        busybox     "top"         10 minutes ago      Up 10 minutes                           focused_hamilton

#### Volume

The `volume` filter shows only containers that mount a specific volume or have a volume mounted in a specific path:

    $ docker ps --filter volume=remote-volume --format "table {{.ID}}\t{{.Mounts}}"
    CONTAINER ID        MOUNTS
    9c3527ed70ce        remote-volume

    $ docker ps --filter volume=/data --format "table {{.ID}}\t{{.Mounts}}"
    CONTAINER ID        MOUNTS
    9c3527ed70ce        remote-volume


## Formatting

The formatting option (`--format`) will pretty-print container output using a Go template.

Valid placeholders for the Go template are listed below:

Placeholder | Description
---- | ----
`.ID` | Container ID
`.Image` | Image ID
`.Command` | Quoted command
`.CreatedAt` | Time when the container was created.
`.RunningFor` | Elapsed time since the container was started.
`.Ports` | Exposed ports.
`.Status` | Container status.
`.Size` | Container disk size.
`.Names` | Container names.
`.Labels` | All labels assigned to the container.
`.Label` | Value of a specific label for this container. For example `{{.Label "com.docker.swarm.cpu"}}`
`.Mounts` | Names of the volumes mounted in this container.

When using the `--format` option, the `ps` command will either output the data exactly as the template
declares or, when using the `table` directive, will include column headers as well.

The following example uses a template without headers and outputs the `ID` and `Command`
entries separated by a colon for all running containers:

    $ docker ps --format "{{.ID}}: {{.Command}}"
    a87ecb4f327c: /bin/sh -c #(nop) MA
    01946d9d34d8: /bin/sh -c #(nop) MA
    c1d3b0166030: /bin/sh -c yum -y up
    41d50ecd2f57: /bin/sh -c #(nop) MA

To list all running containers with their labels in a table format you can use:

    $ docker ps --format "table {{.ID}}\t{{.Labels}}"
    CONTAINER ID        LABELS
    a87ecb4f327c        com.docker.swarm.node=ubuntu,com.docker.swarm.storage=ssd
    01946d9d34d8
    c1d3b0166030        com.docker.swarm.node=debian,com.docker.swarm.cpu=6
    41d50ecd2f57        com.docker.swarm.node=fedora,com.docker.swarm.cpu=3,com.docker.swarm.storage=ssd
