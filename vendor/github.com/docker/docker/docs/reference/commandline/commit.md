---
title: "commit"
description: "The commit command description and usage"
keywords: "commit, file, changes"
---

<!-- This file is maintained within the docker/docker Github
     repository at https://github.com/docker/docker/. Make all
     pull requests against that repo. If you see this file in
     another repository, consider it read-only there, as it will
     periodically be overwritten by the definitive file. Pull
     requests which include edits to this file in other repositories
     will be rejected.
-->

# commit

```markdown
Usage:  docker commit [OPTIONS] CONTAINER [REPOSITORY[:TAG]]

Create a new image from a container's changes

Options:
  -a, --author string    Author (e.g., "John Hannibal Smith <hannibal@a-team.com>")
  -c, --change value     Apply Dockerfile instruction to the created image (default [])
      --help             Print usage
  -m, --message string   Commit message
  -p, --pause            Pause container during commit (default true)
```

It can be useful to commit a container's file changes or settings into a new
image. This allows you debug a container by running an interactive shell, or to
export a working dataset to another server. Generally, it is better to use
Dockerfiles to manage your images in a documented and maintainable way.
[Read more about valid image names and tags](tag.md).

The commit operation will not include any data contained in
volumes mounted inside the container.

By default, the container being committed and its processes will be paused
while the image is committed. This reduces the likelihood of encountering data
corruption during the process of creating the commit.  If this behavior is
undesired, set the `--pause` option to false.

The `--change` option will apply `Dockerfile` instructions to the image that is
created.  Supported `Dockerfile` instructions:
`CMD`|`ENTRYPOINT`|`ENV`|`EXPOSE`|`LABEL`|`ONBUILD`|`USER`|`VOLUME`|`WORKDIR`

## Commit a container

    $ docker ps
    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS              NAMES
    c3f279d17e0a        ubuntu:12.04        /bin/bash           7 days ago          Up 25 hours                            desperate_dubinsky
    197387f1b436        ubuntu:12.04        /bin/bash           7 days ago          Up 25 hours                            focused_hamilton
    $ docker commit c3f279d17e0a  svendowideit/testimage:version3
    f5283438590d
    $ docker images
    REPOSITORY                        TAG                 ID                  CREATED             SIZE
    svendowideit/testimage            version3            f5283438590d        16 seconds ago      335.7 MB

## Commit a container with new configurations

    {% raw %}
    $ docker ps
    ICONTAINER ID       IMAGE               COMMAND             CREATED             STATUS              PORTS              NAMES
    c3f279d17e0a        ubuntu:12.04        /bin/bash           7 days ago          Up 25 hours                            desperate_dubinsky
    197387f1b436        ubuntu:12.04        /bin/bash           7 days ago          Up 25 hours                            focused_hamilton
    $ docker inspect -f "{{ .Config.Env }}" c3f279d17e0a
    [HOME=/ PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin]
    $ docker commit --change "ENV DEBUG true" c3f279d17e0a  svendowideit/testimage:version3
    f5283438590d
    $ docker inspect -f "{{ .Config.Env }}" f5283438590d
    [HOME=/ PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin DEBUG=true]
    {% endraw %}

## Commit a container with new `CMD` and `EXPOSE` instructions

    $ docker ps
    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS              NAMES
    c3f279d17e0a        ubuntu:12.04        /bin/bash           7 days ago          Up 25 hours                            desperate_dubinsky
    197387f1b436        ubuntu:12.04        /bin/bash           7 days ago          Up 25 hours                            focused_hamilton

    $ docker commit --change='CMD ["apachectl", "-DFOREGROUND"]' -c "EXPOSE 80" c3f279d17e0a  svendowideit/testimage:version4
    f5283438590d

    $ docker run -d svendowideit/testimage:version4
    89373736e2e7f00bc149bd783073ac43d0507da250e999f3f1036e0db60817c0

    $ docker ps
    CONTAINER ID        IMAGE               COMMAND                 CREATED             STATUS              PORTS              NAMES
    89373736e2e7        testimage:version4  "apachectl -DFOREGROU"  3 seconds ago       Up 2 seconds        80/tcp             distracted_fermat
    c3f279d17e0a        ubuntu:12.04        /bin/bash               7 days ago          Up 25 hours                            desperate_dubinsky
    197387f1b436        ubuntu:12.04        /bin/bash               7 days ago          Up 25 hours                            focused_hamilton
