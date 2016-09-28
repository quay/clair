<!--[metadata]>
+++
aliases = ["/engine/userguide/dockervolumes/"]
title = "Manage data in containers"
description = "How to manage data inside your Docker containers."
keywords = ["Examples, Usage, volume, docker, documentation, user guide, data,  volumes"]
[menu.main]
parent = "engine_learn"
+++
<![end-metadata]-->

# Manage data in containers

So far we've been introduced to some [basic Docker concepts](../containers/usingdocker.md),
seen how to work with [Docker images](../containers/dockerimages.md) as well as learned about
[networking and links between containers](../networking/default_network/dockerlinks.md). In this section we're
going to discuss how you can manage data inside and between your Docker
containers.

We're going to look at the two primary ways you can manage data in
Docker.

* Data volumes, and
* Data volume containers.

## Data volumes

A *data volume* is a specially-designated directory within one or more
containers that bypasses the [*Union File System*](../../reference/glossary.md#union-file-system). Data volumes provide several useful features for persistent or shared data:

- Volumes are initialized when a container is created. If the container's
  base image contains data at the specified mount point, that existing data is
  copied into the new volume upon volume initialization. (Note that this does
  not apply when [mounting a host directory](#mount-a-host-directory-as-a-data-volume).)
- Data volumes can be shared and reused among containers.
- Changes to a data volume are made directly.
- Changes to a data volume will not be included when you update an image.
- Data volumes persist even if the container itself is deleted.

Data volumes are designed to persist data, independent of the container's life
cycle. Docker therefore *never* automatically deletes volumes when you remove
a container, nor will it "garbage collect" volumes that are no longer
referenced by a container.

### Adding a data volume

You can add a data volume to a container using the `-v` flag with the
`docker create` and `docker run` command. You can use the `-v` multiple times
to mount multiple data volumes. Let's mount a single volume now in our web
application container.

    $ docker run -d -P --name web -v /webapp training/webapp python app.py

This will create a new volume inside a container at `/webapp`.

> **Note:**
> You can also use the `VOLUME` instruction in a `Dockerfile` to add one or
> more new volumes to any container created from that image.

### Locating a volume

You can locate the volume on the host by utilizing the `docker inspect` command.

    $ docker inspect web

The output will provide details on the container configurations including the
volumes. The output should look something similar to the following:

    ...
    Mounts": [
        {
            "Name": "fac362...80535",
            "Source": "/var/lib/docker/volumes/fac362...80535/_data",
            "Destination": "/webapp",
            "Driver": "local",
            "Mode": "",
            "RW": true,
            "Propagation": ""
        }
    ]
    ...

You will notice in the above `Source` is specifying the location on the host and
`Destination` is specifying the volume location inside the container. `RW` shows
if the volume is read/write.

### Mount a host directory as a data volume

In addition to creating a volume using the `-v` flag you can also mount a
directory from your Docker daemon's host into a container.

```
$ docker run -d -P --name web -v /src/webapp:/opt/webapp training/webapp python app.py
```

This command mounts the host directory, `/src/webapp`, into the container at
`/opt/webapp`.  If the path `/opt/webapp` already exists inside the container's
image, the `/src/webapp` mount overlays but does not remove the pre-existing
content. Once the mount is removed, the content is accessible again. This is
consistent with the expected behavior of the `mount` command.

The `container-dir` must always be an absolute path such as `/src/docs`.
The `host-dir` can either be an absolute path or a `name` value. If you
supply an absolute path for the `host-dir`, Docker bind-mounts to the path
you specify. If you supply a `name`, Docker creates a named volume by that `name`.

A `name` value must start with an alphanumeric character,
followed by `a-z0-9`, `_` (underscore), `.` (period) or `-` (hyphen).
An absolute path starts with a `/` (forward slash).

For example, you can specify either `/foo` or `foo` for a `host-dir` value.
If you supply the `/foo` value, Docker creates a bind-mount. If you supply
the `foo` specification, Docker creates a named volume.

If you are using Docker Machine on Mac or Windows, your Docker daemon has only limited access to your OS X or Windows filesystem. Docker Machine tries
to auto-share your `/Users` (OS X) or `C:\Users` (Windows) directory.  So,
you can mount files or directories on OS X using.

```
docker run -v /Users/<path>:/<container path> ...
```

On Windows, mount directories using:

```
docker run -v /c/Users/<path>:/<container path> ...`
```

All other paths come from your virtual machine's filesystem, so if you want
to make some other host folder available for sharing, you need to do
additional work. In the case of VirtualBox you need to make the host folder
available as a shared folder in VirtualBox. Then, you can mount it using the
Docker `-v` flag.

Mounting a host directory can be useful for testing. For example, you can mount
source code inside a container. Then, change the source code and see its effect
on the application in real time. The directory on the host must be specified as
an absolute path and if the directory doesn't exist Docker will automatically
create it for you.  This auto-creation of the host path has been [*deprecated*](#auto-creating-missing-host-paths-for-bind-mounts).

Docker volumes default to mount in read-write mode, but you can also set it to
be mounted read-only.

```
$ docker run -d -P --name web -v /src/webapp:/opt/webapp:ro training/webapp python app.py
```

Here we've mounted the same `/src/webapp` directory but we've added the `ro`
option to specify that the mount should be read-only.

Because of [limitations in the `mount`
function](http://lists.linuxfoundation.org/pipermail/containers/2015-April/035788.html),
moving subdirectories within the host's source directory can give
access from the container to the host's file system. This requires a malicious
user with access to host and its mounted directory.

>**Note**: The host directory is, by its nature, host-dependent. For this
>reason, you can't mount a host directory from `Dockerfile` because built images
>should be portable. A host directory wouldn't be available on all potential
>hosts.

### Mount a shared-storage volume as a data volume

In addition to mounting a host directory in your container, some Docker
[volume plugins](../../extend/plugins_volume.md) allow you to 
provision and mount shared storage, such as iSCSI, NFS, or FC.

A benefit of using shared volumes is that they are host-independent. This
means that a volume can be made available on any host that a container is
started on as long as it has access to the shared storage backend, and has
the plugin installed.

One way to use volume drivers is through the `docker run` command. 
Volume drivers create volumes by name, instead of by path like in
the other examples.

The following command creates a named volume, called `my-named-volume`,
using the `flocker` volume driver, and makes it available within the container
at `/opt/webapp`:

```bash
$ docker run -d -P \
  --volume-driver=flocker \
  -v my-named-volume:/opt/webapp \
  --name web training/webapp python app.py
```

You may also use the `docker volume create` command, to create a volume before
using it in a container.

The following example also creates the `my-named-volume` volume, this time
using the `docker volume create` command.

```bash
$ docker volume create -d flocker --name my-named-volume -o size=20GB
$ docker run -d -P \
  -v my-named-volume:/opt/webapp \
  --name web training/webapp python app.py
```

A list of available plugins, including volume plugins, is available
[here](../../extend/plugins.md).

### Volume labels

Labeling systems like SELinux require that proper labels are placed on volume
content mounted into a container. Without a label, the security system might
prevent the processes running inside the container from using the content. By
default, Docker does not change the labels set by the OS.

To change a label in the container context, you can add either of two suffixes
`:z` or `:Z` to the volume mount. These suffixes tell Docker to relabel file
objects on the shared volumes. The `z` option tells Docker that two containers
share the volume content. As a result, Docker labels the content with a shared
content label. Shared volume labels allow all containers to read/write content.
The `Z` option tells Docker to label the content with a private unshared label.
Only the current container can use a private volume.

### Mount a host file as a data volume

The `-v` flag can also be used to mount a single file  - instead of *just*
directories - from the host machine.

    $ docker run --rm -it -v ~/.bash_history:/root/.bash_history ubuntu /bin/bash

This will drop you into a bash shell in a new container, you will have your bash
history from the host and when you exit the container, the host will have the
history of the commands typed while in the container.

> **Note:**
> Many tools used to edit files including `vi` and `sed --in-place` may result
> in an inode change. Since Docker v1.1.0, this will produce an error such as
> "*sed: cannot rename ./sedKdJ9Dy: Device or resource busy*". In the case where
> you want to edit the mounted file, it is often easiest to instead mount the
> parent directory.

## Creating and mounting a data volume container

If you have some persistent data that you want to share between
containers, or want to use from non-persistent containers, it's best to
create a named Data Volume Container, and then to mount the data from
it.

Let's create a new named container with a volume to share.
While this container doesn't run an application, it reuses the `training/postgres`
image so that all containers are using layers in common, saving disk space.

    $ docker create -v /dbdata --name dbstore training/postgres /bin/true

You can then use the `--volumes-from` flag to mount the `/dbdata` volume in another container.

    $ docker run -d --volumes-from dbstore --name db1 training/postgres

And another:

    $ docker run -d --volumes-from dbstore --name db2 training/postgres

In this case, if the `postgres` image contained a directory called `/dbdata`
then mounting the volumes from the `dbstore` container hides the
`/dbdata` files from the `postgres` image. The result is only the files
from the `dbstore` container are visible.

You can use multiple `--volumes-from` parameters to combine data volumes from
several containers. To find detailed information about `--volumes-from` see the
[Mount volumes from container](../../reference/commandline/run.md#mount-volumes-from-container-volumes-from)
in the `run` command reference.

You can also extend the chain by mounting the volume that came from the
`dbstore` container in yet another container via the `db1` or `db2` containers.

    $ docker run -d --name db3 --volumes-from db1 training/postgres

If you remove containers that mount volumes, including the initial `dbstore`
container, or the subsequent containers `db1` and `db2`, the volumes will not
be deleted.  To delete the volume from disk, you must explicitly call
`docker rm -v` against the last container with a reference to the volume. This
allows you to upgrade, or effectively migrate data volumes between containers.

> **Note:** Docker will not warn you when removing a container *without*
> providing the `-v` option to delete its volumes. If you remove containers
> without using the `-v` option, you may end up with "dangling" volumes;
> volumes that are no longer referenced by a container.
> You can use `docker volume ls -f dangling=true` to find dangling volumes,
> and use `docker volume rm <volume name>` to remove a volume that's
> no longer needed.

## Backup, restore, or migrate data volumes

Another useful function we can perform with volumes is use them for
backups, restores or migrations.  We do this by using the
`--volumes-from` flag to create a new container that mounts that volume,
like so:

    $ docker run --rm --volumes-from dbstore -v $(pwd):/backup ubuntu tar cvf /backup/backup.tar /dbdata

Here we've launched a new container and mounted the volume from the
`dbstore` container. We've then mounted a local host directory as
`/backup`. Finally, we've passed a command that uses `tar` to backup the
contents of the `dbdata` volume to a `backup.tar` file inside our
`/backup` directory. When the command completes and the container stops
we'll be left with a backup of our `dbdata` volume.

You could then restore it to the same container, or another that you've made
elsewhere. Create a new container.

    $ docker run -v /dbdata --name dbstore2 ubuntu /bin/bash

Then un-tar the backup file in the new container's data volume.

    $ docker run --rm --volumes-from dbstore2 -v $(pwd):/backup ubuntu bash -c "cd /dbdata && tar xvf /backup/backup.tar --strip 1"

You can use the techniques above to automate backup, migration and
restore testing using your preferred tools.

## Important tips on using shared volumes

Multiple containers can also share one or more data volumes. However, multiple containers writing to a single shared volume can cause data corruption. Make sure your applications are designed to write to shared data stores.

Data volumes are directly accessible from the Docker host. This means you can read and write to them with normal Linux tools. In most cases you should not do this as it can cause data corruption if your containers and applications are unaware of your direct access.

# Next steps

Now we've learned a bit more about how to use Docker we're going to see how to
combine Docker with the services available on
[Docker Hub](https://hub.docker.com) including Automated Builds and private
repositories.

Go to [Working with Docker Hub](../containers/dockerrepos.md).
