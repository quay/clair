---
title: "cp"
description: "The cp command description and usage"
keywords: "copy, container, files, folders"
---

<!-- This file is maintained within the docker/docker Github
     repository at https://github.com/docker/docker/. Make all
     pull requests against that repo. If you see this file in
     another repository, consider it read-only there, as it will
     periodically be overwritten by the definitive file. Pull
     requests which include edits to this file in other repositories
     will be rejected.
-->

# cp

```markdown
Usage:  docker cp [OPTIONS] CONTAINER:SRC_PATH DEST_PATH|-
        docker cp [OPTIONS] SRC_PATH|- CONTAINER:DEST_PATH

Copy files/folders between a container and the local filesystem

Use '-' as the source to read a tar archive from stdin
and extract it to a directory destination in a container.
Use '-' as the destination to stream a tar archive of a
container source to stdout.

Options:
  -L, --follow-link   Always follow symbol link in SRC_PATH
      --help          Print usage
```

The `docker cp` utility copies the contents of `SRC_PATH` to the `DEST_PATH`.
You can copy from the container's file system to the local machine or the
reverse, from the local filesystem to the container. If `-` is specified for
either the `SRC_PATH` or `DEST_PATH`, you can also stream a tar archive from
`STDIN` or to `STDOUT`. The `CONTAINER` can be a running or stopped container.
The `SRC_PATH` or `DEST_PATH` can be a file or directory.

The `docker cp` command assumes container paths are relative to the container's
`/` (root) directory. This means supplying the initial forward slash is optional;
The command sees `compassionate_darwin:/tmp/foo/myfile.txt` and
`compassionate_darwin:tmp/foo/myfile.txt` as identical. Local machine paths can
be an absolute or relative value. The command interprets a local machine's
relative paths as relative to the current working directory where `docker cp` is
run.

The `cp` command behaves like the Unix `cp -a` command in that directories are
copied recursively with permissions preserved if possible. Ownership is set to
the user and primary group at the destination. For example, files copied to a
container are created with `UID:GID` of the root user. Files copied to the local
machine are created with the `UID:GID` of the user which invoked the `docker cp`
command.  If you specify the `-L` option, `docker cp` follows any symbolic link
in the `SRC_PATH`.  `docker cp` does *not* create parent directories for
`DEST_PATH` if they do not exist.

Assuming a path separator of `/`, a first argument of `SRC_PATH` and second
argument of `DEST_PATH`, the behavior is as follows:

- `SRC_PATH` specifies a file
    - `DEST_PATH` does not exist
        - the file is saved to a file created at `DEST_PATH`
    - `DEST_PATH` does not exist and ends with `/`
        - Error condition: the destination directory must exist.
    - `DEST_PATH` exists and is a file
        - the destination is overwritten with the source file's contents
    - `DEST_PATH` exists and is a directory
        - the file is copied into this directory using the basename from
          `SRC_PATH`
- `SRC_PATH` specifies a directory
    - `DEST_PATH` does not exist
        - `DEST_PATH` is created as a directory and the *contents* of the source
           directory are copied into this directory
    - `DEST_PATH` exists and is a file
        - Error condition: cannot copy a directory to a file
    - `DEST_PATH` exists and is a directory
        - `SRC_PATH` does not end with `/.` (that is: _slash_ followed by _dot_)
            - the source directory is copied into this directory
        - `SRC_PATH` does end with `/.` (that is: _slash_ followed by _dot_)
            - the *content* of the source directory is copied into this
              directory

The command requires `SRC_PATH` and `DEST_PATH` to exist according to the above
rules. If `SRC_PATH` is local and is a symbolic link, the symbolic link, not
the target, is copied by default. To copy the link target and not the link, specify
the `-L` option.

A colon (`:`) is used as a delimiter between `CONTAINER` and its path. You can
also use `:` when specifying paths to a `SRC_PATH` or `DEST_PATH` on a local
machine, for example  `file:name.txt`. If you use a `:` in a local machine path,
you must be explicit with a relative or absolute path, for example:

    `/path/to/file:name.txt` or `./file:name.txt`

It is not possible to copy certain system files such as resources under
`/proc`, `/sys`, `/dev`, [tmpfs](run.md#mount-tmpfs-tmpfs), and mounts created by
the user in the container. However, you can still copy such files by manually
running `tar` in `docker exec`. For example (consider `SRC_PATH` and `DEST_PATH`
are directories):

    $ docker exec foo tar Ccf $(dirname SRC_PATH) - $(basename SRC_PATH) | tar Cxf DEST_PATH -

or

    $ tar Ccf $(dirname SRC_PATH) - $(basename SRC_PATH) | docker exec -i foo tar Cxf DEST_PATH -


Using `-` as the `SRC_PATH` streams the contents of `STDIN` as a tar archive.
The command extracts the content of the tar to the `DEST_PATH` in container's
filesystem. In this case, `DEST_PATH` must specify a directory. Using `-` as
the `DEST_PATH` streams the contents of the resource as a tar archive to `STDOUT`.
