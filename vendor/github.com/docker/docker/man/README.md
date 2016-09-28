Docker Documentation
====================

This directory contains the Docker user manual in the Markdown format.
Do *not* edit the man pages in the man1 directory. Instead, amend the
Markdown (*.md) files.

# Generating man pages from the Markdown files

The recommended approach for generating the man pages is via a Docker
container using the supplied `Dockerfile` to create an image with the correct
environment. This uses `go-md2man`, a pure Go Markdown to man page generator.

## Building the md2man image

There is a `Dockerfile` provided in the `/man` directory of your
'docker/docker' fork.

Using this `Dockerfile`, create a Docker image tagged `docker/md2man`:

    docker build -t docker/md2man .

## Utilizing the image

From within the `/man` directory run the following command:

    docker run -v $(pwd):/man -w /man -i docker/md2man ./md2man-all.sh
    
The `md2man` Docker container will process the Markdown files and generate
the man pages inside the `/man/man1` directory of your fork using
Docker volumes. For more information on Docker volumes see the man page for
`docker run` and also look at the article [Sharing Directories via Volumes]
(https://docs.docker.com/use/working_with_volumes/).
