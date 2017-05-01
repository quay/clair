Assigns a new alias to an image in a registry. An alias refers to the
entire image name including the optional `TAG` after the ':'. 

# OPTIONS
**NAME**
   The image name which is made up of slash-separated name components, 
   optionally prefixed by a registry hostname. The hostname must comply with 
   standard DNS rules, but may not contain underscores. If a hostname is 
   present, it may optionally be followed by a port number in the format 
   `:8080`. If not present, the command uses Docker's public registry located at
   `registry-1.docker.io` by default. Name components may contain lowercase 
   letters, digits and separators. A separator is defined as a period, one or
   two underscores, or one or more dashes. A name component may not start or end 
   with a separator.

**TAG**
   The tag assigned to the image to version and distinguish images with the same
   name. The tag name must be valid ASCII and may contain lowercase and
   uppercase letters, digits, underscores, periods and hyphens. A tag name
   may not start with a period or a hyphen and may contain a maximum of 128
   characters.

# EXAMPLES

## Tagging an image referenced by ID

To tag a local image with ID "0e5574283393" into the "fedora" repository with 
"version1.0":

    docker image tag 0e5574283393 fedora/httpd:version1.0

## Tagging an image referenced by Name

To tag a local image with name "httpd" into the "fedora" repository with 
"version1.0":

    docker image tag httpd fedora/httpd:version1.0

Note that since the tag name is not specified, the alias is created for an
existing local version `httpd:latest`.

## Tagging an image referenced by Name and Tag

To tag a local image with name "httpd" and tag "test" into the "fedora"
repository with "version1.0.test":

    docker image tag httpd:test fedora/httpd:version1.0.test

## Tagging an image for a private repository

To push an image to a private registry and not the central Docker
registry you must tag it with the registry hostname and port (if needed).

    docker image tag 0e5574283393 myregistryhost:5000/fedora/httpd:version1.0
