# Terminology

## Container

- *Container* - the execution of an image
- *Image* - a set of tarballs that contain the filesystem contents and run-time metadata of a container
- *Layer* - one of the tarballs used in the composition of an image, often expressed as a filesystem delta from another layer

## Specific to Clair

- *Ancestry* - the Clair-internal representation of an Image
- *Feature* - anything that when present in a filesystem could be an indication of a *vulnerability* (e.g. the presence of a file or an installed software package)
- *Feature Namespace* (featurens) - a context around *features* and *vulnerabilities* (e.g. an operating system or a programming language)
- *Vulnerability Source* (vulnsrc) - the component of Clair that tracks upstream vulnerability data and imports them into Clair's database
- *Vulnerability Metadata Source* (vulnmdsrc) - the component of Clair that tracks upstream vulnerability metadata and associates them with vulnerabilities in Clair's database
