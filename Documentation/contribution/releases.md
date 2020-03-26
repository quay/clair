# Releases

Clair releases are cut roughly every three months and actively maintained for
six.

This means that bugfixes should be landed on `master` (if applicable) and then
marked for backporting to a minor version's release branch. The process for
doing this is not yet formalized.

## Process

### Minor

When cutting a new minor release, two things need to be done: creating a tag and
creating a release branch. This can be done like so:

```sh
git tag -as v4.x.0 HEAD
git push upstream HEAD:release-4.x tag v4.x.0
```

Then, a "release" needs to be created in the Github UI using the created tag.

### Patch

A patch release is just like a minor release with the caveat that minor version
tags should *only* appear on release branches and a new branch does not need to
be created.

```sh
git checkout release-4.x
git tag -as v4.x.1 HEAD
git push upstream tag v4.x.1
```

Then, a "release" needs to be created in the Github UI using the created tag.

### Creating Artifacts

Clair's artifact release process is automated and driven off the releases in
Github.

Publishing a new release in the Github UI automatically triggers the creation of
a complete source archive and a container. The archive is attached to the
release, and the container is pushed to the
[`quay.io/projectquay/clair`](https://quay.io/repository/projectquay/clair)
repository.

This is all powered by a Github Action in `.github/workflows/cut-release.yml`.
