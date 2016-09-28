<!-- [metadata]>
+++
aliases = ["/engine/misc/"]
title = "Docker Engine"
description = "Engine"
keywords = ["Engine"]
[menu.main]
identifier="engine_use"
weight=-85
+++
<![end-metadata]-->

# About Docker Engine

**Develop, Ship and Run Any Application, Anywhere**

[**Docker**](https://www.docker.com) is a platform for developers and sysadmins
to develop, ship, and run applications.  Docker lets you quickly assemble
applications from components and eliminates the friction that can come when
shipping code. Docker lets you get your code tested and deployed into production
as fast as possible.

Docker consists of:

* The Docker Engine - our lightweight and powerful open source containerization
  technology combined with a work flow for building and containerizing your
  applications.
* [Docker Hub](https://hub.docker.com) - our SaaS service for
  sharing and managing your application stacks.

## Why Docker?

*Faster delivery of your applications*

* We want your environment to work better. Docker containers,
      and the work flow that comes with them, help your developers,
      sysadmins, QA folks, and release engineers work together to get your code
      into production and make it useful. We've created a standard
      container format that lets developers care about their applications
      inside containers while sysadmins and operators can work on running the
      container in your deployment. This separation of duties streamlines and
      simplifies the management and deployment of code.
* We make it easy to build new containers, enable rapid iteration of
      your applications, and increase the visibility of changes. This
      helps everyone in your organization understand how an application works
      and how it is built.
* Docker containers are lightweight and fast! Containers have
      sub-second launch times, reducing the cycle
      time of development, testing, and deployment.

*Deploy and scale more easily*

* Docker containers run (almost) everywhere. You can deploy
      containers on desktops, physical servers, virtual machines, into
      data centers, and up to public and private clouds.
* Since Docker runs on so many platforms, it's easy to move your
      applications around. You can easily move an application from a
      testing environment into the cloud and back whenever you need.
* Docker's lightweight containers also make scaling up and
      down fast and easy. You can quickly launch more containers when
      needed and then shut them down easily when they're no longer needed.

*Get higher density and run more workloads*

* Docker containers don't need a hypervisor, so you can pack more of
      them onto your hosts. This means you get more value out of every
      server and can potentially reduce what you spend on equipment and
      licenses.

*Faster deployment makes for easier management*

* As Docker speeds up your work flow, it gets easier to make lots
      of small changes instead of huge, big bang updates. Smaller
      changes mean reduced risk and more uptime.

## About this guide

The [Understanding Docker section](understanding-docker.md) will help you:

 - See how Docker works at a high level
 - Understand the architecture of Docker
 - Discover Docker's features;
 - See how Docker compares to virtual machines
 - See some common use cases.

### Installation guides

The [installation section](installation/index.md) will show you how to install Docker
on a variety of platforms.


### Docker user guide

To learn about Docker in more detail and to answer questions about usage and
implementation, check out the [Docker User Guide](userguide/index.md).

## Release notes

A summary of the changes in each release in the current series can now be found
on the separate [Release Notes page](https://docs.docker.com/release-notes)

## Feature Deprecation Policy

As changes are made to Docker there may be times when existing features
will need to be removed or replaced with newer features. Before an existing
feature is removed it will be labeled as "deprecated" within the documentation
and will remain in Docker for, usually, at least 2 releases. After that time
it may be removed.

Users are expected to take note of the list of deprecated features each
release and plan their migration away from those features, and (if applicable)
towards the replacement features as soon as possible.

The complete list of deprecated features can be found on the
[Deprecated Features page](deprecated.md).

## Licensing

Docker is licensed under the Apache License, Version 2.0. See
[LICENSE](https://github.com/docker/docker/blob/master/LICENSE) for the full
license text.
