# What is ClairV4

ClairV4 is an application for parsing container contents and reporting any vulnerabilities affecting the image. These actions happen via static analysis and not during container runtime.

## Architecture

ClairV4 utilizes the [ClairCore](https://quay.github.io/claircore/) library as its engine for extracing image contents and reporting vulnerabilities. At a high level you can consider ClairV4 a service wrapper to the functionality provided in the ClairCore library. 

![diagram of clairV4 highlevel architecture](./clairv4_arch.png)

The above diagram expresses the separation of concerns between ClairV4 and the ClairCore library. Most development involving new distrubtion, vulnerability analysis, and container indexing will occur in ClairCore.

## How ClairV4 Works

ClairV4's container analysis is broken into three distinct parts.

### Indexing

Indexing is the act of submitting a Manifest to ClairV4. On receipt ClairV4 will fetch all the layers, scan each layer for contents, and create an intermediate representation of the contents called an IndexReport. 

Manifests are treated as content-addressable containeers. A manifest's hash will always represent the same content and ClairV4 exploits this fact, not performing duplicate work unless necessary.

Once a Manifest is indexed the IndxReport is persisted for later retrieval. 

### Matching

Matching is the act of taking an IndexReport and discovering vulnerabilties affecting the container the report represents. 

The matcher takes care to not cache any datat for too long. ClairV4 is continually indexing new security data and a request to the matcher will always provide you with the most up to date vulnerability analysse of an IndexReport.

*how we implement indexing and matching in detail is covered in [ClairCore's](https://quay.github.io/claircore/) documentation*

### Notifications

ClairV4 implements a notification service. 

When new vulnerabilities are discovered the notifier service will determine if these vulnerabilities affect any indexed Manifests. The notifier will then fire a web hook or deliver a notification to a message broker depending on its configuration. 

### Getting Started

At this point you'll probably want to check out [Getting Started With ClairV4](./howto/getting_started.md)
