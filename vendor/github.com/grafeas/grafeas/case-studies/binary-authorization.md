# Kritis: Deployment Authorization for Kubernetes Applications

## Abstract

Binary Authorization aims to provide full software supply chain security for
cloud based applications. In an initial release we enable customers to secure
their supply chain for Kubernetes applications using an attestation based
enforcement technology.

## Introduction

Organizations increasingly employ short software life cycle (for example
continuous delivery) and highly decoupled systems (for example microservice
architecture). In such environments it becomes difficult to ensure that all
software is released and deployed according to best practices and standards.
This is important because running, say, a wrong version of a binary, through
accident or malice, may result in downtime, loss of user data, financial loss,
or worse damage. Binary Authorization wants to address this major concern of
today’s organizations: central control and enforcement of software life cycle
process.

Binary Authorization allows stakeholders to ensure that deployed software
artifacts have been prepared according to organization’s standards. It does so
through attestation and enforcement: a deployment is prevented unless the
artifact is conformant to central policy; and to express evidence of
conformance, teams use trusted attestations. A Binary Authorization policy then
states attestation requirements necessary for artifact deployment. Policy thus
codifies an important part of organization’s life cycle policy.

### Scope

Kritis is our initiative to provide an open implementation of Binary
Authorization. This paper discusses the general ideas behind Binary
Authorization, and as such is a first part of the Kritis initiative. It further
touches upon some specifics of our existing implementation of Binary
Authorization, which in its first release is focused on Google Container Engine
(GKE).

### Software Life Cycle Within an Organization

Each organization uses a release process tailored to specific needs and
constraints. Binary Authorization does not prescribe any process, it instead
helps codify and enforce the process that makes sense to the organization. To
see how Binary Authorization fits into a release process, consider the following
common pattern. Once a release is cut, artifacts go through the following
stages, successful completion of a stage being the prerequisite for progression
to the next one:

*   Build and unit test.
*   Deploy into development environment, where users aren’t affected.
    *   End to end testing might occur here.
*   Deploy into QA environment, where only internal users are affected.
*   Deploy into canary environment, where only a fraction of external users are
    affected.
*   Deploy into production.

When an artifact successfully completes a stage, an attestation on that artifact
is created which asserts success. The policy requires previous stage’s
attestations in order to allow deployment into next stage’s environment. In this
way, Binary Authorization policy increases assurance that release process is
followed. The policy may also specify that only recently attested artifacts be
allowed deployment, and so ensure freshness.

#### Third Party Dependencies

Organizations rarely develop software from blank slate. Most of the time there
is some reliance on third party “canned” software, e.g. sidecar container images
from public repositories. Ideally, third party dependencies should be subject to
the same scrutiny as internally developed software, however this is rarely
practical. Compromises are usually made, for example by vetting third party
container images as practically possible, and mandating the use of only tested
and vetted versions of the software. Binary Authorization supports this use
case.

### Example

An online merchant runs their services on Kubernetes. They have two clusters:
`production` to run production approved services, and `experimental` to run
experimental versions of services, but only 1% of the traffic is directed to the
experimental cluster. Production versions of the software must pass a stringent
test, while experimental versions, serving only a fraction of the traffic, are
subject to less strict criteria. Both experimental and production software must
pass a basic suite of tests. This organization wants to reduce the risk of
accidentally deploying experimental software to the production cluster.
Following policy realizes their requirements:

```
{
  “cluster_admission_requirements”: {
    “cluster_name”: “prod”,
    “require_attestations”: [ “tested”, “production-approved” ]
  }
  “cluster_admission_requirements”: {
    “cluster_name”: “experimental”,
    “require_attestations”: [ “tested” ]
  }
}
```

In this organization, the release process has to be designed to respect this
policy. Production qualification process must create the `production-approved`
attestation on artifacts which have indeed passed the qualification. Continuous
testing system must create the `tested` attestation.

## Binary Authorization Model in Google Container Engine (GKE)

Binary Authorization for GKE (BinAuthz) is available as an Alpha release. We
overview its design, discussing some of the more interesting choices. In a
nutshell, a user sets a BinAuthz policy for a GCP project; this policy specifies
attestations required to deploy a container image into the project or into a
specific cluster (or service account in the future). Attestations are managed
through Grafeas as a dedicated Kind `ATTESTATION`.

### Deployment Environments

Google Cloud Platform (GCP) uses projects and service accounts as security
boundaries. In addition to that, GKE uses clusters as a security boundary (a
Kubernetes cluster can have its own secrets for example). These are some of the
deployment targets that we plan to support as subjects of BinAuthz policy
requirements: project, service account, cluster.

### Policy Management

Key concepts of BinAuthz are Attestation Authority and Policy, realized as REST
resources managed through a REST API. An Attestation Authority is a named entity
which has the power to create attestations. As a REST resource, it encapsulates
the location of its attestations (where to store and retrieve from), as well as
verification criteria (what makes an attestation valid). A Policy then names
Attestation Authorities (whose attestations are) required to deploy an artifact
to some target.

#### Example

This might be an Attestation Authority which represents an organization’s secure
build system.

```
{
  “name”: “projects/secure-builder/attestationAuthorities/built-securely”
  “public_keys”: <list of keys expected to sign this authority’s attestations>
}
```

A policy which requires securely built artifacts to deploy to the `prod` cluster
may then look like this.

```
{
  “cluster_admission_requirements”: {
    “cluster_name”: “prod”,
    “attestation_requirements”: [ “projects/secure-builder/attestationAuthorities/built-securely” ]
  }
}
```

### Attestations via Component Metadata API / Grafeas

Attestations are represented as Component Metadata objects. Grafeas is its open
source sister project, and can be used as attestation transport too. An
Attestation Authority names a Note (of Kind `ATTESTATION`) which is used as an
anchor for this authority’s attestations, and optionally specifies public keys
if attestations must be signed. Attestations by this authority are then
represented as Occurrences attached to the authority’s Note.

### Enforcement Module Entry Point

Kubernetes orchestrates the execution of containers, predominantly focusing on
Docker as the container runtime. Pod is the lowest level abstraction of a
running container. Users can create Pods directly, or users can create
Controllers (such as ReplicaSet) which then mediate Pod creation. We chose Pod
admission as the interception point. At Pod admission time, information which BinAuthz
needs is available: artifact identifier (container image URL), deploy target
(project, service account, cluster). And Pod creation is the chokepoint through
which flow all code paths to run a Docker container. Intercepting at Pod
creation has some consequences which we must tolerate. Notably, a user may
create a Controller, which then creates and manages Pods asynchronously from
user’s original request. Because BinAuthz intercepts Pod creation, but not
Container creation, we don't report a BinAuthz failure at Controller creation
time, but only later, asynchronously from user’s action. Longer-term we plan to
support intercepting Controller creation too for a better user experience
(clearer errors immediately delivered). Even then we will have to keep the Pod
enforcement, to ensure that community contributed controllers don’t accidentally
bypass enforcement. Image policy webhook is a Kubernetes admission control
webhook which allows delegating Pod admission decisions to a web service. We
implement an enforcement service and configure the webhook to point to the
service.

### Artifact Identification via Early Tag Resolution

A Docker container image is identified by the registry where it is stored,
repository within the registry, and either tag or digest. Tags or digests are
usually used for versioning. A digest uniquely and immutably identifies a
container image. A tag, by contrast, may be associated to any digest, and this
association may change over time. We chose to allow only digest based container
images in BinAuthz. That is, when deploying to an environment which is subject
to BinAuthz, a tag based deployment is automatically disallowed as it is
impossible to decide the actual version that will be used once the Pod is
created. Besides giving clearer BinAuthz semantics, we believe that digest based
deployments are better production hygiene and thus were favored strongly by
customers we worked with. As an exception to this rule, our policy language
allows glob-based container image whitelisting, through which even tag based
deployments may be allowed. This is useful for images that don’t go through the
same internal vetting process (e.g., various sidecar containers). Longer-term
this should be solved through exchange of attestations with the image providers.

## Conclusion and Next Steps

Binary Authorization enables centralized control over software release cycle.
Stakeholders configure policies to enforce the requirements of the release
process, gaining confidence that software is delivered to customers only if it
meets the organization’s requirements. Attestations - trusted metadata
associated to software artifacts - are used to assert that software meets
specified requirements.

### Generalizing to Other Orchestration Systems

We described our first, GKE specific, implementation of BinAuthz, however we
note that the basic principles apply to a variety of orchestration systems. We
plan to support other GCP platforms (such as App Engine and App Engine Flex) in
the future. Furthermore, an open specification of BinAuthz is forthcoming.

### Richer Policies and Attestations

BinAuthz attestation is like a seal stamp: its only meaning is “authority `X`
attests artifact `Y`”. A richer language of statements, such as “authority `X`
attests that artifact `Y` was built from source code `Z`” allows for more
expressive policies and more meaningful control. We plan to extend the data
model and policy language to support such richer statements.

### Toolchain Integration

In its current form, BinAuthz requires custom integration into organizations’
workflows. We will reduce the integration cost by working with partners to
support BinAuthz in their products. For example, CI/CD providers are of
particular interest. A CI/CD pipeline may at different stages produce various
attestations for the artifacts which it creates, and BinAuthz policy then
enforce that proper process was followed. Source control system is another
integration point, especially if Binary Authorization is to be based on source
provenance of artifacts. To strengthen such guarantees, a trusted build system
may be needed.
