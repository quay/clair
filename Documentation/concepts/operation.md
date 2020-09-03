# Operation


## Architecture

Clair is structured so that it can be easily scaled with demand. It can be
broken up into up to 3 microservices as needed ([Indexer], [Matcher], and
[Notifier]) or run as a single monolith. Each process talks to separate tables
in the database and is responsible for disparate API endpoints.

[Indexer]: #indexer
[Matcher]: #matcher
[Notifier]: #notifier

### Indexer

Responsible for ...

### Matcher

Responsible for ...

### Notifier

Responsible for ...

## Ingress

One recommended configuration is to use some sort of service ingress to route
API endpoints to the component responsible for servicing it.

