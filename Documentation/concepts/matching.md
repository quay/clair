# Matching

A [Matcher](../reference/matcher.md) node is responsible for matching vulnerabilities to a provided IndexReport. 

Matchers by default are also responsible for keeping the database of vulnerabilities up to date. Matchers will typically run a set of Updaters which periodically probe their data sources for new contents, storing new vulnerabilities in the database when discovered.

The matcher API is designed to be called often and will always provide the most up-to-date VulnerabilityReport when queried. This VulnerabilityReport summaries both a manifest's contents and any vulnerabilities affecting the contents.

See our [api](../howto/api.md) guide to learn how to view our api specification and work with the Matcher api.

# Remote Matching

A remote matcher behaves similarly to a matcher, except that it uses api calls to fetch vulnerability data for a provided IndexReport.
Remote matchers are useful when it is not possible to persist data from a given source into the database.

The `crda` remote matcher is responsible for fetching vulnerabilities from Red Hat Code Ready Dependency Analytics (CRDA).
By default, this matcher serves 100 requests per minute.
The rate-limiting can be lifted by requesting a dedicated API key, which is done via [this form][CRDA-Request-Form].

[CRDA-Request-Form]: https://developers.redhat.com/content-gateway/link/3872178

## Summary

In summary you should understand that a Matcher node provides vulnerability reports given the output of an Indexing process. By default it will also run background Updaters keeping the vulnerability database up-to-date.

For a more indepth look at indexing check out the [ClairCore Documentation](https://quay.github.io/claircore/)
