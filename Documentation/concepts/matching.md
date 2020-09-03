# Matching

A [Matcher](../reference/matcher.md) node is responsible for matching vulnerabilities to a provided IndexReport. 

Matchers by default are also responsible for keeping the database of vulnerabilities up to date. Matchers will typically run a set of Updaters which periodically probe their data sources for new contents, writing new vulns to the database when discovered.

The matcher API is designed to be called often and will always provide the most up-to-date VulnerabilityReport when queried. This VulnerabilityReport summaries both the container's contents and any vulnerabilities affecting the container image.

See our [api](../howto/api.md) guide to learn how to view our api specification and work with the Matcher api.

## Summary

In summary you should understand that a Matcher node provides vulnerability reports given the output of an Indexing process. By default it will also run background Updaters keeping the vulnerability database up-to-date.

For a more indepth look at indexing check out the [ClairCore Documentation](https://quay.github.io/claircore/)
