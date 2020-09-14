# Indexing

The [Indexer](../reference/indexer.md) service is responsble for "indexing a manifest".

Indexing involves taking a manifest representing a container image and computing its constituent parts. The indexer is trying to discover what packages exist in the image, what distribution the image is derived from, and what package repositories are used within the image. Once this information is computed it is persisted in an IndexReport.

The IndexReport is an intermediate data structure describing the contents of a container image. This report can be fed to a [Matcher](../reference/matcher.md) node for vulnerability analysis.

## Content Addressability

ClairV4 treats all manifests and layers as [content addressable](https://en.wikipedia.org/wiki/Content-addressable_storage). In the context of ClairV4 this means once we index a specific manifest we will not index it again unless it's required, and likewise with individual layers. This allows a large reduction in work. 

For example, consider how many images in a registry may use "ubuntu:artful" as a base layer. It could be a large majority of images if the developers prefer basing their images off ubuntu. Treating the layers and manifests as content addressable means we will only fetch and scan the base layer once.

There are of course conditions where ClairV4 should re-index a manifest. 

When an internal component such as a package scanner is updated, Clair will know to perform the scan with the new package scanner. Clair has enough information to determine that a component has changed and the IndexReport may be different this time around. 

A client can track ClairV4's `index_state` endpoint to understand when an internal component has changed and subsequently issue re-indexes. See our [api](../howto/api.md) guide to learn how to view our api specification.

## Summary

In summary, you should understand that Indexing is the process Clair uses to understand the contents of layers.

For a more indepth look at indexing check out the [ClairCore Documentation](https://quay.github.io/claircore/)
