# PackageManagerDistribution

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**CpeUri** | **string** | The cpe_uri in [cpe format](https://cpe.mitre.org/specification/) denoting the package manager version distributing a package. | [optional] [default to null]
**Architecture** | [**PackageManagerArchitecture**](PackageManagerArchitecture.md) |  | [optional] [default to null]
**LatestVersion** | [**VulnerabilityTypeVersion**](VulnerabilityTypeVersion.md) | The latest available version of this package in this distribution channel. | [optional] [default to null]
**Maintainer** | **string** | A freeform string denoting the maintainer of this package. | [optional] [default to null]
**Url** | **string** | The distribution channel-specific homepage for this package. | [optional] [default to null]
**Description** | **string** | The distribution channel-specific description of this package. | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


