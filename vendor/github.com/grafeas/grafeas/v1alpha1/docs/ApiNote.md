# ApiNote

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** |  | [optional] [default to null]
**ShortDescription** | **string** | A one sentence description of this &#x60;Note&#x60;. | [optional] [default to null]
**LongDescription** | **string** | A detailed description of this &#x60;Note&#x60;. | [optional] [default to null]
**Kind** | [**ApiNoteKind**](apiNoteKind.md) | Output only. This explicitly denotes which kind of note is specified. This field can be used as a filter in list requests. | [optional] [default to null]
**VulnerabilityType** | [**ApiVulnerabilityType**](apiVulnerabilityType.md) | A package vulnerability type of note. | [optional] [default to null]
**BuildType** | [**ApiBuildType**](apiBuildType.md) | Build provenance type for a verifiable build. | [optional] [default to null]
**BaseImage** | [**DockerImageBasis**](DockerImageBasis.md) | A note describing a base image. | [optional] [default to null]
**Package_** | [**PackageManagerPackage**](PackageManagerPackage.md) | A note describing a package hosted by various package managers. | [optional] [default to null]
**Deployable** | [**ApiDeployable**](apiDeployable.md) | A note describing something that can be deployed. | [optional] [default to null]
**Discovery** | [**ApiDiscovery**](apiDiscovery.md) | A note describing a provider/analysis type. | [optional] [default to null]
**RelatedUrl** | [**[]NoteRelatedUrl**](NoteRelatedUrl.md) |  | [optional] [default to null]
**ExpirationTime** | [**time.Time**](time.Time.md) | Time of expiration for this note, null if note does not expire. | [optional] [default to null]
**CreateTime** | [**time.Time**](time.Time.md) | Output only. The time this note was created. This field can be used as a filter in list requests. | [optional] [default to null]
**UpdateTime** | [**time.Time**](time.Time.md) | Output only. The time this note was last updated. This field can be used as a filter in list requests. | [optional] [default to null]
**OperationName** | **string** |  | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


