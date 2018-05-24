# DockerImageDerivedDetails

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Fingerprint** | [**DockerImageFingerprint**](DockerImageFingerprint.md) |  | [optional] [default to null]
**Distance** | **int64** | Output only. The number of layers by which this image differs from the associated image basis. | [optional] [default to null]
**LayerInfo** | [**[]DockerImageLayer**](DockerImageLayer.md) | This contains layer-specific metadata, if populated it has length \&quot;distance\&quot; and is ordered with [distance] being the layer immediately following the base image and [1] being the final layer. | [optional] [default to null]
**BaseResourceUrl** | **string** |  | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


