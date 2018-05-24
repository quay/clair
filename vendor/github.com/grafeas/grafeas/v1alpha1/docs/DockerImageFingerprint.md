# DockerImageFingerprint

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**V1Name** | **string** | The layer-id of the final layer in the Docker image&#39;s v1 representation. This field can be used as a filter in list requests. | [optional] [default to null]
**V2Blob** | **[]string** | The ordered list of v2 blobs that represent a given image. | [optional] [default to null]
**V2Name** | **string** | Output only. The name of the image&#39;s v2 blobs computed via:   [bottom] :&#x3D; v2_blob[bottom]   [N] :&#x3D; sha256(v2_blob[N] + \&quot; \&quot; + v2_name[N+1]) Only the name of the final blob is kept. This field can be used as a filter in list requests. | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


