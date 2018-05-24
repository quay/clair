# LongrunningOperation

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | The server-assigned name, which is only unique within the same service that originally returns it. If you use the default HTTP mapping, the &#x60;name&#x60; should have the format of &#x60;operations/some/unique/name&#x60;. | [optional] [default to null]
**Metadata** | [**ProtobufAny**](protobufAny.md) | Service-specific metadata associated with the operation.  It typically contains progress information and common metadata such as create time. Some services might not provide such metadata.  Any method that returns a long-running operation should document the metadata type, if any. | [optional] [default to null]
**Done** | **bool** | If the value is &#x60;false&#x60;, it means the operation is still in progress. If true, the operation is completed, and either &#x60;error&#x60; or &#x60;response&#x60; is available. | [optional] [default to null]
**Error_** | [**RpcStatus**](rpcStatus.md) | The error result of the operation in case of failure or cancellation. | [optional] [default to null]
**Response** | [**ProtobufAny**](protobufAny.md) | The normal response of the operation in case of success.  If the original method returns no data on success, such as &#x60;Delete&#x60;, the response is &#x60;google.protobuf.Empty&#x60;.  If the original method is standard &#x60;Get&#x60;/&#x60;Create&#x60;/&#x60;Update&#x60;, the response should be the resource.  For other methods, the response should have the type &#x60;XxxResponse&#x60;, where &#x60;Xxx&#x60; is the original method name.  For example, if the original method name is &#x60;TakeSnapshot()&#x60;, the inferred response type is &#x60;TakeSnapshotResponse&#x60;. | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


