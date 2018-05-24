# ApiGerritSourceContext

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**HostUri** | **string** | The URI of a running Gerrit instance. | [optional] [default to null]
**GerritProject** | **string** | The full project name within the host. Projects may be nested, so \&quot;project/subproject\&quot; is a valid project name. The \&quot;repo name\&quot; is the hostURI/project. | [optional] [default to null]
**RevisionId** | **string** | A revision (commit) ID. | [optional] [default to null]
**AliasContext** | [**ApiAliasContext**](apiAliasContext.md) | An alias, which may be a branch or tag. | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


