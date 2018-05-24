# DeployableDeploymentDetails

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**UserEmail** | **string** | Identity of the user that triggered this deployment. | [optional] [default to null]
**DeployTime** | [**time.Time**](time.Time.md) | Beginning of the lifetime of this deployment. | [optional] [default to null]
**UndeployTime** | [**time.Time**](time.Time.md) | End of the lifetime of this deployment. | [optional] [default to null]
**Config** | **string** | Configuration used to create this deployment. | [optional] [default to null]
**Address** | **string** | Address of the runtime element hosting this deployment. | [optional] [default to null]
**ResourceUri** | **[]string** | Output only. Resource URI for the artifact being deployed taken from the deployable field with the same name. | [optional] [default to null]
**Platform** | [**DeploymentDetailsPlatform**](DeploymentDetailsPlatform.md) | Platform hosting this deployment. | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


