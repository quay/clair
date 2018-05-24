# ApiBuildProvenance

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Id** | **string** | Unique identifier of the build. | [optional] [default to null]
**ProjectId** | **string** | ID of the project. | [optional] [default to null]
**Commands** | [**[]ApiCommand**](apiCommand.md) | Commands requested by the build. | [optional] [default to null]
**BuiltArtifacts** | [**[]ApiArtifact**](apiArtifact.md) | Output of the build. | [optional] [default to null]
**CreateTime** | [**time.Time**](time.Time.md) | Time at which the build was created. | [optional] [default to null]
**StartTime** | [**time.Time**](time.Time.md) | Time at which execution of the build was started. | [optional] [default to null]
**FinishTime** | [**time.Time**](time.Time.md) | Time at which execution of the build was finished. | [optional] [default to null]
**Creator** | **string** | E-mail address of the user who initiated this build. Note that this was the user&#39;s e-mail address at the time the build was initiated; this address may not represent the same end-user for all time. | [optional] [default to null]
**LogsBucket** | **string** | Google Cloud Storage bucket where logs were written. | [optional] [default to null]
**SourceProvenance** | [**ApiSource**](apiSource.md) | Details of the Source input to the build. | [optional] [default to null]
**TriggerId** | **string** | Trigger identifier if the build was triggered automatically; empty if not. | [optional] [default to null]
**BuildOptions** | **map[string]string** | Special options applied to this build. This is a catch-all field where build providers can enter any desired additional details. | [optional] [default to null]
**BuilderVersion** | **string** | Version string of the builder at the time this build was executed. | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


