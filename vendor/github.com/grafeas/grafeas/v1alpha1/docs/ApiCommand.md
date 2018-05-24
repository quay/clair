# ApiCommand

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | Name of the command, as presented on the command line, or if the command is packaged as a Docker container, as presented to &#x60;docker pull&#x60;. | [optional] [default to null]
**Env** | **[]string** | Environment variables set before running this Command. | [optional] [default to null]
**Args** | **[]string** | Command-line arguments used when executing this Command. | [optional] [default to null]
**Dir** | **string** | Working directory (relative to project source root) used when running this Command. | [optional] [default to null]
**Id** | **string** | Optional unique identifier for this Command, used in wait_for to reference this Command as a dependency. | [optional] [default to null]
**WaitFor** | **[]string** | The ID(s) of the Command(s) that this Command depends on. | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


