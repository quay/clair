# ApiOccurrence

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** |  | [optional] [default to null]
**ResourceUrl** | **string** | The unique URL of the image or the container for which the &#x60;Occurrence&#x60; applies. For example, https://gcr.io/project/image@sha256:foo This field can be used as a filter in list requests. | [optional] [default to null]
**NoteName** | **string** | An analysis note associated with this image, in the form \&quot;providers/{provider_id}/notes/{NOTE_ID}\&quot; This field can be used as a filter in list requests. | [optional] [default to null]
**Kind** | [**ApiNoteKind**](apiNoteKind.md) | Output only. This explicitly denotes which of the &#x60;Occurrence&#x60; details are specified. This field can be used as a filter in list requests. | [optional] [default to null]
**VulnerabilityDetails** | [**VulnerabilityTypeVulnerabilityDetails**](VulnerabilityTypeVulnerabilityDetails.md) | Details of a security vulnerability note. | [optional] [default to null]
**BuildDetails** | [**ApiBuildDetails**](apiBuildDetails.md) | Build details for a verifiable build. | [optional] [default to null]
**DerivedImageDetails** | [**DockerImageDerivedDetails**](DockerImageDerivedDetails.md) | Describes how this resource derives from the basis in the associated note. | [optional] [default to null]
**InstallationDetails** | [**PackageManagerInstallationDetails**](PackageManagerInstallationDetails.md) | Describes the installation of a package on the linked resource. | [optional] [default to null]
**DeploymentDetails** | [**DeployableDeploymentDetails**](DeployableDeploymentDetails.md) | Describes the deployment of an artifact on a runtime. | [optional] [default to null]
**DiscoveredDetails** | [**DiscoveryDiscoveredDetails**](DiscoveryDiscoveredDetails.md) | Describes the initial scan status for this resource. | [optional] [default to null]
**AttestationDetails** | [**AttestationAuthorityAttestationDetails**](AttestationAuthorityAttestationDetails.md) | Describes an attestation of an artifact. | [optional] [default to null]
**Remediation** | **string** |  | [optional] [default to null]
**CreateTime** | [**time.Time**](time.Time.md) | Output only. The time this &#x60;Occurrence&#x60; was created. | [optional] [default to null]
**UpdateTime** | [**time.Time**](time.Time.md) | Output only. The time this &#x60;Occurrence&#x60; was last updated. | [optional] [default to null]
**OperationName** | **string** |  | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


