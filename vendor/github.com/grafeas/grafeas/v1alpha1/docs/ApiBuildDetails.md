# ApiBuildDetails

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Provenance** | [**ApiBuildProvenance**](apiBuildProvenance.md) |  | [optional] [default to null]
**ProvenanceBytes** | **string** | Serialized JSON representation of the provenance, used in generating the &#x60;BuildSignature&#x60; in the corresponding Result. After verifying the signature, &#x60;provenance_bytes&#x60; can be unmarshalled and compared to the provenance to confirm that it is unchanged. A base64-encoded string representation of the provenance bytes is used for the signature in order to interoperate with openssl which expects this format for signature verification.  The serialized form is captured both to avoid ambiguity in how the provenance is marshalled to json as well to prevent incompatibilities with future changes. | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


