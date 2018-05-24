# ApiBuildSignature

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**PublicKey** | **string** | Public key of the builder which can be used to verify that the related findings are valid and unchanged. If &#x60;key_type&#x60; is empty, this defaults to PEM encoded public keys.  This field may be empty if &#x60;key_id&#x60; references an external key.  For Cloud Container Builder based signatures, this is a PEM encoded public key. To verify the Cloud Container Builder signature, place the contents of this field into a file (public.pem). The signature field is base64-decoded into its binary representation in signature.bin, and the provenance bytes from &#x60;BuildDetails&#x60; are base64-decoded into a binary representation in signed.bin. OpenSSL can then verify the signature: &#x60;openssl sha256 -verify public.pem -signature signature.bin signed.bin&#x60; | [optional] [default to null]
**Signature** | **string** | Signature of the related &#x60;BuildProvenance&#x60;, encoded in a base64 string. | [optional] [default to null]
**KeyId** | **string** | An Id for the key used to sign. This could be either an Id for the key stored in &#x60;public_key&#x60; (such as the Id or fingerprint for a PGP key, or the CN for a cert), or a reference to an external key (such as a reference to a key in Cloud Key Management Service). | [optional] [default to null]
**KeyType** | [**BuildSignatureKeyType**](BuildSignatureKeyType.md) |  | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


