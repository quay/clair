# ApiPgpSignedAttestation

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Signature** | **string** | The raw content of the signature, as output by gpg or equivalent.  Since this message only supports attached signatures, the payload that was signed must be attached. While the signature format supported is dependent on the verification implementation, currently only ASCII-armored (&#x60;--armor&#x60; to gpg), non-clearsigned (&#x60;--sign&#x60; rather than &#x60;--clearsign&#x60; to gpg) are supported. Concretely, &#x60;gpg --sign --armor --output&#x3D;signature.gpg payload.json&#x60; will create the signature content expected in this field in &#x60;signature.gpg&#x60; for the &#x60;payload.json&#x60; attestation payload. | [optional] [default to null]
**ContentType** | [**PgpSignedAttestationContentType**](PgpSignedAttestationContentType.md) | Type (e.g. schema) of the attestation payload that was signed. The verifier must ensure that the provided type is one that the verifier supports, and that the attestation payload is a valid instantiation of that type (e.g. by validating a JSON schema). | [optional] [default to null]
**PgpKeyId** | **string** | The cryptographic fingerprint of the key used to generate the signature, as output by, e.g. &#x60;gpg --list-keys&#x60;. This should be the version 4, full 160-bit fingerprint, expressed as a 40 character hexidecimal string. See https://tools.ietf.org/html/rfc4880#section-12.2 for details. Implementations may choose to acknowledge \&quot;LONG\&quot;, \&quot;SHORT\&quot;, or other abbreviated key IDs, but only the full fingerprint is guaranteed to work. In gpg, the full fingerprint can be retrieved from the &#x60;fpr&#x60; field returned when calling --list-keys with --with-colons.  For example: &#x60;&#x60;&#x60; gpg --with-colons --with-fingerprint --force-v4-certs \\     --list-keys attester@example.com tru::1:1513631572:0:3:1:5 pub:...&lt;SNIP&gt;... fpr:::::::::24FF6481B76AC91E66A00AC657A93A81EF3AE6FB: &#x60;&#x60;&#x60; Above, the fingerprint is &#x60;24FF6481B76AC91E66A00AC657A93A81EF3AE6FB&#x60;. | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


