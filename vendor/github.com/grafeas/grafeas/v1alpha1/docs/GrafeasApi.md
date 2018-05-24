# \GrafeasApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CreateNote**](GrafeasApi.md#CreateNote) | **Post** /v1alpha1/{parent}/notes | Creates a new &#x60;Note&#x60;.
[**CreateOccurrence**](GrafeasApi.md#CreateOccurrence) | **Post** /v1alpha1/{parent}/occurrences | Creates a new &#x60;Occurrence&#x60;. Use this method to create &#x60;Occurrences&#x60; for a resource.
[**CreateOperation**](GrafeasApi.md#CreateOperation) | **Post** /v1alpha1/{parent}/operations | Creates a new &#x60;Operation&#x60;.
[**GetOccurrenceNote**](GrafeasApi.md#GetOccurrenceNote) | **Get** /v1alpha1/{name}/notes | Gets the &#x60;Note&#x60; attached to the given &#x60;Occurrence&#x60;.
[**ListNoteOccurrences**](GrafeasApi.md#ListNoteOccurrences) | **Get** /v1alpha1/{name}/occurrences | Lists &#x60;Occurrences&#x60; referencing the specified &#x60;Note&#x60;. Use this method to get all occurrences referencing your &#x60;Note&#x60; across all your customer projects.
[**ListNotes**](GrafeasApi.md#ListNotes) | **Get** /v1alpha1/{parent}/notes | Lists all &#x60;Notes&#x60; for a given project.
[**ListOccurrences**](GrafeasApi.md#ListOccurrences) | **Get** /v1alpha1/{parent}/occurrences | Lists active &#x60;Occurrences&#x60; for a given project matching the filters.
[**UpdateNote**](GrafeasApi.md#UpdateNote) | **Patch** /v1alpha1/{name} | Updates an existing &#x60;Note&#x60;.


# **CreateNote**
> ApiNote CreateNote($parent, $body)

Creates a new `Note`.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **parent** | **string**|  | 
 **body** | [**ApiNote**](ApiNote.md)|  | 

### Return type

[**ApiNote**](apiNote.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **CreateOccurrence**
> ApiOccurrence CreateOccurrence($parent, $body)

Creates a new `Occurrence`. Use this method to create `Occurrences` for a resource.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **parent** | **string**|  | 
 **body** | [**ApiOccurrence**](ApiOccurrence.md)|  | 

### Return type

[**ApiOccurrence**](apiOccurrence.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **CreateOperation**
> LongrunningOperation CreateOperation($parent, $body)

Creates a new `Operation`.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **parent** | **string**|  | 
 **body** | [**ApiCreateOperationRequest**](ApiCreateOperationRequest.md)|  | 

### Return type

[**LongrunningOperation**](longrunningOperation.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **GetOccurrenceNote**
> ApiNote GetOccurrenceNote($name)

Gets the `Note` attached to the given `Occurrence`.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **string**|  | 

### Return type

[**ApiNote**](apiNote.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ListNoteOccurrences**
> ApiListNoteOccurrencesResponse ListNoteOccurrences($name, $filter, $pageSize, $pageToken)

Lists `Occurrences` referencing the specified `Note`. Use this method to get all occurrences referencing your `Note` across all your customer projects.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **string**|  | 
 **filter** | **string**| The filter expression. | [optional] 
 **pageSize** | **int32**| Number of notes to return in the list. | [optional] 
 **pageToken** | **string**| Token to provide to skip to a particular spot in the list. | [optional] 

### Return type

[**ApiListNoteOccurrencesResponse**](apiListNoteOccurrencesResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ListNotes**
> ApiListNotesResponse ListNotes($parent, $filter, $pageSize, $pageToken)

Lists all `Notes` for a given project.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **parent** | **string**|  | 
 **filter** | **string**| The filter expression. | [optional] 
 **pageSize** | **int32**| Number of notes to return in the list. | [optional] 
 **pageToken** | **string**| Token to provide to skip to a particular spot in the list. | [optional] 

### Return type

[**ApiListNotesResponse**](apiListNotesResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ListOccurrences**
> ApiListOccurrencesResponse ListOccurrences($parent, $filter, $pageSize, $pageToken)

Lists active `Occurrences` for a given project matching the filters.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **parent** | **string**|  | 
 **filter** | **string**| The filter expression. | [optional] 
 **pageSize** | **int32**| Number of occurrences to return in the list. | [optional] 
 **pageToken** | **string**| Token to provide to skip to a particular spot in the list. | [optional] 

### Return type

[**ApiListOccurrencesResponse**](apiListOccurrencesResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateNote**
> ApiNote UpdateNote($name, $body)

Updates an existing `Note`.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **string**|  | 
 **body** | [**ApiNote**](ApiNote.md)|  | 

### Return type

[**ApiNote**](apiNote.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

