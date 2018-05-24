# \GrafeasProjectsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CreateProject**](GrafeasProjectsApi.md#CreateProject) | **Post** /v1alpha1/projects | Creates a new &#x60;Project&#x60;.
[**DeleteProject**](GrafeasProjectsApi.md#DeleteProject) | **Delete** /v1alpha1/{name} | Deletes the given &#x60;Project&#x60; from the system.
[**GetProject**](GrafeasProjectsApi.md#GetProject) | **Get** /v1alpha1/{name} | Returns the requested &#x60;Project&#x60;.
[**ListProjects**](GrafeasProjectsApi.md#ListProjects) | **Get** /v1alpha1/projects | Lists &#x60;Projects&#x60;


# **CreateProject**
> ProtobufEmpty CreateProject($body)

Creates a new `Project`.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**ApiProject**](ApiProject.md)|  | 

### Return type

[**ProtobufEmpty**](protobufEmpty.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **DeleteProject**
> ProtobufEmpty DeleteProject($name)

Deletes the given `Project` from the system.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **string**|  | 

### Return type

[**ProtobufEmpty**](protobufEmpty.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **GetProject**
> ApiProject GetProject($name)

Returns the requested `Project`.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **string**|  | 

### Return type

[**ApiProject**](apiProject.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ListProjects**
> ApiListProjectsResponse ListProjects($filter, $pageSize, $pageToken)

Lists `Projects`


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **filter** | **string**| The filter expression. | [optional] 
 **pageSize** | **int32**| Number of projects to return in the list. | [optional] 
 **pageToken** | **string**| Token to provide to skip to a particular spot in the list. | [optional] 

### Return type

[**ApiListProjectsResponse**](apiListProjectsResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

