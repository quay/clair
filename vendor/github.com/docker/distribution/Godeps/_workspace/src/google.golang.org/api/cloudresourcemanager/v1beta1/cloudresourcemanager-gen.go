// Package cloudresourcemanager provides access to the Google Cloud Resource Manager API.
//
// See https://cloud.google.com/resource-manager
//
// Usage example:
//
//   import "google.golang.org/api/cloudresourcemanager/v1beta1"
//   ...
//   cloudresourcemanagerService, err := cloudresourcemanager.New(oauthHttpClient)
package cloudresourcemanager // import "google.golang.org/api/cloudresourcemanager/v1beta1"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/internal"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Always reference these packages, just in case the auto-generated code
// below doesn't.
var _ = bytes.NewBuffer
var _ = strconv.Itoa
var _ = fmt.Sprintf
var _ = json.NewDecoder
var _ = io.Copy
var _ = url.Parse
var _ = googleapi.Version
var _ = errors.New
var _ = strings.Replace
var _ = internal.MarshalJSON
var _ = context.Canceled
var _ = ctxhttp.Do

const apiId = "cloudresourcemanager:v1beta1"
const apiName = "cloudresourcemanager"
const apiVersion = "v1beta1"
const basePath = "https://cloudresourcemanager.googleapis.com/"

// OAuth2 scopes used by this API.
const (
	// View and manage your data across Google Cloud Platform services
	CloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
)

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.Organizations = NewOrganizationsService(s)
	s.Projects = NewProjectsService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	Organizations *OrganizationsService

	Projects *ProjectsService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewOrganizationsService(s *Service) *OrganizationsService {
	rs := &OrganizationsService{s: s}
	return rs
}

type OrganizationsService struct {
	s *Service
}

func NewProjectsService(s *Service) *ProjectsService {
	rs := &ProjectsService{s: s}
	return rs
}

type ProjectsService struct {
	s *Service
}

// Binding: Associates `members` with a `role`.
type Binding struct {
	// Members: Specifies the identities requesting access for a Cloud
	// Platform resource. `members` can have the following formats: *
	// `allUsers`: A special identifier that represents anyone who is on the
	// internet; with or without a Google account. *
	// `allAuthenticatedUsers`: A special identifier that represents anyone
	// who is authenticated with a Google account or a service account. *
	// `user:{emailid}`: An email address that represents a specific Google
	// account. For example, `alice@gmail.com` or `joe@example.com`. *
	// `serviceAccount:{emailid}`: An email address that represents a
	// service account. For example,
	// `my-other-app@appspot.gserviceaccount.com`. * `group:{emailid}`: An
	// email address that represents a Google group. For example,
	// `admins@example.com`. * `domain:{domain}`: A Google Apps domain name
	// that represents all the users of that domain. For example,
	// `google.com` or `example.com`.
	Members []string `json:"members,omitempty"`

	// Role: Role that is assigned to `members`. For example,
	// `roles/viewer`, `roles/editor`, or `roles/owner`. Required
	Role string `json:"role,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Members") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Binding) MarshalJSON() ([]byte, error) {
	type noMethod Binding
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Empty: A generic empty message that you can re-use to avoid defining
// duplicated empty messages in your APIs. A typical example is to use
// it as the request or the response type of an API method. For
// instance: service Foo { rpc Bar(google.protobuf.Empty) returns
// (google.protobuf.Empty); } The JSON representation for `Empty` is
// empty JSON object `{}`.
type Empty struct {
	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`
}

// GetIamPolicyRequest: Request message for `GetIamPolicy` method.
type GetIamPolicyRequest struct {
}

// ListOrganizationsResponse: The response returned from the
// ListOrganizations method.
type ListOrganizationsResponse struct {
	// NextPageToken: A pagination token to be used to retrieve the next
	// page of results. If the result is too large to fit within the page
	// size specified in the request, this field will be set with a token
	// that can be used to fetch the next page of results. If this field is
	// empty, it indicates that this response contains the last page of
	// results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// Organizations: The list of Organizations that matched the list query,
	// possibly paginated.
	Organizations []*Organization `json:"organizations,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "NextPageToken") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ListOrganizationsResponse) MarshalJSON() ([]byte, error) {
	type noMethod ListOrganizationsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ListProjectsResponse: A page of the response received from the
// [ListProjects][google.cloudresourcemanager.projects.v1beta1.DeveloperP
// rojects.ListProjects] method. A paginated response where more pages
// are available has `next_page_token` set. This token can be used in a
// subsequent request to retrieve the next request page.
type ListProjectsResponse struct {
	// NextPageToken: Pagination token. If the result set is too large to
	// fit in a single response, this token is returned. It encodes the
	// position of the current result cursor. Feeding this value into a new
	// list request with the `page_token` parameter gives the next page of
	// the results. When `next_page_token` is not filled in, there is no
	// next page and the list returned is the last page in the result set.
	// Pagination tokens have a limited lifetime. Note: pagination is not
	// yet supported; the server will not set this field.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// Projects: The list of projects that matched the list filter. This
	// list can be paginated.
	Projects []*Project `json:"projects,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "NextPageToken") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ListProjectsResponse) MarshalJSON() ([]byte, error) {
	type noMethod ListProjectsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Organization: The root node in the resource hierarchy to which a
// particular entity's (e.g., company) resources belong.
type Organization struct {
	// DisplayName: A friendly string to be used to refer to the
	// Organization in the UI. This field is required.
	DisplayName string `json:"displayName,omitempty"`

	// OrganizationId: An immutable id for the Organization that is assigned
	// on creation. This should be omitted when creating a new Organization.
	// This field is read-only.
	OrganizationId string `json:"organizationId,omitempty"`

	// Owner: The owner of this Organization. The owner should be specified
	// upon creation. Once set, it cannot be changed. This field is
	// required.
	Owner *OrganizationOwner `json:"owner,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "DisplayName") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Organization) MarshalJSON() ([]byte, error) {
	type noMethod Organization
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// OrganizationOwner: The entity that owns an Organization. The lifetime
// of the Organization and all of its descendants are bound to the
// OrganizationOwner. If the OrganizationOwner is deleted, the
// Organization and all its descendants will be deleted.
type OrganizationOwner struct {
	// DirectoryCustomerId: The Google for Work customer id used in the
	// Directory API.
	DirectoryCustomerId string `json:"directoryCustomerId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DirectoryCustomerId")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *OrganizationOwner) MarshalJSON() ([]byte, error) {
	type noMethod OrganizationOwner
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Policy: Defines an Identity and Access Management (IAM) policy. It is
// used to specify access control policies for Cloud Platform resources.
// A `Policy` consists of a list of `bindings`. A `Binding` binds a list
// of `members` to a `role`, where the members can be user accounts,
// Google groups, Google domains, and service accounts. A `role` is a
// named list of permissions defined by IAM. **Example** ``` {
// "bindings": [ { "role": "roles/owner", "members": [
// "user:mike@example.com", "group:admins@example.com",
// "domain:google.com",
// "serviceAccount:my-other-app@appspot.gserviceaccount.com"] }, {
// "role": "roles/viewer", "members": ["user:sean@example.com"] } ] }
// ``` For a description of IAM and its features, see the [IAM
// developer's guide][https://cloud.google.com/iam].
type Policy struct {
	// Bindings: Associates a list of `members` to a `role`. Multiple
	// `bindings` must not be specified for the same `role`. `bindings` with
	// no members will result in an error.
	Bindings []*Binding `json:"bindings,omitempty"`

	// Etag: Can be used to perform a read-modify-write.
	Etag string `json:"etag,omitempty"`

	// Version: Version of the `Policy`. The default version is 0.
	Version int64 `json:"version,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Bindings") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Policy) MarshalJSON() ([]byte, error) {
	type noMethod Policy
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Project: A Project is a high-level Google Cloud Platform entity. It
// is a container for ACLs, APIs, AppEngine Apps, VMs, and other Google
// Cloud Platform resources.
type Project struct {
	// CreateTime: Creation time. Read-only.
	CreateTime string `json:"createTime,omitempty"`

	// Labels: The labels associated with this project. Label keys must be
	// between 1 and 63 characters long and must conform to the following
	// regular expression: \[a-z\](\[-a-z0-9\]*\[a-z0-9\])?. Label values
	// must be between 0 and 63 characters long and must conform to the
	// regular expression (\[a-z\](\[-a-z0-9\]*\[a-z0-9\])?)?. No more than
	// 256 labels can be associated with a given resource. Clients should
	// store labels in a representation such as JSON that does not depend on
	// specific characters being disallowed. Example: "environment" : "dev"
	// Read-write.
	Labels map[string]string `json:"labels,omitempty"`

	// LifecycleState: The project lifecycle state. Read-only.
	//
	// Possible values:
	//   "LIFECYCLE_STATE_UNSPECIFIED"
	//   "ACTIVE"
	//   "DELETE_REQUESTED"
	//   "DELETE_IN_PROGRESS"
	LifecycleState string `json:"lifecycleState,omitempty"`

	// Name: The user-assigned name of the project. It must be 4 to 30
	// characters. Allowed characters are: lowercase and uppercase letters,
	// numbers, hyphen, single-quote, double-quote, space, and exclamation
	// point. Example: My Project Read-write.
	Name string `json:"name,omitempty"`

	// Parent: An optional reference to a parent Resource. The only
	// supported parent type is "organization". Once set, the parent cannot
	// be modified. Read-write.
	Parent *ResourceId `json:"parent,omitempty"`

	// ProjectId: The unique, user-assigned ID of the project. It must be 6
	// to 30 lowercase letters, digits, or hyphens. It must start with a
	// letter. Trailing hyphens are prohibited. Example: tokyo-rain-123
	// Read-only after creation.
	ProjectId string `json:"projectId,omitempty"`

	// ProjectNumber: The number uniquely identifying the project. Example:
	// 415104041262 Read-only.
	ProjectNumber int64 `json:"projectNumber,omitempty,string"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "CreateTime") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Project) MarshalJSON() ([]byte, error) {
	type noMethod Project
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ResourceId: A container to reference an id for any resource type. A
// 'resource' in Google Cloud Platform is a generic term for something
// you (a developer) may want to interact with through one of our API's.
// Some examples are an AppEngine app, a Compute Engine instance, Cloud
// SQL database, ...
type ResourceId struct {
	// Id: Required field for the type-specific id. This should correspond
	// to the id used in the type-specific API's.
	Id string `json:"id,omitempty"`

	// Type: Required field representing the resource type this id is for.
	// At present, the only valid type is "organization".
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ResourceId) MarshalJSON() ([]byte, error) {
	type noMethod ResourceId
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SetIamPolicyRequest: Request message for `SetIamPolicy` method.
type SetIamPolicyRequest struct {
	// Policy: REQUIRED: The complete policy to be applied to the
	// `resource`. The size of the policy is limited to a few 10s of KB. An
	// empty policy is a valid policy but certain Cloud Platform services
	// (such as Projects) might reject them.
	Policy *Policy `json:"policy,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Policy") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SetIamPolicyRequest) MarshalJSON() ([]byte, error) {
	type noMethod SetIamPolicyRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TestIamPermissionsRequest: Request message for `TestIamPermissions`
// method.
type TestIamPermissionsRequest struct {
	// Permissions: The set of permissions to check for the `resource`.
	// Permissions with wildcards (such as '*' or 'storage.*') are not
	// allowed.
	Permissions []string `json:"permissions,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Permissions") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TestIamPermissionsRequest) MarshalJSON() ([]byte, error) {
	type noMethod TestIamPermissionsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// TestIamPermissionsResponse: Response message for `TestIamPermissions`
// method.
type TestIamPermissionsResponse struct {
	// Permissions: A subset of `TestPermissionsRequest.permissions` that
	// the caller is allowed.
	Permissions []string `json:"permissions,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Permissions") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TestIamPermissionsResponse) MarshalJSON() ([]byte, error) {
	type noMethod TestIamPermissionsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "cloudresourcemanager.organizations.get":

type OrganizationsGetCall struct {
	s              *Service
	organizationId string
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Get: Fetches an Organization resource by id.
func (r *OrganizationsService) Get(organizationId string) *OrganizationsGetCall {
	c := &OrganizationsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.organizationId = organizationId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *OrganizationsGetCall) Fields(s ...googleapi.Field) *OrganizationsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *OrganizationsGetCall) IfNoneMatch(entityTag string) *OrganizationsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *OrganizationsGetCall) Context(ctx context.Context) *OrganizationsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *OrganizationsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/organizations/{organizationId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"organizationId": c.organizationId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.organizations.get" call.
// Exactly one of *Organization or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Organization.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *OrganizationsGetCall) Do() (*Organization, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Organization{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Fetches an Organization resource by id.",
	//   "httpMethod": "GET",
	//   "id": "cloudresourcemanager.organizations.get",
	//   "parameterOrder": [
	//     "organizationId"
	//   ],
	//   "parameters": {
	//     "organizationId": {
	//       "description": "The id of the Organization resource to fetch.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/organizations/{organizationId}",
	//   "response": {
	//     "$ref": "Organization"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.organizations.getIamPolicy":

type OrganizationsGetIamPolicyCall struct {
	s                   *Service
	resource            string
	getiampolicyrequest *GetIamPolicyRequest
	opt_                map[string]interface{}
	ctx_                context.Context
}

// GetIamPolicy: Gets the access control policy for a Organization
// resource. May be empty if no such policy or resource exists.
func (r *OrganizationsService) GetIamPolicy(resource string, getiampolicyrequest *GetIamPolicyRequest) *OrganizationsGetIamPolicyCall {
	c := &OrganizationsGetIamPolicyCall{s: r.s, opt_: make(map[string]interface{})}
	c.resource = resource
	c.getiampolicyrequest = getiampolicyrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *OrganizationsGetIamPolicyCall) Fields(s ...googleapi.Field) *OrganizationsGetIamPolicyCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *OrganizationsGetIamPolicyCall) Context(ctx context.Context) *OrganizationsGetIamPolicyCall {
	c.ctx_ = ctx
	return c
}

func (c *OrganizationsGetIamPolicyCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.getiampolicyrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/organizations/{resource}:getIamPolicy")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"resource": c.resource,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.organizations.getIamPolicy" call.
// Exactly one of *Policy or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Policy.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *OrganizationsGetIamPolicyCall) Do() (*Policy, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Policy{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets the access control policy for a Organization resource. May be empty if no such policy or resource exists.",
	//   "httpMethod": "POST",
	//   "id": "cloudresourcemanager.organizations.getIamPolicy",
	//   "parameterOrder": [
	//     "resource"
	//   ],
	//   "parameters": {
	//     "resource": {
	//       "description": "REQUIRED: The resource for which policy is being requested. Resource is usually specified as a path, such as, `projects/{project}`.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/organizations/{resource}:getIamPolicy",
	//   "request": {
	//     "$ref": "GetIamPolicyRequest"
	//   },
	//   "response": {
	//     "$ref": "Policy"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.organizations.list":

type OrganizationsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Query Organization resources.
func (r *OrganizationsService) List() *OrganizationsListCall {
	c := &OrganizationsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Filter sets the optional parameter "filter": An optional query string
// used to filter the Organizations to be return in the response. Filter
// rules are case-insensitive. Organizations may be filtered by
// `owner.directoryCustomerId` or by `domain`, where the domain is a
// Google for Work domain, for example: |Filter|Description|
// |------|-----------|
// |owner.directorycustomerid:123456789|Organizations with
// `owner.directory_customer_id` equal to `123456789`.|
// |domain:google.com|Organizations corresponding to the domain
// `google.com`.| This field is optional.
func (c *OrganizationsListCall) Filter(filter string) *OrganizationsListCall {
	c.opt_["filter"] = filter
	return c
}

// PageSize sets the optional parameter "pageSize": The maximum number
// of Organizations to return in the response. This field is optional.
func (c *OrganizationsListCall) PageSize(pageSize int64) *OrganizationsListCall {
	c.opt_["pageSize"] = pageSize
	return c
}

// PageToken sets the optional parameter "pageToken": A pagination token
// returned from a previous call to ListOrganizations that indicates
// from where listing should continue. This field is optional.
func (c *OrganizationsListCall) PageToken(pageToken string) *OrganizationsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *OrganizationsListCall) Fields(s ...googleapi.Field) *OrganizationsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *OrganizationsListCall) IfNoneMatch(entityTag string) *OrganizationsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *OrganizationsListCall) Context(ctx context.Context) *OrganizationsListCall {
	c.ctx_ = ctx
	return c
}

func (c *OrganizationsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["filter"]; ok {
		params.Set("filter", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageSize"]; ok {
		params.Set("pageSize", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/organizations")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.organizations.list" call.
// Exactly one of *ListOrganizationsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *ListOrganizationsResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *OrganizationsListCall) Do() (*ListOrganizationsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ListOrganizationsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Query Organization resources.",
	//   "httpMethod": "GET",
	//   "id": "cloudresourcemanager.organizations.list",
	//   "parameters": {
	//     "filter": {
	//       "description": "An optional query string used to filter the Organizations to be return in the response. Filter rules are case-insensitive. Organizations may be filtered by `owner.directoryCustomerId` or by `domain`, where the domain is a Google for Work domain, for example: |Filter|Description| |------|-----------| |owner.directorycustomerid:123456789|Organizations with `owner.directory_customer_id` equal to `123456789`.| |domain:google.com|Organizations corresponding to the domain `google.com`.| This field is optional.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageSize": {
	//       "description": "The maximum number of Organizations to return in the response. This field is optional.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "A pagination token returned from a previous call to ListOrganizations that indicates from where listing should continue. This field is optional.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/organizations",
	//   "response": {
	//     "$ref": "ListOrganizationsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.organizations.setIamPolicy":

type OrganizationsSetIamPolicyCall struct {
	s                   *Service
	resource            string
	setiampolicyrequest *SetIamPolicyRequest
	opt_                map[string]interface{}
	ctx_                context.Context
}

// SetIamPolicy: Sets the access control policy on a Organization
// resource. Replaces any existing policy.
func (r *OrganizationsService) SetIamPolicy(resource string, setiampolicyrequest *SetIamPolicyRequest) *OrganizationsSetIamPolicyCall {
	c := &OrganizationsSetIamPolicyCall{s: r.s, opt_: make(map[string]interface{})}
	c.resource = resource
	c.setiampolicyrequest = setiampolicyrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *OrganizationsSetIamPolicyCall) Fields(s ...googleapi.Field) *OrganizationsSetIamPolicyCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *OrganizationsSetIamPolicyCall) Context(ctx context.Context) *OrganizationsSetIamPolicyCall {
	c.ctx_ = ctx
	return c
}

func (c *OrganizationsSetIamPolicyCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.setiampolicyrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/organizations/{resource}:setIamPolicy")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"resource": c.resource,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.organizations.setIamPolicy" call.
// Exactly one of *Policy or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Policy.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *OrganizationsSetIamPolicyCall) Do() (*Policy, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Policy{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Sets the access control policy on a Organization resource. Replaces any existing policy.",
	//   "httpMethod": "POST",
	//   "id": "cloudresourcemanager.organizations.setIamPolicy",
	//   "parameterOrder": [
	//     "resource"
	//   ],
	//   "parameters": {
	//     "resource": {
	//       "description": "REQUIRED: The resource for which policy is being specified. `resource` is usually specified as a path, such as, `projects/{project}/zones/{zone}/disks/{disk}`.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/organizations/{resource}:setIamPolicy",
	//   "request": {
	//     "$ref": "SetIamPolicyRequest"
	//   },
	//   "response": {
	//     "$ref": "Policy"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.organizations.testIamPermissions":

type OrganizationsTestIamPermissionsCall struct {
	s                         *Service
	resource                  string
	testiampermissionsrequest *TestIamPermissionsRequest
	opt_                      map[string]interface{}
	ctx_                      context.Context
}

// TestIamPermissions: Returns permissions that a caller has on the
// specified Organization.
func (r *OrganizationsService) TestIamPermissions(resource string, testiampermissionsrequest *TestIamPermissionsRequest) *OrganizationsTestIamPermissionsCall {
	c := &OrganizationsTestIamPermissionsCall{s: r.s, opt_: make(map[string]interface{})}
	c.resource = resource
	c.testiampermissionsrequest = testiampermissionsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *OrganizationsTestIamPermissionsCall) Fields(s ...googleapi.Field) *OrganizationsTestIamPermissionsCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *OrganizationsTestIamPermissionsCall) Context(ctx context.Context) *OrganizationsTestIamPermissionsCall {
	c.ctx_ = ctx
	return c
}

func (c *OrganizationsTestIamPermissionsCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.testiampermissionsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/organizations/{resource}:testIamPermissions")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"resource": c.resource,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.organizations.testIamPermissions" call.
// Exactly one of *TestIamPermissionsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *TestIamPermissionsResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *OrganizationsTestIamPermissionsCall) Do() (*TestIamPermissionsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &TestIamPermissionsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Returns permissions that a caller has on the specified Organization.",
	//   "httpMethod": "POST",
	//   "id": "cloudresourcemanager.organizations.testIamPermissions",
	//   "parameterOrder": [
	//     "resource"
	//   ],
	//   "parameters": {
	//     "resource": {
	//       "description": "REQUIRED: The resource for which policy detail is being requested. `resource` is usually specified as a path, such as, `projects/{project}`.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/organizations/{resource}:testIamPermissions",
	//   "request": {
	//     "$ref": "TestIamPermissionsRequest"
	//   },
	//   "response": {
	//     "$ref": "TestIamPermissionsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.organizations.update":

type OrganizationsUpdateCall struct {
	s              *Service
	organizationId string
	organization   *Organization
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Update: Updates an Organization resource.
func (r *OrganizationsService) Update(organizationId string, organization *Organization) *OrganizationsUpdateCall {
	c := &OrganizationsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.organizationId = organizationId
	c.organization = organization
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *OrganizationsUpdateCall) Fields(s ...googleapi.Field) *OrganizationsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *OrganizationsUpdateCall) Context(ctx context.Context) *OrganizationsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *OrganizationsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.organization)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/organizations/{organizationId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"organizationId": c.organizationId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.organizations.update" call.
// Exactly one of *Organization or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Organization.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *OrganizationsUpdateCall) Do() (*Organization, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Organization{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates an Organization resource.",
	//   "httpMethod": "PUT",
	//   "id": "cloudresourcemanager.organizations.update",
	//   "parameterOrder": [
	//     "organizationId"
	//   ],
	//   "parameters": {
	//     "organizationId": {
	//       "description": "An immutable id for the Organization that is assigned on creation. This should be omitted when creating a new Organization. This field is read-only.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/organizations/{organizationId}",
	//   "request": {
	//     "$ref": "Organization"
	//   },
	//   "response": {
	//     "$ref": "Organization"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.projects.create":

type ProjectsCreateCall struct {
	s       *Service
	project *Project
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Create: Creates a project resource. Initially, the project resource
// is owned by its creator exclusively. The creator can later grant
// permission to others to read or update the project. Several APIs are
// activated automatically for the project, including Google Cloud
// Storage.
func (r *ProjectsService) Create(project *Project) *ProjectsCreateCall {
	c := &ProjectsCreateCall{s: r.s, opt_: make(map[string]interface{})}
	c.project = project
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsCreateCall) Fields(s ...googleapi.Field) *ProjectsCreateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ProjectsCreateCall) Context(ctx context.Context) *ProjectsCreateCall {
	c.ctx_ = ctx
	return c
}

func (c *ProjectsCreateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.project)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/projects")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.projects.create" call.
// Exactly one of *Project or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Project.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ProjectsCreateCall) Do() (*Project, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Project{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Creates a project resource. Initially, the project resource is owned by its creator exclusively. The creator can later grant permission to others to read or update the project. Several APIs are activated automatically for the project, including Google Cloud Storage.",
	//   "httpMethod": "POST",
	//   "id": "cloudresourcemanager.projects.create",
	//   "path": "v1beta1/projects",
	//   "request": {
	//     "$ref": "Project"
	//   },
	//   "response": {
	//     "$ref": "Project"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.projects.delete":

type ProjectsDeleteCall struct {
	s         *Service
	projectId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Delete: Marks the project identified by the specified `project_id`
// (for example, `my-project-123`) for deletion. This method will only
// affect the project if the following criteria are met: + The project
// does not have a billing account associated with it. + The project has
// a lifecycle state of
// [ACTIVE][google.cloudresourcemanager.projects.v1beta1.LifecycleState.A
// CTIVE]. This method changes the project's lifecycle state from
// [ACTIVE][google.cloudresourcemanager.projects.v1beta1.LifecycleState.A
// CTIVE] to [DELETE_REQUESTED]
// [google.cloudresourcemanager.projects.v1beta1.LifecycleState.DELETE_RE
// QUESTED]. The deletion starts at an unspecified time, at which point
// the lifecycle state changes to [DELETE_IN_PROGRESS]
// [google.cloudresourcemanager.projects.v1beta1.LifecycleState.DELETE_IN
// _PROGRESS]. Until the deletion completes, you can check the lifecycle
// state checked by retrieving the project with [GetProject]
// [google.cloudresourcemanager.projects.v1beta1.DeveloperProjects.GetPro
// ject], and the project remains visible to [ListProjects]
// [google.cloudresourcemanager.projects.v1beta1.DeveloperProjects.ListPr
// ojects]. However, you cannot update the project. After the deletion
// completes, the project is not retrievable by the [GetProject]
// [google.cloudresourcemanager.projects.v1beta1.DeveloperProjects.GetPro
// ject] and [ListProjects]
// [google.cloudresourcemanager.projects.v1beta1.DeveloperProjects.ListPr
// ojects] methods. The caller must have modify permissions for this
// project.
func (r *ProjectsService) Delete(projectId string) *ProjectsDeleteCall {
	c := &ProjectsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.projectId = projectId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsDeleteCall) Fields(s ...googleapi.Field) *ProjectsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ProjectsDeleteCall) Context(ctx context.Context) *ProjectsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ProjectsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/projects/{projectId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"projectId": c.projectId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.projects.delete" call.
// Exactly one of *Empty or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Empty.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ProjectsDeleteCall) Do() (*Empty, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Empty{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Marks the project identified by the specified `project_id` (for example, `my-project-123`) for deletion. This method will only affect the project if the following criteria are met: + The project does not have a billing account associated with it. + The project has a lifecycle state of [ACTIVE][google.cloudresourcemanager.projects.v1beta1.LifecycleState.ACTIVE]. This method changes the project's lifecycle state from [ACTIVE][google.cloudresourcemanager.projects.v1beta1.LifecycleState.ACTIVE] to [DELETE_REQUESTED] [google.cloudresourcemanager.projects.v1beta1.LifecycleState.DELETE_REQUESTED]. The deletion starts at an unspecified time, at which point the lifecycle state changes to [DELETE_IN_PROGRESS] [google.cloudresourcemanager.projects.v1beta1.LifecycleState.DELETE_IN_PROGRESS]. Until the deletion completes, you can check the lifecycle state checked by retrieving the project with [GetProject] [google.cloudresourcemanager.projects.v1beta1.DeveloperProjects.GetProject], and the project remains visible to [ListProjects] [google.cloudresourcemanager.projects.v1beta1.DeveloperProjects.ListProjects]. However, you cannot update the project. After the deletion completes, the project is not retrievable by the [GetProject] [google.cloudresourcemanager.projects.v1beta1.DeveloperProjects.GetProject] and [ListProjects] [google.cloudresourcemanager.projects.v1beta1.DeveloperProjects.ListProjects] methods. The caller must have modify permissions for this project.",
	//   "httpMethod": "DELETE",
	//   "id": "cloudresourcemanager.projects.delete",
	//   "parameterOrder": [
	//     "projectId"
	//   ],
	//   "parameters": {
	//     "projectId": {
	//       "description": "The project ID (for example, `foo-bar-123`). Required.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/projects/{projectId}",
	//   "response": {
	//     "$ref": "Empty"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.projects.get":

type ProjectsGetCall struct {
	s         *Service
	projectId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Retrieves the project identified by the specified `project_id`
// (for example, `my-project-123`). The caller must have read
// permissions for this project.
func (r *ProjectsService) Get(projectId string) *ProjectsGetCall {
	c := &ProjectsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.projectId = projectId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsGetCall) Fields(s ...googleapi.Field) *ProjectsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ProjectsGetCall) IfNoneMatch(entityTag string) *ProjectsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ProjectsGetCall) Context(ctx context.Context) *ProjectsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ProjectsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/projects/{projectId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"projectId": c.projectId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.projects.get" call.
// Exactly one of *Project or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Project.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ProjectsGetCall) Do() (*Project, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Project{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Retrieves the project identified by the specified `project_id` (for example, `my-project-123`). The caller must have read permissions for this project.",
	//   "httpMethod": "GET",
	//   "id": "cloudresourcemanager.projects.get",
	//   "parameterOrder": [
	//     "projectId"
	//   ],
	//   "parameters": {
	//     "projectId": {
	//       "description": "The project ID (for example, `my-project-123`). Required.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/projects/{projectId}",
	//   "response": {
	//     "$ref": "Project"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.projects.getIamPolicy":

type ProjectsGetIamPolicyCall struct {
	s                   *Service
	resource            string
	getiampolicyrequest *GetIamPolicyRequest
	opt_                map[string]interface{}
	ctx_                context.Context
}

// GetIamPolicy: Returns the IAM access control policy for specified
// project.
func (r *ProjectsService) GetIamPolicy(resource string, getiampolicyrequest *GetIamPolicyRequest) *ProjectsGetIamPolicyCall {
	c := &ProjectsGetIamPolicyCall{s: r.s, opt_: make(map[string]interface{})}
	c.resource = resource
	c.getiampolicyrequest = getiampolicyrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsGetIamPolicyCall) Fields(s ...googleapi.Field) *ProjectsGetIamPolicyCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ProjectsGetIamPolicyCall) Context(ctx context.Context) *ProjectsGetIamPolicyCall {
	c.ctx_ = ctx
	return c
}

func (c *ProjectsGetIamPolicyCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.getiampolicyrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/projects/{resource}:getIamPolicy")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"resource": c.resource,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.projects.getIamPolicy" call.
// Exactly one of *Policy or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Policy.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ProjectsGetIamPolicyCall) Do() (*Policy, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Policy{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Returns the IAM access control policy for specified project.",
	//   "httpMethod": "POST",
	//   "id": "cloudresourcemanager.projects.getIamPolicy",
	//   "parameterOrder": [
	//     "resource"
	//   ],
	//   "parameters": {
	//     "resource": {
	//       "description": "REQUIRED: The resource for which policy is being requested. Resource is usually specified as a path, such as, `projects/{project}`.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/projects/{resource}:getIamPolicy",
	//   "request": {
	//     "$ref": "GetIamPolicyRequest"
	//   },
	//   "response": {
	//     "$ref": "Policy"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.projects.list":

type ProjectsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Lists projects that are visible to the user and satisfy the
// specified filter. This method returns projects in an unspecified
// order. New projects do not necessarily appear at the end of the list.
func (r *ProjectsService) List() *ProjectsListCall {
	c := &ProjectsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Filter sets the optional parameter "filter": An expression for
// filtering the results of the request. Filter rules are case
// insensitive. The fields eligible for filtering are: + `name` + `id` +
// labels.key where *key* is the name of a label Some examples of using
// labels as filters: |Filter|Description| |------|-----------|
// |name:*|The project has a name.| |name:Howl|The project's name is
// `Howl` or `howl`.| |name:HOWL|Equivalent to above.|
// |NAME:howl|Equivalent to above.| |labels.color:*|The project has the
// label `color`.| |labels.color:red|The project's label `color` has the
// value `red`.| |labels.color:red label.size:big|The project's label
// `color` has the value `red` and its label `size` has the value `big`.
func (c *ProjectsListCall) Filter(filter string) *ProjectsListCall {
	c.opt_["filter"] = filter
	return c
}

// PageSize sets the optional parameter "pageSize": The maximum number
// of Projects to return in the response. The server can return fewer
// projects than requested. If unspecified, server picks an appropriate
// default. Note: pagination is not yet supported; the server ignores
// this field.
func (c *ProjectsListCall) PageSize(pageSize int64) *ProjectsListCall {
	c.opt_["pageSize"] = pageSize
	return c
}

// PageToken sets the optional parameter "pageToken": A pagination token
// returned from a previous call to ListProject that indicates from
// where listing should continue. Note: pagination is not yet supported;
// the server ignores this field.
func (c *ProjectsListCall) PageToken(pageToken string) *ProjectsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsListCall) Fields(s ...googleapi.Field) *ProjectsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ProjectsListCall) IfNoneMatch(entityTag string) *ProjectsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ProjectsListCall) Context(ctx context.Context) *ProjectsListCall {
	c.ctx_ = ctx
	return c
}

func (c *ProjectsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["filter"]; ok {
		params.Set("filter", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageSize"]; ok {
		params.Set("pageSize", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/projects")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.projects.list" call.
// Exactly one of *ListProjectsResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ListProjectsResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ProjectsListCall) Do() (*ListProjectsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ListProjectsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Lists projects that are visible to the user and satisfy the specified filter. This method returns projects in an unspecified order. New projects do not necessarily appear at the end of the list.",
	//   "httpMethod": "GET",
	//   "id": "cloudresourcemanager.projects.list",
	//   "parameters": {
	//     "filter": {
	//       "description": "An expression for filtering the results of the request. Filter rules are case insensitive. The fields eligible for filtering are: + `name` + `id` + labels.key where *key* is the name of a label Some examples of using labels as filters: |Filter|Description| |------|-----------| |name:*|The project has a name.| |name:Howl|The project's name is `Howl` or `howl`.| |name:HOWL|Equivalent to above.| |NAME:howl|Equivalent to above.| |labels.color:*|The project has the label `color`.| |labels.color:red|The project's label `color` has the value `red`.| |labels.color:red label.size:big|The project's label `color` has the value `red` and its label `size` has the value `big`. Optional.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageSize": {
	//       "description": "The maximum number of Projects to return in the response. The server can return fewer projects than requested. If unspecified, server picks an appropriate default. Note: pagination is not yet supported; the server ignores this field. Optional.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "A pagination token returned from a previous call to ListProject that indicates from where listing should continue. Note: pagination is not yet supported; the server ignores this field. Optional.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/projects",
	//   "response": {
	//     "$ref": "ListProjectsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.projects.setIamPolicy":

type ProjectsSetIamPolicyCall struct {
	s                   *Service
	resource            string
	setiampolicyrequest *SetIamPolicyRequest
	opt_                map[string]interface{}
	ctx_                context.Context
}

// SetIamPolicy: Sets the IAM access control policy for the specified
// project. We do not currently support 'domain:' prefixed members in a
// Binding of a Policy. Calling this method requires enabling the App
// Engine Admin API.
func (r *ProjectsService) SetIamPolicy(resource string, setiampolicyrequest *SetIamPolicyRequest) *ProjectsSetIamPolicyCall {
	c := &ProjectsSetIamPolicyCall{s: r.s, opt_: make(map[string]interface{})}
	c.resource = resource
	c.setiampolicyrequest = setiampolicyrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsSetIamPolicyCall) Fields(s ...googleapi.Field) *ProjectsSetIamPolicyCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ProjectsSetIamPolicyCall) Context(ctx context.Context) *ProjectsSetIamPolicyCall {
	c.ctx_ = ctx
	return c
}

func (c *ProjectsSetIamPolicyCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.setiampolicyrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/projects/{resource}:setIamPolicy")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"resource": c.resource,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.projects.setIamPolicy" call.
// Exactly one of *Policy or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Policy.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ProjectsSetIamPolicyCall) Do() (*Policy, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Policy{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Sets the IAM access control policy for the specified project. We do not currently support 'domain:' prefixed members in a Binding of a Policy. Calling this method requires enabling the App Engine Admin API.",
	//   "httpMethod": "POST",
	//   "id": "cloudresourcemanager.projects.setIamPolicy",
	//   "parameterOrder": [
	//     "resource"
	//   ],
	//   "parameters": {
	//     "resource": {
	//       "description": "REQUIRED: The resource for which policy is being specified. `resource` is usually specified as a path, such as, `projects/{project}/zones/{zone}/disks/{disk}`.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/projects/{resource}:setIamPolicy",
	//   "request": {
	//     "$ref": "SetIamPolicyRequest"
	//   },
	//   "response": {
	//     "$ref": "Policy"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.projects.testIamPermissions":

type ProjectsTestIamPermissionsCall struct {
	s                         *Service
	resource                  string
	testiampermissionsrequest *TestIamPermissionsRequest
	opt_                      map[string]interface{}
	ctx_                      context.Context
}

// TestIamPermissions: Tests the specified permissions against the IAM
// access control policy for the specified project.
func (r *ProjectsService) TestIamPermissions(resource string, testiampermissionsrequest *TestIamPermissionsRequest) *ProjectsTestIamPermissionsCall {
	c := &ProjectsTestIamPermissionsCall{s: r.s, opt_: make(map[string]interface{})}
	c.resource = resource
	c.testiampermissionsrequest = testiampermissionsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsTestIamPermissionsCall) Fields(s ...googleapi.Field) *ProjectsTestIamPermissionsCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ProjectsTestIamPermissionsCall) Context(ctx context.Context) *ProjectsTestIamPermissionsCall {
	c.ctx_ = ctx
	return c
}

func (c *ProjectsTestIamPermissionsCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.testiampermissionsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/projects/{resource}:testIamPermissions")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"resource": c.resource,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.projects.testIamPermissions" call.
// Exactly one of *TestIamPermissionsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *TestIamPermissionsResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ProjectsTestIamPermissionsCall) Do() (*TestIamPermissionsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &TestIamPermissionsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Tests the specified permissions against the IAM access control policy for the specified project.",
	//   "httpMethod": "POST",
	//   "id": "cloudresourcemanager.projects.testIamPermissions",
	//   "parameterOrder": [
	//     "resource"
	//   ],
	//   "parameters": {
	//     "resource": {
	//       "description": "REQUIRED: The resource for which policy detail is being requested. `resource` is usually specified as a path, such as, `projects/{project}`.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/projects/{resource}:testIamPermissions",
	//   "request": {
	//     "$ref": "TestIamPermissionsRequest"
	//   },
	//   "response": {
	//     "$ref": "TestIamPermissionsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.projects.undelete":

type ProjectsUndeleteCall struct {
	s         *Service
	projectId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Undelete: Restores the project identified by the specified
// `project_id` (for example, `my-project-123`). You can only use this
// method for a project that has a lifecycle state of [DELETE_REQUESTED]
// [google.cloudresourcemanager.projects.v1beta1.LifecycleState.DELETE_RE
// QUESTED]. After deletion starts, as indicated by a lifecycle state of
// [DELETE_IN_PROGRESS]
// [google.cloudresourcemanager.projects.v1beta1.LifecycleState.DELETE_IN
// _PROGRESS], the project cannot be restored. The caller must have
// modify permissions for this project.
func (r *ProjectsService) Undelete(projectId string) *ProjectsUndeleteCall {
	c := &ProjectsUndeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.projectId = projectId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsUndeleteCall) Fields(s ...googleapi.Field) *ProjectsUndeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ProjectsUndeleteCall) Context(ctx context.Context) *ProjectsUndeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ProjectsUndeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/projects/{projectId}:undelete")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"projectId": c.projectId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.projects.undelete" call.
// Exactly one of *Empty or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Empty.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ProjectsUndeleteCall) Do() (*Empty, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Empty{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Restores the project identified by the specified `project_id` (for example, `my-project-123`). You can only use this method for a project that has a lifecycle state of [DELETE_REQUESTED] [google.cloudresourcemanager.projects.v1beta1.LifecycleState.DELETE_REQUESTED]. After deletion starts, as indicated by a lifecycle state of [DELETE_IN_PROGRESS] [google.cloudresourcemanager.projects.v1beta1.LifecycleState.DELETE_IN_PROGRESS], the project cannot be restored. The caller must have modify permissions for this project.",
	//   "httpMethod": "POST",
	//   "id": "cloudresourcemanager.projects.undelete",
	//   "parameterOrder": [
	//     "projectId"
	//   ],
	//   "parameters": {
	//     "projectId": {
	//       "description": "The project ID (for example, `foo-bar-123`). Required.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/projects/{projectId}:undelete",
	//   "response": {
	//     "$ref": "Empty"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}

// method id "cloudresourcemanager.projects.update":

type ProjectsUpdateCall struct {
	s         *Service
	projectId string
	project   *Project
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Update: Updates the attributes of the project identified by the
// specified `project_id` (for example, `my-project-123`). The caller
// must have modify permissions for this project.
func (r *ProjectsService) Update(projectId string, project *Project) *ProjectsUpdateCall {
	c := &ProjectsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.projectId = projectId
	c.project = project
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsUpdateCall) Fields(s ...googleapi.Field) *ProjectsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ProjectsUpdateCall) Context(ctx context.Context) *ProjectsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ProjectsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.project)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1beta1/projects/{projectId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"projectId": c.projectId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "cloudresourcemanager.projects.update" call.
// Exactly one of *Project or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Project.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ProjectsUpdateCall) Do() (*Project, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Project{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates the attributes of the project identified by the specified `project_id` (for example, `my-project-123`). The caller must have modify permissions for this project.",
	//   "httpMethod": "PUT",
	//   "id": "cloudresourcemanager.projects.update",
	//   "parameterOrder": [
	//     "projectId"
	//   ],
	//   "parameters": {
	//     "projectId": {
	//       "description": "The project ID (for example, `my-project-123`). Required.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1beta1/projects/{projectId}",
	//   "request": {
	//     "$ref": "Project"
	//   },
	//   "response": {
	//     "$ref": "Project"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform"
	//   ]
	// }

}
