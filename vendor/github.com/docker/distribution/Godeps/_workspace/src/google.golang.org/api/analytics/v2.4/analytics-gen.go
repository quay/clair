// Package analytics provides access to the Google Analytics API.
//
// See https://developers.google.com/analytics/
//
// Usage example:
//
//   import "google.golang.org/api/analytics/v2.4"
//   ...
//   analyticsService, err := analytics.New(oauthHttpClient)
package analytics // import "google.golang.org/api/analytics/v2.4"

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

const apiId = "analytics:v2.4"
const apiName = "analytics"
const apiVersion = "v2.4"
const basePath = "https://www.googleapis.com/analytics/v2.4/"

// OAuth2 scopes used by this API.
const (
	// View and manage your Google Analytics data
	AnalyticsScope = "https://www.googleapis.com/auth/analytics"

	// View your Google Analytics data
	AnalyticsReadonlyScope = "https://www.googleapis.com/auth/analytics.readonly"
)

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.Data = NewDataService(s)
	s.Management = NewManagementService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	Data *DataService

	Management *ManagementService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewDataService(s *Service) *DataService {
	rs := &DataService{s: s}
	return rs
}

type DataService struct {
	s *Service
}

func NewManagementService(s *Service) *ManagementService {
	rs := &ManagementService{s: s}
	rs.Accounts = NewManagementAccountsService(s)
	rs.Goals = NewManagementGoalsService(s)
	rs.Profiles = NewManagementProfilesService(s)
	rs.Segments = NewManagementSegmentsService(s)
	rs.Webproperties = NewManagementWebpropertiesService(s)
	return rs
}

type ManagementService struct {
	s *Service

	Accounts *ManagementAccountsService

	Goals *ManagementGoalsService

	Profiles *ManagementProfilesService

	Segments *ManagementSegmentsService

	Webproperties *ManagementWebpropertiesService
}

func NewManagementAccountsService(s *Service) *ManagementAccountsService {
	rs := &ManagementAccountsService{s: s}
	return rs
}

type ManagementAccountsService struct {
	s *Service
}

func NewManagementGoalsService(s *Service) *ManagementGoalsService {
	rs := &ManagementGoalsService{s: s}
	return rs
}

type ManagementGoalsService struct {
	s *Service
}

func NewManagementProfilesService(s *Service) *ManagementProfilesService {
	rs := &ManagementProfilesService{s: s}
	return rs
}

type ManagementProfilesService struct {
	s *Service
}

func NewManagementSegmentsService(s *Service) *ManagementSegmentsService {
	rs := &ManagementSegmentsService{s: s}
	return rs
}

type ManagementSegmentsService struct {
	s *Service
}

func NewManagementWebpropertiesService(s *Service) *ManagementWebpropertiesService {
	rs := &ManagementWebpropertiesService{s: s}
	return rs
}

type ManagementWebpropertiesService struct {
	s *Service
}

// method id "analytics.data.get":

type DataGetCall struct {
	s         *Service
	ids       string
	startDate string
	endDate   string
	metrics   string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Returns Analytics report data for a view (profile).
func (r *DataService) Get(ids string, startDate string, endDate string, metrics string) *DataGetCall {
	c := &DataGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.ids = ids
	c.startDate = startDate
	c.endDate = endDate
	c.metrics = metrics
	return c
}

// Dimensions sets the optional parameter "dimensions": A
// comma-separated list of Analytics dimensions. E.g.,
// 'ga:browser,ga:city'.
func (c *DataGetCall) Dimensions(dimensions string) *DataGetCall {
	c.opt_["dimensions"] = dimensions
	return c
}

// Filters sets the optional parameter "filters": A comma-separated list
// of dimension or metric filters to be applied to the report data.
func (c *DataGetCall) Filters(filters string) *DataGetCall {
	c.opt_["filters"] = filters
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of entries to include in this feed.
func (c *DataGetCall) MaxResults(maxResults int64) *DataGetCall {
	c.opt_["max-results"] = maxResults
	return c
}

// Segment sets the optional parameter "segment": An Analytics advanced
// segment to be applied to the report data.
func (c *DataGetCall) Segment(segment string) *DataGetCall {
	c.opt_["segment"] = segment
	return c
}

// Sort sets the optional parameter "sort": A comma-separated list of
// dimensions or metrics that determine the sort order for the report
// data.
func (c *DataGetCall) Sort(sort string) *DataGetCall {
	c.opt_["sort"] = sort
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first entity to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
func (c *DataGetCall) StartIndex(startIndex int64) *DataGetCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *DataGetCall) Fields(s ...googleapi.Field) *DataGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *DataGetCall) IfNoneMatch(entityTag string) *DataGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *DataGetCall) Context(ctx context.Context) *DataGetCall {
	c.ctx_ = ctx
	return c
}

func (c *DataGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("end-date", fmt.Sprintf("%v", c.endDate))
	params.Set("ids", fmt.Sprintf("%v", c.ids))
	params.Set("metrics", fmt.Sprintf("%v", c.metrics))
	params.Set("start-date", fmt.Sprintf("%v", c.startDate))
	if v, ok := c.opt_["dimensions"]; ok {
		params.Set("dimensions", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["filters"]; ok {
		params.Set("filters", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["max-results"]; ok {
		params.Set("max-results", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["segment"]; ok {
		params.Set("segment", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["sort"]; ok {
		params.Set("sort", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["start-index"]; ok {
		params.Set("start-index", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "data")
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

// Do executes the "analytics.data.get" call.
func (c *DataGetCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Returns Analytics report data for a view (profile).",
	//   "httpMethod": "GET",
	//   "id": "analytics.data.get",
	//   "parameterOrder": [
	//     "ids",
	//     "start-date",
	//     "end-date",
	//     "metrics"
	//   ],
	//   "parameters": {
	//     "dimensions": {
	//       "description": "A comma-separated list of Analytics dimensions. E.g., 'ga:browser,ga:city'.",
	//       "location": "query",
	//       "pattern": "(ga:.+)?",
	//       "type": "string"
	//     },
	//     "end-date": {
	//       "description": "End date for fetching report data. All requests should specify an end date formatted as YYYY-MM-DD.",
	//       "location": "query",
	//       "pattern": "[0-9]{4}-[0-9]{2}-[0-9]{2}",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "filters": {
	//       "description": "A comma-separated list of dimension or metric filters to be applied to the report data.",
	//       "location": "query",
	//       "pattern": "ga:.+",
	//       "type": "string"
	//     },
	//     "ids": {
	//       "description": "Unique table ID for retrieving report data. Table ID is of the form ga:XXXX, where XXXX is the Analytics view (profile) ID.",
	//       "location": "query",
	//       "pattern": "ga:[0-9]+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of entries to include in this feed.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "metrics": {
	//       "description": "A comma-separated list of Analytics metrics. E.g., 'ga:sessions,ga:pageviews'. At least one metric must be specified to retrieve a valid Analytics report.",
	//       "location": "query",
	//       "pattern": "ga:.+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "segment": {
	//       "description": "An Analytics advanced segment to be applied to the report data.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "sort": {
	//       "description": "A comma-separated list of dimensions or metrics that determine the sort order for the report data.",
	//       "location": "query",
	//       "pattern": "(-)?ga:.+",
	//       "type": "string"
	//     },
	//     "start-date": {
	//       "description": "Start date for fetching report data. All requests should specify a start date formatted as YYYY-MM-DD.",
	//       "location": "query",
	//       "pattern": "[0-9]{4}-[0-9]{2}-[0-9]{2}",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "start-index": {
	//       "description": "An index of the first entity to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     }
	//   },
	//   "path": "data",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.accounts.list":

type ManagementAccountsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Lists all accounts to which the user has access.
func (r *ManagementAccountsService) List() *ManagementAccountsListCall {
	c := &ManagementAccountsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of accounts to include in this response.
func (c *ManagementAccountsListCall) MaxResults(maxResults int64) *ManagementAccountsListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first account to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
func (c *ManagementAccountsListCall) StartIndex(startIndex int64) *ManagementAccountsListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementAccountsListCall) Fields(s ...googleapi.Field) *ManagementAccountsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementAccountsListCall) IfNoneMatch(entityTag string) *ManagementAccountsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementAccountsListCall) Context(ctx context.Context) *ManagementAccountsListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementAccountsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["max-results"]; ok {
		params.Set("max-results", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["start-index"]; ok {
		params.Set("start-index", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts")
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

// Do executes the "analytics.management.accounts.list" call.
func (c *ManagementAccountsListCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Lists all accounts to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.accounts.list",
	//   "parameters": {
	//     "max-results": {
	//       "description": "The maximum number of accounts to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "start-index": {
	//       "description": "An index of the first account to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     }
	//   },
	//   "path": "management/accounts",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.goals.list":

type ManagementGoalsListCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: Lists goals to which the user has access.
func (r *ManagementGoalsService) List(accountId string, webPropertyId string, profileId string) *ManagementGoalsListCall {
	c := &ManagementGoalsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of goals to include in this response.
func (c *ManagementGoalsListCall) MaxResults(maxResults int64) *ManagementGoalsListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first goal to retrieve. Use this parameter as a pagination mechanism
// along with the max-results parameter.
func (c *ManagementGoalsListCall) StartIndex(startIndex int64) *ManagementGoalsListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementGoalsListCall) Fields(s ...googleapi.Field) *ManagementGoalsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementGoalsListCall) IfNoneMatch(entityTag string) *ManagementGoalsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementGoalsListCall) Context(ctx context.Context) *ManagementGoalsListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementGoalsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["max-results"]; ok {
		params.Set("max-results", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["start-index"]; ok {
		params.Set("start-index", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
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

// Do executes the "analytics.management.goals.list" call.
func (c *ManagementGoalsListCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Lists goals to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.goals.list",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve goals for. Can either be a specific account ID or '~all', which refers to all the accounts that user has access to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of goals to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to retrieve goals for. Can either be a specific view (profile) ID or '~all', which refers to all the views (profiles) that user has access to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "start-index": {
	//       "description": "An index of the first goal to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to retrieve goals for. Can either be a specific web property ID or '~all', which refers to all the web properties that user has access to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.profiles.list":

type ManagementProfilesListCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: Lists views (profiles) to which the user has access.
func (r *ManagementProfilesService) List(accountId string, webPropertyId string) *ManagementProfilesListCall {
	c := &ManagementProfilesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of views (profiles) to include in this response.
func (c *ManagementProfilesListCall) MaxResults(maxResults int64) *ManagementProfilesListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first entity to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
func (c *ManagementProfilesListCall) StartIndex(startIndex int64) *ManagementProfilesListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfilesListCall) Fields(s ...googleapi.Field) *ManagementProfilesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementProfilesListCall) IfNoneMatch(entityTag string) *ManagementProfilesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfilesListCall) Context(ctx context.Context) *ManagementProfilesListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfilesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["max-results"]; ok {
		params.Set("max-results", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["start-index"]; ok {
		params.Set("start-index", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
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

// Do executes the "analytics.management.profiles.list" call.
func (c *ManagementProfilesListCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Lists views (profiles) to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.profiles.list",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID for the views (profiles) to retrieve. Can either be a specific account ID or '~all', which refers to all the accounts to which the user has access.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of views (profiles) to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "start-index": {
	//       "description": "An index of the first entity to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID for the views (profiles) to retrieve. Can either be a specific web property ID or '~all', which refers to all the web properties to which the user has access.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.segments.list":

type ManagementSegmentsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Lists advanced segments to which the user has access.
func (r *ManagementSegmentsService) List() *ManagementSegmentsListCall {
	c := &ManagementSegmentsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of advanced segments to include in this response.
func (c *ManagementSegmentsListCall) MaxResults(maxResults int64) *ManagementSegmentsListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first advanced segment to retrieve. Use this parameter as a
// pagination mechanism along with the max-results parameter.
func (c *ManagementSegmentsListCall) StartIndex(startIndex int64) *ManagementSegmentsListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementSegmentsListCall) Fields(s ...googleapi.Field) *ManagementSegmentsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementSegmentsListCall) IfNoneMatch(entityTag string) *ManagementSegmentsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementSegmentsListCall) Context(ctx context.Context) *ManagementSegmentsListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementSegmentsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["max-results"]; ok {
		params.Set("max-results", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["start-index"]; ok {
		params.Set("start-index", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/segments")
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

// Do executes the "analytics.management.segments.list" call.
func (c *ManagementSegmentsListCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Lists advanced segments to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.segments.list",
	//   "parameters": {
	//     "max-results": {
	//       "description": "The maximum number of advanced segments to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "start-index": {
	//       "description": "An index of the first advanced segment to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     }
	//   },
	//   "path": "management/segments",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.webproperties.list":

type ManagementWebpropertiesListCall struct {
	s         *Service
	accountId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// List: Lists web properties to which the user has access.
func (r *ManagementWebpropertiesService) List(accountId string) *ManagementWebpropertiesListCall {
	c := &ManagementWebpropertiesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of web properties to include in this response.
func (c *ManagementWebpropertiesListCall) MaxResults(maxResults int64) *ManagementWebpropertiesListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first entity to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
func (c *ManagementWebpropertiesListCall) StartIndex(startIndex int64) *ManagementWebpropertiesListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebpropertiesListCall) Fields(s ...googleapi.Field) *ManagementWebpropertiesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementWebpropertiesListCall) IfNoneMatch(entityTag string) *ManagementWebpropertiesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebpropertiesListCall) Context(ctx context.Context) *ManagementWebpropertiesListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebpropertiesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["max-results"]; ok {
		params.Set("max-results", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["start-index"]; ok {
		params.Set("start-index", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId": c.accountId,
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

// Do executes the "analytics.management.webproperties.list" call.
func (c *ManagementWebpropertiesListCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Lists web properties to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.webproperties.list",
	//   "parameterOrder": [
	//     "accountId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve web properties for. Can either be a specific account ID or '~all', which refers to all the accounts that user has access to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of web properties to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "start-index": {
	//       "description": "An index of the first entity to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}
