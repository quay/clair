// Package webmasters provides access to the Webmaster Tools API.
//
// See https://developers.google.com/webmaster-tools/
//
// Usage example:
//
//   import "google.golang.org/api/webmasters/v3"
//   ...
//   webmastersService, err := webmasters.New(oauthHttpClient)
package webmasters // import "google.golang.org/api/webmasters/v3"

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

const apiId = "webmasters:v3"
const apiName = "webmasters"
const apiVersion = "v3"
const basePath = "https://www.googleapis.com/webmasters/v3/"

// OAuth2 scopes used by this API.
const (
	// View and modify Webmaster Tools data for your verified sites
	WebmastersScope = "https://www.googleapis.com/auth/webmasters"

	// View Webmaster Tools data for your verified sites
	WebmastersReadonlyScope = "https://www.googleapis.com/auth/webmasters.readonly"
)

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.Searchanalytics = NewSearchanalyticsService(s)
	s.Sitemaps = NewSitemapsService(s)
	s.Sites = NewSitesService(s)
	s.Urlcrawlerrorscounts = NewUrlcrawlerrorscountsService(s)
	s.Urlcrawlerrorssamples = NewUrlcrawlerrorssamplesService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	Searchanalytics *SearchanalyticsService

	Sitemaps *SitemapsService

	Sites *SitesService

	Urlcrawlerrorscounts *UrlcrawlerrorscountsService

	Urlcrawlerrorssamples *UrlcrawlerrorssamplesService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewSearchanalyticsService(s *Service) *SearchanalyticsService {
	rs := &SearchanalyticsService{s: s}
	return rs
}

type SearchanalyticsService struct {
	s *Service
}

func NewSitemapsService(s *Service) *SitemapsService {
	rs := &SitemapsService{s: s}
	return rs
}

type SitemapsService struct {
	s *Service
}

func NewSitesService(s *Service) *SitesService {
	rs := &SitesService{s: s}
	return rs
}

type SitesService struct {
	s *Service
}

func NewUrlcrawlerrorscountsService(s *Service) *UrlcrawlerrorscountsService {
	rs := &UrlcrawlerrorscountsService{s: s}
	return rs
}

type UrlcrawlerrorscountsService struct {
	s *Service
}

func NewUrlcrawlerrorssamplesService(s *Service) *UrlcrawlerrorssamplesService {
	rs := &UrlcrawlerrorssamplesService{s: s}
	return rs
}

type UrlcrawlerrorssamplesService struct {
	s *Service
}

type ApiDataRow struct {
	Clicks float64 `json:"clicks,omitempty"`

	Ctr float64 `json:"ctr,omitempty"`

	Impressions float64 `json:"impressions,omitempty"`

	Keys []string `json:"keys,omitempty"`

	Position float64 `json:"position,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Clicks") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ApiDataRow) MarshalJSON() ([]byte, error) {
	type noMethod ApiDataRow
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ApiDimensionFilter struct {
	Dimension string `json:"dimension,omitempty"`

	Expression string `json:"expression,omitempty"`

	Operator string `json:"operator,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Dimension") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ApiDimensionFilter) MarshalJSON() ([]byte, error) {
	type noMethod ApiDimensionFilter
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ApiDimensionFilterGroup struct {
	Filters []*ApiDimensionFilter `json:"filters,omitempty"`

	GroupType string `json:"groupType,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Filters") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ApiDimensionFilterGroup) MarshalJSON() ([]byte, error) {
	type noMethod ApiDimensionFilterGroup
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type SearchAnalyticsQueryRequest struct {
	// AggregationType: [Optional; Default is "auto"] How data is
	// aggregated. If aggregated by property, all data for the same property
	// is aggregated; if aggregated by page, all data is aggregated by
	// canonical URI. If you filter or group by page, choose AUTO; otherwise
	// you can aggregate either by property or by page, depending on how you
	// want your data calculated; see  the help documentation to learn how
	// data is calculated differently by site versus by page.
	//
	// Note: If you group or filter by page, you cannot aggregate by
	// property.
	//
	// If you specify any value other than AUTO, the aggregation type in the
	// result will match the requested type, or if you request an invalid
	// type, you will get an error. The API will never change your
	// aggregation type if the requested type is invalid.
	AggregationType string `json:"aggregationType,omitempty"`

	// DimensionFilterGroups: [Optional] Zero or more filters to apply to
	// the dimension grouping values; for example, 'query contains "buy"' to
	// see only data where the query string contains the substring "buy"
	// (not case-sensitive). You can filter by a dimension without grouping
	// by it.
	DimensionFilterGroups []*ApiDimensionFilterGroup `json:"dimensionFilterGroups,omitempty"`

	// Dimensions: [Optional] Zero or more dimensions to group results by.
	// Dimensions are the group-by values in the Search Analytics page.
	// Dimensions are combined to create a unique row key for each row.
	// Results are grouped in the order that you supply these dimensions.
	Dimensions []string `json:"dimensions,omitempty"`

	// EndDate: [Required] End date of the requested date range, in
	// YYYY-MM-DD format, in PST (UTC - 8:00). Must be greater than or equal
	// to the start date. This value is included in the range.
	EndDate string `json:"endDate,omitempty"`

	// RowLimit: [Optional; Default is 1000] The maximum number of rows to
	// return. Must be a number from 1 to 5,000 (inclusive).
	RowLimit int64 `json:"rowLimit,omitempty"`

	// SearchType: [Optional; Default is "web"] The search type to filter
	// for.
	SearchType string `json:"searchType,omitempty"`

	// StartDate: [Required] Start date of the requested date range, in
	// YYYY-MM-DD format, in PST time (UTC - 8:00). Must be less than or
	// equal to the end date. This value is included in the range.
	StartDate string `json:"startDate,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AggregationType") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchAnalyticsQueryRequest) MarshalJSON() ([]byte, error) {
	type noMethod SearchAnalyticsQueryRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchAnalyticsQueryResponse: A list of rows, one per result, grouped
// by key. Metrics in each row are aggregated for all data grouped by
// that key either by page or property, as specified by the aggregation
// type parameter.
type SearchAnalyticsQueryResponse struct {
	// ResponseAggregationType: How the results were aggregated.
	ResponseAggregationType string `json:"responseAggregationType,omitempty"`

	// Rows: A list of rows grouped by the key values in the order given in
	// the query.
	Rows []*ApiDataRow `json:"rows,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g.
	// "ResponseAggregationType") to unconditionally include in API
	// requests. By default, fields with empty values are omitted from API
	// requests. However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchAnalyticsQueryResponse) MarshalJSON() ([]byte, error) {
	type noMethod SearchAnalyticsQueryResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SitemapsListResponse: List of sitemaps.
type SitemapsListResponse struct {
	// Sitemap: Contains detailed information about a specific URL submitted
	// as a sitemap.
	Sitemap []*WmxSitemap `json:"sitemap,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Sitemap") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SitemapsListResponse) MarshalJSON() ([]byte, error) {
	type noMethod SitemapsListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SitesListResponse: List of sites with access level information.
type SitesListResponse struct {
	// SiteEntry: Contains permission level information about a Webmaster
	// Tools site. For more information, see Permissions in Webmaster Tools.
	SiteEntry []*WmxSite `json:"siteEntry,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "SiteEntry") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SitesListResponse) MarshalJSON() ([]byte, error) {
	type noMethod SitesListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// UrlCrawlErrorCount: An entry in a URL crawl errors time series.
type UrlCrawlErrorCount struct {
	// Count: The error count at the given timestamp.
	Count int64 `json:"count,omitempty,string"`

	// Timestamp: The date and time when the crawl attempt took place, in
	// RFC 3339 format.
	Timestamp string `json:"timestamp,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Count") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *UrlCrawlErrorCount) MarshalJSON() ([]byte, error) {
	type noMethod UrlCrawlErrorCount
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// UrlCrawlErrorCountsPerType: Number of errors per day for a specific
// error type (defined by platform and category).
type UrlCrawlErrorCountsPerType struct {
	// Category: The crawl error type.
	Category string `json:"category,omitempty"`

	// Entries: The error count entries time series.
	Entries []*UrlCrawlErrorCount `json:"entries,omitempty"`

	// Platform: The general type of Googlebot that made the request (see
	// list of Googlebot user-agents for the user-agents used).
	Platform string `json:"platform,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Category") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *UrlCrawlErrorCountsPerType) MarshalJSON() ([]byte, error) {
	type noMethod UrlCrawlErrorCountsPerType
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// UrlCrawlErrorsCountsQueryResponse: A time series of the number of URL
// crawl errors per error category and platform.
type UrlCrawlErrorsCountsQueryResponse struct {
	// CountPerTypes: The time series of the number of URL crawl errors per
	// error category and platform.
	CountPerTypes []*UrlCrawlErrorCountsPerType `json:"countPerTypes,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "CountPerTypes") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *UrlCrawlErrorsCountsQueryResponse) MarshalJSON() ([]byte, error) {
	type noMethod UrlCrawlErrorsCountsQueryResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// UrlCrawlErrorsSample: Contains information about specific crawl
// errors.
type UrlCrawlErrorsSample struct {
	// FirstDetected: The time the error was first detected, in RFC 3339
	// format.
	FirstDetected string `json:"first_detected,omitempty"`

	// LastCrawled: The time when the URL was last crawled, in RFC 3339
	// format.
	LastCrawled string `json:"last_crawled,omitempty"`

	// PageUrl: The URL of an error, relative to the site.
	PageUrl string `json:"pageUrl,omitempty"`

	// ResponseCode: The HTTP response code, if any.
	ResponseCode int64 `json:"responseCode,omitempty"`

	// UrlDetails: Additional details about the URL, set only when calling
	// get().
	UrlDetails *UrlSampleDetails `json:"urlDetails,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "FirstDetected") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *UrlCrawlErrorsSample) MarshalJSON() ([]byte, error) {
	type noMethod UrlCrawlErrorsSample
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// UrlCrawlErrorsSamplesListResponse: List of crawl error samples.
type UrlCrawlErrorsSamplesListResponse struct {
	// UrlCrawlErrorSample: Information about the sample URL and its crawl
	// error.
	UrlCrawlErrorSample []*UrlCrawlErrorsSample `json:"urlCrawlErrorSample,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "UrlCrawlErrorSample")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *UrlCrawlErrorsSamplesListResponse) MarshalJSON() ([]byte, error) {
	type noMethod UrlCrawlErrorsSamplesListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// UrlSampleDetails: Additional details about the URL, set only when
// calling get().
type UrlSampleDetails struct {
	// ContainingSitemaps: List of sitemaps pointing at this URL.
	ContainingSitemaps []string `json:"containingSitemaps,omitempty"`

	// LinkedFromUrls: A sample set of URLs linking to this URL.
	LinkedFromUrls []string `json:"linkedFromUrls,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ContainingSitemaps")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *UrlSampleDetails) MarshalJSON() ([]byte, error) {
	type noMethod UrlSampleDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// WmxSite: Contains permission level information about a Webmaster
// Tools site. For more information, see  Permissions in Webmaster
// Tools.
type WmxSite struct {
	// PermissionLevel: The user's permission level for the site.
	PermissionLevel string `json:"permissionLevel,omitempty"`

	// SiteUrl: The URL of the site.
	SiteUrl string `json:"siteUrl,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "PermissionLevel") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *WmxSite) MarshalJSON() ([]byte, error) {
	type noMethod WmxSite
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// WmxSitemap: Contains detailed information about a specific URL
// submitted as a sitemap.
type WmxSitemap struct {
	// Contents: The various content types in the sitemap.
	Contents []*WmxSitemapContent `json:"contents,omitempty"`

	// Errors: Number of errors in the sitemap. These are issues with the
	// sitemap itself that need to be fixed before it can be processed
	// correctly.
	Errors int64 `json:"errors,omitempty,string"`

	// IsPending: If true, the sitemap has not been processed.
	IsPending bool `json:"isPending,omitempty"`

	// IsSitemapsIndex: If true, the sitemap is a collection of sitemaps.
	IsSitemapsIndex bool `json:"isSitemapsIndex,omitempty"`

	// LastDownloaded: Date & time in which this sitemap was last
	// downloaded. Date format is in RFC 3339 format (yyyy-mm-dd).
	LastDownloaded string `json:"lastDownloaded,omitempty"`

	// LastSubmitted: Date & time in which this sitemap was submitted. Date
	// format is in RFC 3339 format (yyyy-mm-dd).
	LastSubmitted string `json:"lastSubmitted,omitempty"`

	// Path: The url of the sitemap.
	Path string `json:"path,omitempty"`

	// Type: The type of the sitemap. For example: rssFeed.
	Type string `json:"type,omitempty"`

	// Warnings: Number of warnings for the sitemap. These are generally
	// non-critical issues with URLs in the sitemaps.
	Warnings int64 `json:"warnings,omitempty,string"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Contents") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *WmxSitemap) MarshalJSON() ([]byte, error) {
	type noMethod WmxSitemap
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// WmxSitemapContent: Information about the various content types in the
// sitemap.
type WmxSitemapContent struct {
	// Indexed: The number of URLs from the sitemap that were indexed (of
	// the content type).
	Indexed int64 `json:"indexed,omitempty,string"`

	// Submitted: The number of URLs in the sitemap (of the content type).
	Submitted int64 `json:"submitted,omitempty,string"`

	// Type: The specific type of content in this sitemap. For example: web.
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Indexed") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *WmxSitemapContent) MarshalJSON() ([]byte, error) {
	type noMethod WmxSitemapContent
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "webmasters.searchanalytics.query":

type SearchanalyticsQueryCall struct {
	s                           *Service
	siteUrl                     string
	searchanalyticsqueryrequest *SearchAnalyticsQueryRequest
	opt_                        map[string]interface{}
	ctx_                        context.Context
}

// Query: Query your data with filters and parameters that you define.
// Returns zero or more rows grouped by the row keys that you define.
// You must define a date range of one or more days.
//
// When date is one of the group by values, any days without data are
// omitted from the result list. If you need to know which days have
// data, issue a broad date range query grouped by date for any metric,
// and see which day rows are returned.
func (r *SearchanalyticsService) Query(siteUrl string, searchanalyticsqueryrequest *SearchAnalyticsQueryRequest) *SearchanalyticsQueryCall {
	c := &SearchanalyticsQueryCall{s: r.s, opt_: make(map[string]interface{})}
	c.siteUrl = siteUrl
	c.searchanalyticsqueryrequest = searchanalyticsqueryrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SearchanalyticsQueryCall) Fields(s ...googleapi.Field) *SearchanalyticsQueryCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SearchanalyticsQueryCall) Context(ctx context.Context) *SearchanalyticsQueryCall {
	c.ctx_ = ctx
	return c
}

func (c *SearchanalyticsQueryCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.searchanalyticsqueryrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "sites/{siteUrl}/searchAnalytics/query")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"siteUrl": c.siteUrl,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "webmasters.searchanalytics.query" call.
// Exactly one of *SearchAnalyticsQueryResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *SearchAnalyticsQueryResponse.ServerResponse.Header or (if a
// response was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *SearchanalyticsQueryCall) Do() (*SearchAnalyticsQueryResponse, error) {
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
	ret := &SearchAnalyticsQueryResponse{
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
	//   "description": "Query your data with filters and parameters that you define. Returns zero or more rows grouped by the row keys that you define. You must define a date range of one or more days.\n\nWhen date is one of the group by values, any days without data are omitted from the result list. If you need to know which days have data, issue a broad date range query grouped by date for any metric, and see which day rows are returned.",
	//   "httpMethod": "POST",
	//   "id": "webmasters.searchanalytics.query",
	//   "parameterOrder": [
	//     "siteUrl"
	//   ],
	//   "parameters": {
	//     "siteUrl": {
	//       "description": "The site's URL, including protocol. For example: http://www.example.com/",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "sites/{siteUrl}/searchAnalytics/query",
	//   "request": {
	//     "$ref": "SearchAnalyticsQueryRequest"
	//   },
	//   "response": {
	//     "$ref": "SearchAnalyticsQueryResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/webmasters",
	//     "https://www.googleapis.com/auth/webmasters.readonly"
	//   ]
	// }

}

// method id "webmasters.sitemaps.delete":

type SitemapsDeleteCall struct {
	s        *Service
	siteUrl  string
	feedpath string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Delete: Deletes a sitemap from this site.
func (r *SitemapsService) Delete(siteUrl string, feedpath string) *SitemapsDeleteCall {
	c := &SitemapsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.siteUrl = siteUrl
	c.feedpath = feedpath
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SitemapsDeleteCall) Fields(s ...googleapi.Field) *SitemapsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SitemapsDeleteCall) Context(ctx context.Context) *SitemapsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *SitemapsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "sites/{siteUrl}/sitemaps/{feedpath}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"siteUrl":  c.siteUrl,
		"feedpath": c.feedpath,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "webmasters.sitemaps.delete" call.
func (c *SitemapsDeleteCall) Do() error {
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
	//   "description": "Deletes a sitemap from this site.",
	//   "httpMethod": "DELETE",
	//   "id": "webmasters.sitemaps.delete",
	//   "parameterOrder": [
	//     "siteUrl",
	//     "feedpath"
	//   ],
	//   "parameters": {
	//     "feedpath": {
	//       "description": "The URL of the actual sitemap. For example: http://www.example.com/sitemap.xml",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "siteUrl": {
	//       "description": "The site's URL, including protocol. For example: http://www.example.com/",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "sites/{siteUrl}/sitemaps/{feedpath}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/webmasters"
	//   ]
	// }

}

// method id "webmasters.sitemaps.get":

type SitemapsGetCall struct {
	s        *Service
	siteUrl  string
	feedpath string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Get: Retrieves information about a specific sitemap.
func (r *SitemapsService) Get(siteUrl string, feedpath string) *SitemapsGetCall {
	c := &SitemapsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.siteUrl = siteUrl
	c.feedpath = feedpath
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SitemapsGetCall) Fields(s ...googleapi.Field) *SitemapsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *SitemapsGetCall) IfNoneMatch(entityTag string) *SitemapsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SitemapsGetCall) Context(ctx context.Context) *SitemapsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *SitemapsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "sites/{siteUrl}/sitemaps/{feedpath}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"siteUrl":  c.siteUrl,
		"feedpath": c.feedpath,
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

// Do executes the "webmasters.sitemaps.get" call.
// Exactly one of *WmxSitemap or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *WmxSitemap.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *SitemapsGetCall) Do() (*WmxSitemap, error) {
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
	ret := &WmxSitemap{
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
	//   "description": "Retrieves information about a specific sitemap.",
	//   "httpMethod": "GET",
	//   "id": "webmasters.sitemaps.get",
	//   "parameterOrder": [
	//     "siteUrl",
	//     "feedpath"
	//   ],
	//   "parameters": {
	//     "feedpath": {
	//       "description": "The URL of the actual sitemap. For example: http://www.example.com/sitemap.xml",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "siteUrl": {
	//       "description": "The site's URL, including protocol. For example: http://www.example.com/",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "sites/{siteUrl}/sitemaps/{feedpath}",
	//   "response": {
	//     "$ref": "WmxSitemap"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/webmasters",
	//     "https://www.googleapis.com/auth/webmasters.readonly"
	//   ]
	// }

}

// method id "webmasters.sitemaps.list":

type SitemapsListCall struct {
	s       *Service
	siteUrl string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// List: Lists the sitemaps-entries submitted for this site, or included
// in the sitemap index file (if sitemapIndex is specified in the
// request).
func (r *SitemapsService) List(siteUrl string) *SitemapsListCall {
	c := &SitemapsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.siteUrl = siteUrl
	return c
}

// SitemapIndex sets the optional parameter "sitemapIndex": A URL of a
// site's sitemap index. For example:
// http://www.example.com/sitemapindex.xml
func (c *SitemapsListCall) SitemapIndex(sitemapIndex string) *SitemapsListCall {
	c.opt_["sitemapIndex"] = sitemapIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SitemapsListCall) Fields(s ...googleapi.Field) *SitemapsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *SitemapsListCall) IfNoneMatch(entityTag string) *SitemapsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SitemapsListCall) Context(ctx context.Context) *SitemapsListCall {
	c.ctx_ = ctx
	return c
}

func (c *SitemapsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["sitemapIndex"]; ok {
		params.Set("sitemapIndex", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "sites/{siteUrl}/sitemaps")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"siteUrl": c.siteUrl,
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

// Do executes the "webmasters.sitemaps.list" call.
// Exactly one of *SitemapsListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *SitemapsListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *SitemapsListCall) Do() (*SitemapsListResponse, error) {
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
	ret := &SitemapsListResponse{
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
	//   "description": "Lists the sitemaps-entries submitted for this site, or included in the sitemap index file (if sitemapIndex is specified in the request).",
	//   "httpMethod": "GET",
	//   "id": "webmasters.sitemaps.list",
	//   "parameterOrder": [
	//     "siteUrl"
	//   ],
	//   "parameters": {
	//     "siteUrl": {
	//       "description": "The site's URL, including protocol. For example: http://www.example.com/",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "sitemapIndex": {
	//       "description": "A URL of a site's sitemap index. For example: http://www.example.com/sitemapindex.xml",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "sites/{siteUrl}/sitemaps",
	//   "response": {
	//     "$ref": "SitemapsListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/webmasters",
	//     "https://www.googleapis.com/auth/webmasters.readonly"
	//   ]
	// }

}

// method id "webmasters.sitemaps.submit":

type SitemapsSubmitCall struct {
	s        *Service
	siteUrl  string
	feedpath string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Submit: Submits a sitemap for a site.
func (r *SitemapsService) Submit(siteUrl string, feedpath string) *SitemapsSubmitCall {
	c := &SitemapsSubmitCall{s: r.s, opt_: make(map[string]interface{})}
	c.siteUrl = siteUrl
	c.feedpath = feedpath
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SitemapsSubmitCall) Fields(s ...googleapi.Field) *SitemapsSubmitCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SitemapsSubmitCall) Context(ctx context.Context) *SitemapsSubmitCall {
	c.ctx_ = ctx
	return c
}

func (c *SitemapsSubmitCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "sites/{siteUrl}/sitemaps/{feedpath}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"siteUrl":  c.siteUrl,
		"feedpath": c.feedpath,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "webmasters.sitemaps.submit" call.
func (c *SitemapsSubmitCall) Do() error {
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
	//   "description": "Submits a sitemap for a site.",
	//   "httpMethod": "PUT",
	//   "id": "webmasters.sitemaps.submit",
	//   "parameterOrder": [
	//     "siteUrl",
	//     "feedpath"
	//   ],
	//   "parameters": {
	//     "feedpath": {
	//       "description": "The URL of the sitemap to add. For example: http://www.example.com/sitemap.xml",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "siteUrl": {
	//       "description": "The site's URL, including protocol. For example: http://www.example.com/",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "sites/{siteUrl}/sitemaps/{feedpath}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/webmasters"
	//   ]
	// }

}

// method id "webmasters.sites.add":

type SitesAddCall struct {
	s       *Service
	siteUrl string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Add: Adds a site to the set of the user's sites in Webmaster Tools.
func (r *SitesService) Add(siteUrl string) *SitesAddCall {
	c := &SitesAddCall{s: r.s, opt_: make(map[string]interface{})}
	c.siteUrl = siteUrl
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SitesAddCall) Fields(s ...googleapi.Field) *SitesAddCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SitesAddCall) Context(ctx context.Context) *SitesAddCall {
	c.ctx_ = ctx
	return c
}

func (c *SitesAddCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "sites/{siteUrl}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"siteUrl": c.siteUrl,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "webmasters.sites.add" call.
func (c *SitesAddCall) Do() error {
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
	//   "description": "Adds a site to the set of the user's sites in Webmaster Tools.",
	//   "httpMethod": "PUT",
	//   "id": "webmasters.sites.add",
	//   "parameterOrder": [
	//     "siteUrl"
	//   ],
	//   "parameters": {
	//     "siteUrl": {
	//       "description": "The URL of the site to add.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "sites/{siteUrl}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/webmasters"
	//   ]
	// }

}

// method id "webmasters.sites.delete":

type SitesDeleteCall struct {
	s       *Service
	siteUrl string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Delete: Removes a site from the set of the user's Webmaster Tools
// sites.
func (r *SitesService) Delete(siteUrl string) *SitesDeleteCall {
	c := &SitesDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.siteUrl = siteUrl
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SitesDeleteCall) Fields(s ...googleapi.Field) *SitesDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SitesDeleteCall) Context(ctx context.Context) *SitesDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *SitesDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "sites/{siteUrl}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"siteUrl": c.siteUrl,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "webmasters.sites.delete" call.
func (c *SitesDeleteCall) Do() error {
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
	//   "description": "Removes a site from the set of the user's Webmaster Tools sites.",
	//   "httpMethod": "DELETE",
	//   "id": "webmasters.sites.delete",
	//   "parameterOrder": [
	//     "siteUrl"
	//   ],
	//   "parameters": {
	//     "siteUrl": {
	//       "description": "The URI of the property as defined in Search Console. Examples: http://www.example.com/ or android-app://com.example/",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "sites/{siteUrl}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/webmasters"
	//   ]
	// }

}

// method id "webmasters.sites.get":

type SitesGetCall struct {
	s       *Service
	siteUrl string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Get: Retrieves information about specific site.
func (r *SitesService) Get(siteUrl string) *SitesGetCall {
	c := &SitesGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.siteUrl = siteUrl
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SitesGetCall) Fields(s ...googleapi.Field) *SitesGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *SitesGetCall) IfNoneMatch(entityTag string) *SitesGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SitesGetCall) Context(ctx context.Context) *SitesGetCall {
	c.ctx_ = ctx
	return c
}

func (c *SitesGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "sites/{siteUrl}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"siteUrl": c.siteUrl,
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

// Do executes the "webmasters.sites.get" call.
// Exactly one of *WmxSite or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *WmxSite.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *SitesGetCall) Do() (*WmxSite, error) {
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
	ret := &WmxSite{
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
	//   "description": "Retrieves information about specific site.",
	//   "httpMethod": "GET",
	//   "id": "webmasters.sites.get",
	//   "parameterOrder": [
	//     "siteUrl"
	//   ],
	//   "parameters": {
	//     "siteUrl": {
	//       "description": "The URI of the property as defined in Search Console. Examples: http://www.example.com/ or android-app://com.example/",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "sites/{siteUrl}",
	//   "response": {
	//     "$ref": "WmxSite"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/webmasters",
	//     "https://www.googleapis.com/auth/webmasters.readonly"
	//   ]
	// }

}

// method id "webmasters.sites.list":

type SitesListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Lists the user's Webmaster Tools sites.
func (r *SitesService) List() *SitesListCall {
	c := &SitesListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SitesListCall) Fields(s ...googleapi.Field) *SitesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *SitesListCall) IfNoneMatch(entityTag string) *SitesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SitesListCall) Context(ctx context.Context) *SitesListCall {
	c.ctx_ = ctx
	return c
}

func (c *SitesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "sites")
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

// Do executes the "webmasters.sites.list" call.
// Exactly one of *SitesListResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *SitesListResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *SitesListCall) Do() (*SitesListResponse, error) {
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
	ret := &SitesListResponse{
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
	//   "description": "Lists the user's Webmaster Tools sites.",
	//   "httpMethod": "GET",
	//   "id": "webmasters.sites.list",
	//   "path": "sites",
	//   "response": {
	//     "$ref": "SitesListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/webmasters",
	//     "https://www.googleapis.com/auth/webmasters.readonly"
	//   ]
	// }

}

// method id "webmasters.urlcrawlerrorscounts.query":

type UrlcrawlerrorscountsQueryCall struct {
	s       *Service
	siteUrl string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Query: Retrieves a time series of the number of URL crawl errors per
// error category and platform.
func (r *UrlcrawlerrorscountsService) Query(siteUrl string) *UrlcrawlerrorscountsQueryCall {
	c := &UrlcrawlerrorscountsQueryCall{s: r.s, opt_: make(map[string]interface{})}
	c.siteUrl = siteUrl
	return c
}

// Category sets the optional parameter "category": The crawl error
// category. For example: serverError. If not specified, returns results
// for all categories.
//
// Possible values:
//   "authPermissions"
//   "manyToOneRedirect"
//   "notFollowed"
//   "notFound"
//   "other"
//   "roboted"
//   "serverError"
//   "soft404"
func (c *UrlcrawlerrorscountsQueryCall) Category(category string) *UrlcrawlerrorscountsQueryCall {
	c.opt_["category"] = category
	return c
}

// LatestCountsOnly sets the optional parameter "latestCountsOnly": If
// true, returns only the latest crawl error counts.
func (c *UrlcrawlerrorscountsQueryCall) LatestCountsOnly(latestCountsOnly bool) *UrlcrawlerrorscountsQueryCall {
	c.opt_["latestCountsOnly"] = latestCountsOnly
	return c
}

// Platform sets the optional parameter "platform": The user agent type
// (platform) that made the request. For example: web. If not specified,
// returns results for all platforms.
//
// Possible values:
//   "mobile"
//   "smartphoneOnly"
//   "web"
func (c *UrlcrawlerrorscountsQueryCall) Platform(platform string) *UrlcrawlerrorscountsQueryCall {
	c.opt_["platform"] = platform
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *UrlcrawlerrorscountsQueryCall) Fields(s ...googleapi.Field) *UrlcrawlerrorscountsQueryCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *UrlcrawlerrorscountsQueryCall) IfNoneMatch(entityTag string) *UrlcrawlerrorscountsQueryCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *UrlcrawlerrorscountsQueryCall) Context(ctx context.Context) *UrlcrawlerrorscountsQueryCall {
	c.ctx_ = ctx
	return c
}

func (c *UrlcrawlerrorscountsQueryCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["category"]; ok {
		params.Set("category", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["latestCountsOnly"]; ok {
		params.Set("latestCountsOnly", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["platform"]; ok {
		params.Set("platform", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "sites/{siteUrl}/urlCrawlErrorsCounts/query")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"siteUrl": c.siteUrl,
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

// Do executes the "webmasters.urlcrawlerrorscounts.query" call.
// Exactly one of *UrlCrawlErrorsCountsQueryResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *UrlCrawlErrorsCountsQueryResponse.ServerResponse.Header or
// (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *UrlcrawlerrorscountsQueryCall) Do() (*UrlCrawlErrorsCountsQueryResponse, error) {
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
	ret := &UrlCrawlErrorsCountsQueryResponse{
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
	//   "description": "Retrieves a time series of the number of URL crawl errors per error category and platform.",
	//   "httpMethod": "GET",
	//   "id": "webmasters.urlcrawlerrorscounts.query",
	//   "parameterOrder": [
	//     "siteUrl"
	//   ],
	//   "parameters": {
	//     "category": {
	//       "description": "The crawl error category. For example: serverError. If not specified, returns results for all categories.",
	//       "enum": [
	//         "authPermissions",
	//         "manyToOneRedirect",
	//         "notFollowed",
	//         "notFound",
	//         "other",
	//         "roboted",
	//         "serverError",
	//         "soft404"
	//       ],
	//       "enumDescriptions": [
	//         "",
	//         "",
	//         "",
	//         "",
	//         "",
	//         "",
	//         "",
	//         ""
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "latestCountsOnly": {
	//       "default": "true",
	//       "description": "If true, returns only the latest crawl error counts.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "platform": {
	//       "description": "The user agent type (platform) that made the request. For example: web. If not specified, returns results for all platforms.",
	//       "enum": [
	//         "mobile",
	//         "smartphoneOnly",
	//         "web"
	//       ],
	//       "enumDescriptions": [
	//         "",
	//         "",
	//         ""
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "siteUrl": {
	//       "description": "The site's URL, including protocol. For example: http://www.example.com/",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "sites/{siteUrl}/urlCrawlErrorsCounts/query",
	//   "response": {
	//     "$ref": "UrlCrawlErrorsCountsQueryResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/webmasters",
	//     "https://www.googleapis.com/auth/webmasters.readonly"
	//   ]
	// }

}

// method id "webmasters.urlcrawlerrorssamples.get":

type UrlcrawlerrorssamplesGetCall struct {
	s        *Service
	siteUrl  string
	url      string
	category string
	platform string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Get: Retrieves details about crawl errors for a site's sample URL.
func (r *UrlcrawlerrorssamplesService) Get(siteUrl string, url string, category string, platform string) *UrlcrawlerrorssamplesGetCall {
	c := &UrlcrawlerrorssamplesGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.siteUrl = siteUrl
	c.url = url
	c.category = category
	c.platform = platform
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *UrlcrawlerrorssamplesGetCall) Fields(s ...googleapi.Field) *UrlcrawlerrorssamplesGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *UrlcrawlerrorssamplesGetCall) IfNoneMatch(entityTag string) *UrlcrawlerrorssamplesGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *UrlcrawlerrorssamplesGetCall) Context(ctx context.Context) *UrlcrawlerrorssamplesGetCall {
	c.ctx_ = ctx
	return c
}

func (c *UrlcrawlerrorssamplesGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("category", fmt.Sprintf("%v", c.category))
	params.Set("platform", fmt.Sprintf("%v", c.platform))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "sites/{siteUrl}/urlCrawlErrorsSamples/{url}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"siteUrl": c.siteUrl,
		"url":     c.url,
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

// Do executes the "webmasters.urlcrawlerrorssamples.get" call.
// Exactly one of *UrlCrawlErrorsSample or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *UrlCrawlErrorsSample.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *UrlcrawlerrorssamplesGetCall) Do() (*UrlCrawlErrorsSample, error) {
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
	ret := &UrlCrawlErrorsSample{
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
	//   "description": "Retrieves details about crawl errors for a site's sample URL.",
	//   "httpMethod": "GET",
	//   "id": "webmasters.urlcrawlerrorssamples.get",
	//   "parameterOrder": [
	//     "siteUrl",
	//     "url",
	//     "category",
	//     "platform"
	//   ],
	//   "parameters": {
	//     "category": {
	//       "description": "The crawl error category. For example: authPermissions",
	//       "enum": [
	//         "authPermissions",
	//         "manyToOneRedirect",
	//         "notFollowed",
	//         "notFound",
	//         "other",
	//         "roboted",
	//         "serverError",
	//         "soft404"
	//       ],
	//       "enumDescriptions": [
	//         "",
	//         "",
	//         "",
	//         "",
	//         "",
	//         "",
	//         "",
	//         ""
	//       ],
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "platform": {
	//       "description": "The user agent type (platform) that made the request. For example: web",
	//       "enum": [
	//         "mobile",
	//         "smartphoneOnly",
	//         "web"
	//       ],
	//       "enumDescriptions": [
	//         "",
	//         "",
	//         ""
	//       ],
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "siteUrl": {
	//       "description": "The site's URL, including protocol. For example: http://www.example.com/",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "url": {
	//       "description": "The relative path (without the site) of the sample URL. It must be one of the URLs returned by list(). For example, for the URL https://www.example.com/pagename on the site https://www.example.com/, the url value is pagename",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "sites/{siteUrl}/urlCrawlErrorsSamples/{url}",
	//   "response": {
	//     "$ref": "UrlCrawlErrorsSample"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/webmasters",
	//     "https://www.googleapis.com/auth/webmasters.readonly"
	//   ]
	// }

}

// method id "webmasters.urlcrawlerrorssamples.list":

type UrlcrawlerrorssamplesListCall struct {
	s        *Service
	siteUrl  string
	category string
	platform string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// List: Lists a site's sample URLs for the specified crawl error
// category and platform.
func (r *UrlcrawlerrorssamplesService) List(siteUrl string, category string, platform string) *UrlcrawlerrorssamplesListCall {
	c := &UrlcrawlerrorssamplesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.siteUrl = siteUrl
	c.category = category
	c.platform = platform
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *UrlcrawlerrorssamplesListCall) Fields(s ...googleapi.Field) *UrlcrawlerrorssamplesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *UrlcrawlerrorssamplesListCall) IfNoneMatch(entityTag string) *UrlcrawlerrorssamplesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *UrlcrawlerrorssamplesListCall) Context(ctx context.Context) *UrlcrawlerrorssamplesListCall {
	c.ctx_ = ctx
	return c
}

func (c *UrlcrawlerrorssamplesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("category", fmt.Sprintf("%v", c.category))
	params.Set("platform", fmt.Sprintf("%v", c.platform))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "sites/{siteUrl}/urlCrawlErrorsSamples")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"siteUrl": c.siteUrl,
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

// Do executes the "webmasters.urlcrawlerrorssamples.list" call.
// Exactly one of *UrlCrawlErrorsSamplesListResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *UrlCrawlErrorsSamplesListResponse.ServerResponse.Header or
// (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *UrlcrawlerrorssamplesListCall) Do() (*UrlCrawlErrorsSamplesListResponse, error) {
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
	ret := &UrlCrawlErrorsSamplesListResponse{
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
	//   "description": "Lists a site's sample URLs for the specified crawl error category and platform.",
	//   "httpMethod": "GET",
	//   "id": "webmasters.urlcrawlerrorssamples.list",
	//   "parameterOrder": [
	//     "siteUrl",
	//     "category",
	//     "platform"
	//   ],
	//   "parameters": {
	//     "category": {
	//       "description": "The crawl error category. For example: authPermissions",
	//       "enum": [
	//         "authPermissions",
	//         "manyToOneRedirect",
	//         "notFollowed",
	//         "notFound",
	//         "other",
	//         "roboted",
	//         "serverError",
	//         "soft404"
	//       ],
	//       "enumDescriptions": [
	//         "",
	//         "",
	//         "",
	//         "",
	//         "",
	//         "",
	//         "",
	//         ""
	//       ],
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "platform": {
	//       "description": "The user agent type (platform) that made the request. For example: web",
	//       "enum": [
	//         "mobile",
	//         "smartphoneOnly",
	//         "web"
	//       ],
	//       "enumDescriptions": [
	//         "",
	//         "",
	//         ""
	//       ],
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "siteUrl": {
	//       "description": "The site's URL, including protocol. For example: http://www.example.com/",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "sites/{siteUrl}/urlCrawlErrorsSamples",
	//   "response": {
	//     "$ref": "UrlCrawlErrorsSamplesListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/webmasters",
	//     "https://www.googleapis.com/auth/webmasters.readonly"
	//   ]
	// }

}

// method id "webmasters.urlcrawlerrorssamples.markAsFixed":

type UrlcrawlerrorssamplesMarkAsFixedCall struct {
	s        *Service
	siteUrl  string
	url      string
	category string
	platform string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// MarkAsFixed: Marks the provided site's sample URL as fixed, and
// removes it from the samples list.
func (r *UrlcrawlerrorssamplesService) MarkAsFixed(siteUrl string, url string, category string, platform string) *UrlcrawlerrorssamplesMarkAsFixedCall {
	c := &UrlcrawlerrorssamplesMarkAsFixedCall{s: r.s, opt_: make(map[string]interface{})}
	c.siteUrl = siteUrl
	c.url = url
	c.category = category
	c.platform = platform
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *UrlcrawlerrorssamplesMarkAsFixedCall) Fields(s ...googleapi.Field) *UrlcrawlerrorssamplesMarkAsFixedCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *UrlcrawlerrorssamplesMarkAsFixedCall) Context(ctx context.Context) *UrlcrawlerrorssamplesMarkAsFixedCall {
	c.ctx_ = ctx
	return c
}

func (c *UrlcrawlerrorssamplesMarkAsFixedCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("category", fmt.Sprintf("%v", c.category))
	params.Set("platform", fmt.Sprintf("%v", c.platform))
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "sites/{siteUrl}/urlCrawlErrorsSamples/{url}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"siteUrl": c.siteUrl,
		"url":     c.url,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "webmasters.urlcrawlerrorssamples.markAsFixed" call.
func (c *UrlcrawlerrorssamplesMarkAsFixedCall) Do() error {
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
	//   "description": "Marks the provided site's sample URL as fixed, and removes it from the samples list.",
	//   "httpMethod": "DELETE",
	//   "id": "webmasters.urlcrawlerrorssamples.markAsFixed",
	//   "parameterOrder": [
	//     "siteUrl",
	//     "url",
	//     "category",
	//     "platform"
	//   ],
	//   "parameters": {
	//     "category": {
	//       "description": "The crawl error category. For example: authPermissions",
	//       "enum": [
	//         "authPermissions",
	//         "manyToOneRedirect",
	//         "notFollowed",
	//         "notFound",
	//         "other",
	//         "roboted",
	//         "serverError",
	//         "soft404"
	//       ],
	//       "enumDescriptions": [
	//         "",
	//         "",
	//         "",
	//         "",
	//         "",
	//         "",
	//         "",
	//         ""
	//       ],
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "platform": {
	//       "description": "The user agent type (platform) that made the request. For example: web",
	//       "enum": [
	//         "mobile",
	//         "smartphoneOnly",
	//         "web"
	//       ],
	//       "enumDescriptions": [
	//         "",
	//         "",
	//         ""
	//       ],
	//       "location": "query",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "siteUrl": {
	//       "description": "The site's URL, including protocol. For example: http://www.example.com/",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "url": {
	//       "description": "The relative path (without the site) of the sample URL. It must be one of the URLs returned by list(). For example, for the URL https://www.example.com/pagename on the site https://www.example.com/, the url value is pagename",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "sites/{siteUrl}/urlCrawlErrorsSamples/{url}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/webmasters"
	//   ]
	// }

}
