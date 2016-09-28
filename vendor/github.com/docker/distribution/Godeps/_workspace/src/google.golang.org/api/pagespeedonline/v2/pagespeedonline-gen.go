// Package pagespeedonline provides access to the PageSpeed Insights API.
//
// See https://developers.google.com/speed/docs/insights/v2/getting-started
//
// Usage example:
//
//   import "google.golang.org/api/pagespeedonline/v2"
//   ...
//   pagespeedonlineService, err := pagespeedonline.New(oauthHttpClient)
package pagespeedonline // import "google.golang.org/api/pagespeedonline/v2"

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

const apiId = "pagespeedonline:v2"
const apiName = "pagespeedonline"
const apiVersion = "v2"
const basePath = "https://www.googleapis.com/pagespeedonline/v2/"

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.Pagespeedapi = NewPagespeedapiService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	Pagespeedapi *PagespeedapiService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewPagespeedapiService(s *Service) *PagespeedapiService {
	rs := &PagespeedapiService{s: s}
	return rs
}

type PagespeedapiService struct {
	s *Service
}

type PagespeedApiFormatStringV2 struct {
	// Args: List of arguments for the format string.
	Args []*PagespeedApiFormatStringV2Args `json:"args,omitempty"`

	// Format: A localized format string with {{FOO}} placeholders, where
	// 'FOO' is the key of the argument whose value should be substituted.
	// For HYPERLINK arguments, the format string will instead contain
	// {{BEGIN_FOO}} and {{END_FOO}} for the argument with key 'FOO'.
	Format string `json:"format,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Args") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PagespeedApiFormatStringV2) MarshalJSON() ([]byte, error) {
	type noMethod PagespeedApiFormatStringV2
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PagespeedApiFormatStringV2Args struct {
	// Key: The placeholder key for this arg, as a string.
	Key string `json:"key,omitempty"`

	// Rects: The screen rectangles being referred to, with dimensions
	// measured in CSS pixels. This is only ever used for SNAPSHOT_RECT
	// arguments. If this is absent for a SNAPSHOT_RECT argument, it means
	// that that argument refers to the entire snapshot.
	Rects []*PagespeedApiFormatStringV2ArgsRects `json:"rects,omitempty"`

	// SecondaryRects: Secondary screen rectangles being referred to, with
	// dimensions measured in CSS pixels. This is only ever used for
	// SNAPSHOT_RECT arguments.
	SecondaryRects []*PagespeedApiFormatStringV2ArgsSecondaryRects `json:"secondary_rects,omitempty"`

	// Type: Type of argument. One of URL, STRING_LITERAL, INT_LITERAL,
	// BYTES, DURATION, VERBATIM_STRING, PERCENTAGE, HYPERLINK, or
	// SNAPSHOT_RECT.
	Type string `json:"type,omitempty"`

	// Value: Argument value, as a localized string.
	Value string `json:"value,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Key") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PagespeedApiFormatStringV2Args) MarshalJSON() ([]byte, error) {
	type noMethod PagespeedApiFormatStringV2Args
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PagespeedApiFormatStringV2ArgsRects struct {
	// Height: The height of the rect.
	Height int64 `json:"height,omitempty"`

	// Left: The left coordinate of the rect, in page coordinates.
	Left int64 `json:"left,omitempty"`

	// Top: The top coordinate of the rect, in page coordinates.
	Top int64 `json:"top,omitempty"`

	// Width: The width of the rect.
	Width int64 `json:"width,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Height") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PagespeedApiFormatStringV2ArgsRects) MarshalJSON() ([]byte, error) {
	type noMethod PagespeedApiFormatStringV2ArgsRects
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PagespeedApiFormatStringV2ArgsSecondaryRects struct {
	// Height: The height of the rect.
	Height int64 `json:"height,omitempty"`

	// Left: The left coordinate of the rect, in page coordinates.
	Left int64 `json:"left,omitempty"`

	// Top: The top coordinate of the rect, in page coordinates.
	Top int64 `json:"top,omitempty"`

	// Width: The width of the rect.
	Width int64 `json:"width,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Height") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PagespeedApiFormatStringV2ArgsSecondaryRects) MarshalJSON() ([]byte, error) {
	type noMethod PagespeedApiFormatStringV2ArgsSecondaryRects
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PagespeedApiImageV2 struct {
	// Data: Image data base64 encoded.
	Data string `json:"data,omitempty"`

	// Height: Height of screenshot in pixels.
	Height int64 `json:"height,omitempty"`

	// Key: Unique string key, if any, identifying this image.
	Key string `json:"key,omitempty"`

	// MimeType: Mime type of image data (e.g. "image/jpeg").
	MimeType string `json:"mime_type,omitempty"`

	// PageRect: The region of the page that is captured by this image, with
	// dimensions measured in CSS pixels.
	PageRect *PagespeedApiImageV2PageRect `json:"page_rect,omitempty"`

	// Width: Width of screenshot in pixels.
	Width int64 `json:"width,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Data") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PagespeedApiImageV2) MarshalJSON() ([]byte, error) {
	type noMethod PagespeedApiImageV2
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PagespeedApiImageV2PageRect: The region of the page that is captured
// by this image, with dimensions measured in CSS pixels.
type PagespeedApiImageV2PageRect struct {
	// Height: The height of the rect.
	Height int64 `json:"height,omitempty"`

	// Left: The left coordinate of the rect, in page coordinates.
	Left int64 `json:"left,omitempty"`

	// Top: The top coordinate of the rect, in page coordinates.
	Top int64 `json:"top,omitempty"`

	// Width: The width of the rect.
	Width int64 `json:"width,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Height") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PagespeedApiImageV2PageRect) MarshalJSON() ([]byte, error) {
	type noMethod PagespeedApiImageV2PageRect
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type Result struct {
	// FormattedResults: Localized PageSpeed results. Contains a ruleResults
	// entry for each PageSpeed rule instantiated and run by the server.
	FormattedResults *ResultFormattedResults `json:"formattedResults,omitempty"`

	// Id: Canonicalized and final URL for the document, after following
	// page redirects (if any).
	Id string `json:"id,omitempty"`

	// InvalidRules: List of rules that were specified in the request, but
	// which the server did not know how to instantiate.
	InvalidRules []string `json:"invalidRules,omitempty"`

	// Kind: Kind of result.
	Kind string `json:"kind,omitempty"`

	// PageStats: Summary statistics for the page, such as number of
	// JavaScript bytes, number of HTML bytes, etc.
	PageStats *ResultPageStats `json:"pageStats,omitempty"`

	// ResponseCode: Response code for the document. 200 indicates a normal
	// page load. 4xx/5xx indicates an error.
	ResponseCode int64 `json:"responseCode,omitempty"`

	// RuleGroups: A map with one entry for each rule group in these
	// results.
	RuleGroups *ResultRuleGroups `json:"ruleGroups,omitempty"`

	// Screenshot: Base64-encoded screenshot of the page that was analyzed.
	Screenshot *PagespeedApiImageV2 `json:"screenshot,omitempty"`

	// Title: Title of the page, as displayed in the browser's title bar.
	Title string `json:"title,omitempty"`

	// Version: The version of PageSpeed used to generate these results.
	Version *ResultVersion `json:"version,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "FormattedResults") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Result) MarshalJSON() ([]byte, error) {
	type noMethod Result
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ResultFormattedResults: Localized PageSpeed results. Contains a
// ruleResults entry for each PageSpeed rule instantiated and run by the
// server.
type ResultFormattedResults struct {
	// Locale: The locale of the formattedResults, e.g. "en_US".
	Locale string `json:"locale,omitempty"`

	// RuleResults: Dictionary of formatted rule results, with one entry for
	// each PageSpeed rule instantiated and run by the server.
	RuleResults *ResultFormattedResultsRuleResults `json:"ruleResults,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Locale") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ResultFormattedResults) MarshalJSON() ([]byte, error) {
	type noMethod ResultFormattedResults
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ResultFormattedResultsRuleResults: Dictionary of formatted rule
// results, with one entry for each PageSpeed rule instantiated and run
// by the server.
type ResultFormattedResultsRuleResults struct {
}

// ResultPageStats: Summary statistics for the page, such as number of
// JavaScript bytes, number of HTML bytes, etc.
type ResultPageStats struct {
	// CssResponseBytes: Number of uncompressed response bytes for CSS
	// resources on the page.
	CssResponseBytes int64 `json:"cssResponseBytes,omitempty,string"`

	// FlashResponseBytes: Number of response bytes for flash resources on
	// the page.
	FlashResponseBytes int64 `json:"flashResponseBytes,omitempty,string"`

	// HtmlResponseBytes: Number of uncompressed response bytes for the main
	// HTML document and all iframes on the page.
	HtmlResponseBytes int64 `json:"htmlResponseBytes,omitempty,string"`

	// ImageResponseBytes: Number of response bytes for image resources on
	// the page.
	ImageResponseBytes int64 `json:"imageResponseBytes,omitempty,string"`

	// JavascriptResponseBytes: Number of uncompressed response bytes for JS
	// resources on the page.
	JavascriptResponseBytes int64 `json:"javascriptResponseBytes,omitempty,string"`

	// NumberCssResources: Number of CSS resources referenced by the page.
	NumberCssResources int64 `json:"numberCssResources,omitempty"`

	// NumberHosts: Number of unique hosts referenced by the page.
	NumberHosts int64 `json:"numberHosts,omitempty"`

	// NumberJsResources: Number of JavaScript resources referenced by the
	// page.
	NumberJsResources int64 `json:"numberJsResources,omitempty"`

	// NumberResources: Number of HTTP resources loaded by the page.
	NumberResources int64 `json:"numberResources,omitempty"`

	// NumberStaticResources: Number of static (i.e. cacheable) resources on
	// the page.
	NumberStaticResources int64 `json:"numberStaticResources,omitempty"`

	// OtherResponseBytes: Number of response bytes for other resources on
	// the page.
	OtherResponseBytes int64 `json:"otherResponseBytes,omitempty,string"`

	// TextResponseBytes: Number of uncompressed response bytes for text
	// resources not covered by other statistics (i.e non-HTML, non-script,
	// non-CSS resources) on the page.
	TextResponseBytes int64 `json:"textResponseBytes,omitempty,string"`

	// TotalRequestBytes: Total size of all request bytes sent by the page.
	TotalRequestBytes int64 `json:"totalRequestBytes,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "CssResponseBytes") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ResultPageStats) MarshalJSON() ([]byte, error) {
	type noMethod ResultPageStats
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ResultRuleGroups: A map with one entry for each rule group in these
// results.
type ResultRuleGroups struct {
}

// ResultVersion: The version of PageSpeed used to generate these
// results.
type ResultVersion struct {
	// Major: The major version number of PageSpeed used to generate these
	// results.
	Major int64 `json:"major,omitempty"`

	// Minor: The minor version number of PageSpeed used to generate these
	// results.
	Minor int64 `json:"minor,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Major") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ResultVersion) MarshalJSON() ([]byte, error) {
	type noMethod ResultVersion
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "pagespeedonline.pagespeedapi.runpagespeed":

type PagespeedapiRunpagespeedCall struct {
	s    *Service
	url  string
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Runpagespeed: Runs PageSpeed analysis on the page at the specified
// URL, and returns PageSpeed scores, a list of suggestions to make that
// page faster, and other information.
func (r *PagespeedapiService) Runpagespeed(url string) *PagespeedapiRunpagespeedCall {
	c := &PagespeedapiRunpagespeedCall{s: r.s, opt_: make(map[string]interface{})}
	c.url = url
	return c
}

// FilterThirdPartyResources sets the optional parameter
// "filter_third_party_resources": Indicates if third party resources
// should be filtered out before PageSpeed analysis.
func (c *PagespeedapiRunpagespeedCall) FilterThirdPartyResources(filterThirdPartyResources bool) *PagespeedapiRunpagespeedCall {
	c.opt_["filter_third_party_resources"] = filterThirdPartyResources
	return c
}

// Locale sets the optional parameter "locale": The locale used to
// localize formatted results
func (c *PagespeedapiRunpagespeedCall) Locale(locale string) *PagespeedapiRunpagespeedCall {
	c.opt_["locale"] = locale
	return c
}

// Rule sets the optional parameter "rule": A PageSpeed rule to run; if
// none are given, all rules are run
func (c *PagespeedapiRunpagespeedCall) Rule(rule string) *PagespeedapiRunpagespeedCall {
	c.opt_["rule"] = rule
	return c
}

// Screenshot sets the optional parameter "screenshot": Indicates if
// binary data containing a screenshot should be included
func (c *PagespeedapiRunpagespeedCall) Screenshot(screenshot bool) *PagespeedapiRunpagespeedCall {
	c.opt_["screenshot"] = screenshot
	return c
}

// Strategy sets the optional parameter "strategy": The analysis
// strategy to use
//
// Possible values:
//   "desktop" - Fetch and analyze the URL for desktop browsers
//   "mobile" - Fetch and analyze the URL for mobile devices
func (c *PagespeedapiRunpagespeedCall) Strategy(strategy string) *PagespeedapiRunpagespeedCall {
	c.opt_["strategy"] = strategy
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PagespeedapiRunpagespeedCall) Fields(s ...googleapi.Field) *PagespeedapiRunpagespeedCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PagespeedapiRunpagespeedCall) IfNoneMatch(entityTag string) *PagespeedapiRunpagespeedCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PagespeedapiRunpagespeedCall) Context(ctx context.Context) *PagespeedapiRunpagespeedCall {
	c.ctx_ = ctx
	return c
}

func (c *PagespeedapiRunpagespeedCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("url", fmt.Sprintf("%v", c.url))
	if v, ok := c.opt_["filter_third_party_resources"]; ok {
		params.Set("filter_third_party_resources", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["locale"]; ok {
		params.Set("locale", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["rule"]; ok {
		params.Set("rule", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["screenshot"]; ok {
		params.Set("screenshot", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["strategy"]; ok {
		params.Set("strategy", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "runPagespeed")
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

// Do executes the "pagespeedonline.pagespeedapi.runpagespeed" call.
// Exactly one of *Result or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Result.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *PagespeedapiRunpagespeedCall) Do() (*Result, error) {
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
	ret := &Result{
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
	//   "description": "Runs PageSpeed analysis on the page at the specified URL, and returns PageSpeed scores, a list of suggestions to make that page faster, and other information.",
	//   "httpMethod": "GET",
	//   "id": "pagespeedonline.pagespeedapi.runpagespeed",
	//   "parameterOrder": [
	//     "url"
	//   ],
	//   "parameters": {
	//     "filter_third_party_resources": {
	//       "default": "false",
	//       "description": "Indicates if third party resources should be filtered out before PageSpeed analysis.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "locale": {
	//       "description": "The locale used to localize formatted results",
	//       "location": "query",
	//       "pattern": "[a-zA-Z]+(_[a-zA-Z]+)?",
	//       "type": "string"
	//     },
	//     "rule": {
	//       "description": "A PageSpeed rule to run; if none are given, all rules are run",
	//       "location": "query",
	//       "pattern": "[a-zA-Z]+",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "screenshot": {
	//       "default": "false",
	//       "description": "Indicates if binary data containing a screenshot should be included",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "strategy": {
	//       "description": "The analysis strategy to use",
	//       "enum": [
	//         "desktop",
	//         "mobile"
	//       ],
	//       "enumDescriptions": [
	//         "Fetch and analyze the URL for desktop browsers",
	//         "Fetch and analyze the URL for mobile devices"
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "url": {
	//       "description": "The URL to fetch and analyze",
	//       "location": "query",
	//       "pattern": "http(s)?://.*",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "runPagespeed",
	//   "response": {
	//     "$ref": "Result"
	//   }
	// }

}
