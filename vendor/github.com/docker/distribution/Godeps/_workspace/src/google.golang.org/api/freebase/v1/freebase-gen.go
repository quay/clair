// Package freebase provides access to the Freebase Search.
//
// See https://developers.google.com/freebase/
//
// Usage example:
//
//   import "google.golang.org/api/freebase/v1"
//   ...
//   freebaseService, err := freebase.New(oauthHttpClient)
package freebase // import "google.golang.org/api/freebase/v1"

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

const apiId = "freebase:v1"
const apiName = "freebase"
const apiVersion = "v1"
const basePath = "https://www.googleapis.com/freebase/v1/"

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

type ReconcileCandidate struct {
	// Confidence: Percentage likelihood that this candidate is the unique
	// matching entity. Value will be between 0.0 and 1.0
	Confidence float64 `json:"confidence,omitempty"`

	// Lang: Language code that candidate and notable names are displayed
	// in.
	Lang string `json:"lang,omitempty"`

	// Mid: Freebase MID of candidate entity.
	Mid string `json:"mid,omitempty"`

	// Name: Freebase name of matching entity in specified language.
	Name string `json:"name,omitempty"`

	// Notable: Type or profession the candidate is notable for.
	Notable *ReconcileCandidateNotable `json:"notable,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Confidence") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ReconcileCandidate) MarshalJSON() ([]byte, error) {
	type noMethod ReconcileCandidate
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ReconcileCandidateNotable: Type or profession the candidate is
// notable for.
type ReconcileCandidateNotable struct {
	// Id: MID of notable category.
	Id string `json:"id,omitempty"`

	// Name: Name of notable category in specified language.
	Name string `json:"name,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ReconcileCandidateNotable) MarshalJSON() ([]byte, error) {
	type noMethod ReconcileCandidateNotable
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ReconcileGet struct {
	// Candidate: If filled, then the listed candidates are potential
	// matches, and such should be evaluated by a more discerning algorithm
	// or human. The matches are ordered by confidence.
	Candidate []*ReconcileCandidate `json:"candidate,omitempty"`

	// Costs: Server costs for reconciling.
	Costs *ReconcileGetCosts `json:"costs,omitempty"`

	// Match: If filled, this entity is guaranteed to match at requested
	// confidence probability (default 99%).
	Match *ReconcileCandidate `json:"match,omitempty"`

	// Warning: If filled, then there were recoverable problems that
	// affected the request. For example, some of the properties were
	// ignored because they either are not valid Freebase predicates or are
	// not indexed for reconciliation. The candidates returned should be
	// considered valid results, with the caveat that sections of the
	// request were ignored as specified by the warning text.
	Warning []*ReconcileGetWarning `json:"warning,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Candidate") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ReconcileGet) MarshalJSON() ([]byte, error) {
	type noMethod ReconcileGet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ReconcileGetCosts: Server costs for reconciling.
type ReconcileGetCosts struct {
	// Hits: Total number of hits found.
	Hits int64 `json:"hits,omitempty"`

	// Ms: Total milliseconds spent.
	Ms int64 `json:"ms,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Hits") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ReconcileGetCosts) MarshalJSON() ([]byte, error) {
	type noMethod ReconcileGetCosts
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ReconcileGetWarning struct {
	// Location: Location of warning in the request e.g. invalid predicate.
	Location string `json:"location,omitempty"`

	// Message: Warning message to display to the user.
	Message string `json:"message,omitempty"`

	// Reason: Code for identifying classes of warnings.
	Reason string `json:"reason,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Location") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ReconcileGetWarning) MarshalJSON() ([]byte, error) {
	type noMethod ReconcileGetWarning
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "freebase.reconcile":

type ReconcileCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Reconcile: Reconcile entities to Freebase open data.
func (s *Service) Reconcile() *ReconcileCall {
	c := &ReconcileCall{s: s, opt_: make(map[string]interface{})}
	return c
}

// Confidence sets the optional parameter "confidence": Required
// confidence for a candidate to match. Must be between .5 and 1.0
func (c *ReconcileCall) Confidence(confidence float64) *ReconcileCall {
	c.opt_["confidence"] = confidence
	return c
}

// Kind sets the optional parameter "kind": Classifications of entity
// e.g. type, category, title.
func (c *ReconcileCall) Kind(kind string) *ReconcileCall {
	c.opt_["kind"] = kind
	return c
}

// Lang sets the optional parameter "lang": Languages for names and
// values. First language is used for display. Default is 'en'.
func (c *ReconcileCall) Lang(lang string) *ReconcileCall {
	c.opt_["lang"] = lang
	return c
}

// Limit sets the optional parameter "limit": Maximum number of
// candidates to return.
func (c *ReconcileCall) Limit(limit int64) *ReconcileCall {
	c.opt_["limit"] = limit
	return c
}

// Name sets the optional parameter "name": Name of entity.
func (c *ReconcileCall) Name(name string) *ReconcileCall {
	c.opt_["name"] = name
	return c
}

// Prop sets the optional parameter "prop": Property values for entity
// formatted as
// :
func (c *ReconcileCall) Prop(prop string) *ReconcileCall {
	c.opt_["prop"] = prop
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReconcileCall) Fields(s ...googleapi.Field) *ReconcileCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ReconcileCall) IfNoneMatch(entityTag string) *ReconcileCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReconcileCall) Context(ctx context.Context) *ReconcileCall {
	c.ctx_ = ctx
	return c
}

func (c *ReconcileCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["confidence"]; ok {
		params.Set("confidence", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["kind"]; ok {
		params.Set("kind", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["lang"]; ok {
		params.Set("lang", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["limit"]; ok {
		params.Set("limit", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["name"]; ok {
		params.Set("name", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["prop"]; ok {
		params.Set("prop", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "reconcile")
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

// Do executes the "freebase.reconcile" call.
// Exactly one of *ReconcileGet or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ReconcileGet.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ReconcileCall) Do() (*ReconcileGet, error) {
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
	ret := &ReconcileGet{
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
	//   "description": "Reconcile entities to Freebase open data.",
	//   "httpMethod": "GET",
	//   "id": "freebase.reconcile",
	//   "parameters": {
	//     "confidence": {
	//       "default": "0.99",
	//       "description": "Required confidence for a candidate to match. Must be between .5 and 1.0",
	//       "format": "float",
	//       "location": "query",
	//       "maximum": "1.0",
	//       "minimum": "0.0",
	//       "type": "number"
	//     },
	//     "kind": {
	//       "description": "Classifications of entity e.g. type, category, title.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "lang": {
	//       "description": "Languages for names and values. First language is used for display. Default is 'en'.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "limit": {
	//       "default": "3",
	//       "description": "Maximum number of candidates to return.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "25",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "name": {
	//       "description": "Name of entity.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "prop": {
	//       "description": "Property values for entity formatted as\n:",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "reconcile",
	//   "response": {
	//     "$ref": "ReconcileGet"
	//   }
	// }

}

// method id "freebase.search":

type SearchCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Search: Search Freebase open data.
func (s *Service) Search() *SearchCall {
	c := &SearchCall{s: s, opt_: make(map[string]interface{})}
	return c
}

// AsOfTime sets the optional parameter "as_of_time": A mql as_of_time
// value to use with mql_output queries.
func (c *SearchCall) AsOfTime(asOfTime string) *SearchCall {
	c.opt_["as_of_time"] = asOfTime
	return c
}

// Callback sets the optional parameter "callback": JS method name for
// JSONP callbacks.
func (c *SearchCall) Callback(callback string) *SearchCall {
	c.opt_["callback"] = callback
	return c
}

// Cursor sets the optional parameter "cursor": The cursor value to use
// for the next page of results.
func (c *SearchCall) Cursor(cursor int64) *SearchCall {
	c.opt_["cursor"] = cursor
	return c
}

// Domain sets the optional parameter "domain": Restrict to topics with
// this Freebase domain id.
func (c *SearchCall) Domain(domain string) *SearchCall {
	c.opt_["domain"] = domain
	return c
}

// Encode sets the optional parameter "encode": The encoding of the
// response. You can use this parameter to enable html encoding.
//
// Possible values:
//   "html" - Encode certain characters in the response (such as tags
// and ambersands) using html encoding.
//   "off" (default) - No encoding of the response. You should not print
// the results directly on an web page without html-escaping the content
// first.
func (c *SearchCall) Encode(encode string) *SearchCall {
	c.opt_["encode"] = encode
	return c
}

// Exact sets the optional parameter "exact": Query on exact name and
// keys only.
func (c *SearchCall) Exact(exact bool) *SearchCall {
	c.opt_["exact"] = exact
	return c
}

// Filter sets the optional parameter "filter": A filter to apply to the
// query.
func (c *SearchCall) Filter(filter string) *SearchCall {
	c.opt_["filter"] = filter
	return c
}

// Format sets the optional parameter "format": Structural format of the
// json response.
//
// Possible values:
//   "ac" - Compact format useful for autocomplete/suggest UIs.
//   "classic" - [DEPRECATED] Same format as was returned by
// api.freebase.com.
//   "entity" (default) - Basic information about the entities.
//   "guids" - [DEPRECATED] Ordered list of a freebase guids.
//   "ids" - Ordered list of freebase ids.
//   "mids" - Ordered list of freebase mids.
func (c *SearchCall) Format(format string) *SearchCall {
	c.opt_["format"] = format
	return c
}

// Help sets the optional parameter "help": The keyword to request help
// on.
//
// Possible values:
//   "langs" - The language codes served by the service.
//   "mappings" - The property/path mappings supported by the filter and
// output request parameters.
//   "predicates" - The predicates and path-terminating properties
// supported by the filter and output request parameters.
func (c *SearchCall) Help(help string) *SearchCall {
	c.opt_["help"] = help
	return c
}

// Indent sets the optional parameter "indent": Whether to indent the
// json results or not.
func (c *SearchCall) Indent(indent bool) *SearchCall {
	c.opt_["indent"] = indent
	return c
}

// Lang sets the optional parameter "lang": The code of the language to
// run the query with. Default is 'en'.
func (c *SearchCall) Lang(lang string) *SearchCall {
	c.opt_["lang"] = lang
	return c
}

// Limit sets the optional parameter "limit": Maximum number of results
// to return.
func (c *SearchCall) Limit(limit int64) *SearchCall {
	c.opt_["limit"] = limit
	return c
}

// Mid sets the optional parameter "mid": A mid to use instead of a
// query.
func (c *SearchCall) Mid(mid string) *SearchCall {
	c.opt_["mid"] = mid
	return c
}

// MqlOutput sets the optional parameter "mql_output": The MQL query to
// run againist the results to extract more data.
func (c *SearchCall) MqlOutput(mqlOutput string) *SearchCall {
	c.opt_["mql_output"] = mqlOutput
	return c
}

// Output sets the optional parameter "output": An output expression to
// request data from matches.
func (c *SearchCall) Output(output string) *SearchCall {
	c.opt_["output"] = output
	return c
}

// Prefixed sets the optional parameter "prefixed": Prefix match against
// names and aliases.
func (c *SearchCall) Prefixed(prefixed bool) *SearchCall {
	c.opt_["prefixed"] = prefixed
	return c
}

// Query sets the optional parameter "query": Query term to search for.
func (c *SearchCall) Query(query string) *SearchCall {
	c.opt_["query"] = query
	return c
}

// Scoring sets the optional parameter "scoring": Relevance scoring
// algorithm to use.
//
// Possible values:
//   "entity" (default) - Use freebase and popularity entity ranking.
//   "freebase" - Use freebase entity ranking.
//   "schema" - Use schema ranking for properties and types.
func (c *SearchCall) Scoring(scoring string) *SearchCall {
	c.opt_["scoring"] = scoring
	return c
}

// Spell sets the optional parameter "spell": Request 'did you mean'
// suggestions
//
// Possible values:
//   "always" - Request spelling suggestions for any query at least
// three characters long.
//   "no_results" - Request spelling suggestions if no results were
// found.
//   "no_spelling" (default) - Don't request spelling suggestions.
func (c *SearchCall) Spell(spell string) *SearchCall {
	c.opt_["spell"] = spell
	return c
}

// Stemmed sets the optional parameter "stemmed": Query on stemmed names
// and aliases. May not be used with prefixed.
func (c *SearchCall) Stemmed(stemmed bool) *SearchCall {
	c.opt_["stemmed"] = stemmed
	return c
}

// Type sets the optional parameter "type": Restrict to topics with this
// Freebase type id.
func (c *SearchCall) Type(type_ string) *SearchCall {
	c.opt_["type"] = type_
	return c
}

// With sets the optional parameter "with": A rule to match against.
func (c *SearchCall) With(with string) *SearchCall {
	c.opt_["with"] = with
	return c
}

// Without sets the optional parameter "without": A rule to not match
// against.
func (c *SearchCall) Without(without string) *SearchCall {
	c.opt_["without"] = without
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *SearchCall) Fields(s ...googleapi.Field) *SearchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *SearchCall) IfNoneMatch(entityTag string) *SearchCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do and Download methods.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *SearchCall) Context(ctx context.Context) *SearchCall {
	c.ctx_ = ctx
	return c
}

func (c *SearchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["as_of_time"]; ok {
		params.Set("as_of_time", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["callback"]; ok {
		params.Set("callback", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["cursor"]; ok {
		params.Set("cursor", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["domain"]; ok {
		params.Set("domain", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["encode"]; ok {
		params.Set("encode", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["exact"]; ok {
		params.Set("exact", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["filter"]; ok {
		params.Set("filter", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["format"]; ok {
		params.Set("format", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["help"]; ok {
		params.Set("help", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["indent"]; ok {
		params.Set("indent", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["lang"]; ok {
		params.Set("lang", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["limit"]; ok {
		params.Set("limit", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["mid"]; ok {
		params.Set("mid", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["mql_output"]; ok {
		params.Set("mql_output", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["output"]; ok {
		params.Set("output", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["prefixed"]; ok {
		params.Set("prefixed", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["query"]; ok {
		params.Set("query", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["scoring"]; ok {
		params.Set("scoring", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["spell"]; ok {
		params.Set("spell", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["stemmed"]; ok {
		params.Set("stemmed", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["type"]; ok {
		params.Set("type", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["with"]; ok {
		params.Set("with", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["without"]; ok {
		params.Set("without", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "search")
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

// Download fetches the API endpoint's "media" value, instead of the normal
// API response value. If the returned error is nil, the Response is guaranteed to
// have a 2xx status code. Callers must close the Response.Body as usual.
func (c *SearchCall) Download() (*http.Response, error) {
	res, err := c.doRequest("media")
	if err != nil {
		return nil, err
	}
	if err := googleapi.CheckMediaResponse(res); err != nil {
		res.Body.Close()
		return nil, err
	}
	return res, nil
}

// Do executes the "freebase.search" call.
func (c *SearchCall) Do() error {
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
	//   "description": "Search Freebase open data.",
	//   "httpMethod": "GET",
	//   "id": "freebase.search",
	//   "parameters": {
	//     "as_of_time": {
	//       "description": "A mql as_of_time value to use with mql_output queries.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "callback": {
	//       "description": "JS method name for JSONP callbacks.",
	//       "location": "query",
	//       "pattern": "([A-Za-z0-9_$.]|\\[|\\])+",
	//       "type": "string"
	//     },
	//     "cursor": {
	//       "description": "The cursor value to use for the next page of results.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "domain": {
	//       "description": "Restrict to topics with this Freebase domain id.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "encode": {
	//       "default": "off",
	//       "description": "The encoding of the response. You can use this parameter to enable html encoding.",
	//       "enum": [
	//         "html",
	//         "off"
	//       ],
	//       "enumDescriptions": [
	//         "Encode certain characters in the response (such as tags and ambersands) using html encoding.",
	//         "No encoding of the response. You should not print the results directly on an web page without html-escaping the content first."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "exact": {
	//       "description": "Query on exact name and keys only.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "filter": {
	//       "description": "A filter to apply to the query.",
	//       "location": "query",
	//       "pattern": "^\\(.*\\)$",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "format": {
	//       "default": "entity",
	//       "description": "Structural format of the json response.",
	//       "enum": [
	//         "ac",
	//         "classic",
	//         "entity",
	//         "guids",
	//         "ids",
	//         "mids"
	//       ],
	//       "enumDescriptions": [
	//         "Compact format useful for autocomplete/suggest UIs.",
	//         "[DEPRECATED] Same format as was returned by api.freebase.com.",
	//         "Basic information about the entities.",
	//         "[DEPRECATED] Ordered list of a freebase guids.",
	//         "Ordered list of freebase ids.",
	//         "Ordered list of freebase mids."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "help": {
	//       "description": "The keyword to request help on.",
	//       "enum": [
	//         "langs",
	//         "mappings",
	//         "predicates"
	//       ],
	//       "enumDescriptions": [
	//         "The language codes served by the service.",
	//         "The property/path mappings supported by the filter and output request parameters.",
	//         "The predicates and path-terminating properties supported by the filter and output request parameters."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "indent": {
	//       "description": "Whether to indent the json results or not.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "lang": {
	//       "description": "The code of the language to run the query with. Default is 'en'.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "limit": {
	//       "default": "20",
	//       "description": "Maximum number of results to return.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "mid": {
	//       "description": "A mid to use instead of a query.",
	//       "location": "query",
	//       "pattern": "^/[mgtx]/[0-2][0-9bcdfghjklmnpqrstvwxyz_]{1,24}$",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "mql_output": {
	//       "description": "The MQL query to run againist the results to extract more data.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "output": {
	//       "description": "An output expression to request data from matches.",
	//       "location": "query",
	//       "pattern": "^\\(.*\\)$",
	//       "type": "string"
	//     },
	//     "prefixed": {
	//       "description": "Prefix match against names and aliases.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "query": {
	//       "description": "Query term to search for.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "scoring": {
	//       "default": "entity",
	//       "description": "Relevance scoring algorithm to use.",
	//       "enum": [
	//         "entity",
	//         "freebase",
	//         "schema"
	//       ],
	//       "enumDescriptions": [
	//         "Use freebase and popularity entity ranking.",
	//         "Use freebase entity ranking.",
	//         "Use schema ranking for properties and types."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "spell": {
	//       "default": "no_spelling",
	//       "description": "Request 'did you mean' suggestions",
	//       "enum": [
	//         "always",
	//         "no_results",
	//         "no_spelling"
	//       ],
	//       "enumDescriptions": [
	//         "Request spelling suggestions for any query at least three characters long.",
	//         "Request spelling suggestions if no results were found.",
	//         "Don't request spelling suggestions."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "stemmed": {
	//       "description": "Query on stemmed names and aliases. May not be used with prefixed.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "type": {
	//       "description": "Restrict to topics with this Freebase type id.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "with": {
	//       "description": "A rule to match against.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "without": {
	//       "description": "A rule to not match against.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "search",
	//   "supportsMediaDownload": true
	// }

}
