// Package gamesconfiguration provides access to the Google Play Game Services Publishing API.
//
// See https://developers.google.com/games/services
//
// Usage example:
//
//   import "google.golang.org/api/gamesconfiguration/v1configuration"
//   ...
//   gamesconfigurationService, err := gamesconfiguration.New(oauthHttpClient)
package gamesconfiguration // import "google.golang.org/api/gamesconfiguration/v1configuration"

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

const apiId = "gamesConfiguration:v1configuration"
const apiName = "gamesConfiguration"
const apiVersion = "v1configuration"
const basePath = "https://www.googleapis.com/games/v1configuration/"

// OAuth2 scopes used by this API.
const (
	// View and manage your Google Play Developer account
	AndroidpublisherScope = "https://www.googleapis.com/auth/androidpublisher"
)

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.AchievementConfigurations = NewAchievementConfigurationsService(s)
	s.ImageConfigurations = NewImageConfigurationsService(s)
	s.LeaderboardConfigurations = NewLeaderboardConfigurationsService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	AchievementConfigurations *AchievementConfigurationsService

	ImageConfigurations *ImageConfigurationsService

	LeaderboardConfigurations *LeaderboardConfigurationsService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewAchievementConfigurationsService(s *Service) *AchievementConfigurationsService {
	rs := &AchievementConfigurationsService{s: s}
	return rs
}

type AchievementConfigurationsService struct {
	s *Service
}

func NewImageConfigurationsService(s *Service) *ImageConfigurationsService {
	rs := &ImageConfigurationsService{s: s}
	return rs
}

type ImageConfigurationsService struct {
	s *Service
}

func NewLeaderboardConfigurationsService(s *Service) *LeaderboardConfigurationsService {
	rs := &LeaderboardConfigurationsService{s: s}
	return rs
}

type LeaderboardConfigurationsService struct {
	s *Service
}

// AchievementConfiguration: This is a JSON template for an achievement
// configuration resource.
type AchievementConfiguration struct {
	// AchievementType: The type of the achievement.
	// Possible values are:
	// - "STANDARD" - Achievement is either locked or unlocked.
	// - "INCREMENTAL" - Achievement is incremental.
	AchievementType string `json:"achievementType,omitempty"`

	// Draft: The draft data of the achievement.
	Draft *AchievementConfigurationDetail `json:"draft,omitempty"`

	// Id: The ID of the achievement.
	Id string `json:"id,omitempty"`

	// InitialState: The initial state of the achievement.
	// Possible values are:
	// - "HIDDEN" - Achievement is hidden.
	// - "REVEALED" - Achievement is revealed.
	// - "UNLOCKED" - Achievement is unlocked.
	InitialState string `json:"initialState,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesConfiguration#achievementConfiguration.
	Kind string `json:"kind,omitempty"`

	// Published: The read-only published data of the achievement.
	Published *AchievementConfigurationDetail `json:"published,omitempty"`

	// StepsToUnlock: Steps to unlock. Only applicable to incremental
	// achievements.
	StepsToUnlock int64 `json:"stepsToUnlock,omitempty"`

	// Token: The token for this resource.
	Token string `json:"token,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AchievementType") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AchievementConfiguration) MarshalJSON() ([]byte, error) {
	type noMethod AchievementConfiguration
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AchievementConfigurationDetail: This is a JSON template for an
// achievement configuration detail.
type AchievementConfigurationDetail struct {
	// Description: Localized strings for the achievement description.
	Description *LocalizedStringBundle `json:"description,omitempty"`

	// IconUrl: The icon url of this achievement. Writes to this field are
	// ignored.
	IconUrl string `json:"iconUrl,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesConfiguration#achievementConfigurationDetail.
	Kind string `json:"kind,omitempty"`

	// Name: Localized strings for the achievement name.
	Name *LocalizedStringBundle `json:"name,omitempty"`

	// PointValue: Point value for the achievement.
	PointValue int64 `json:"pointValue,omitempty"`

	// SortRank: The sort rank of this achievement. Writes to this field are
	// ignored.
	SortRank int64 `json:"sortRank,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Description") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AchievementConfigurationDetail) MarshalJSON() ([]byte, error) {
	type noMethod AchievementConfigurationDetail
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AchievementConfigurationListResponse: This is a JSON template for a
// ListConfigurations response.
type AchievementConfigurationListResponse struct {
	// Items: The achievement configurations.
	Items []*AchievementConfiguration `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#achievementConfigurationListResponse.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The pagination token for the next page of results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Items") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AchievementConfigurationListResponse) MarshalJSON() ([]byte, error) {
	type noMethod AchievementConfigurationListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GamesNumberAffixConfiguration: This is a JSON template for a number
// affix resource.
type GamesNumberAffixConfiguration struct {
	// Few: When the language requires special treatment of "small" numbers
	// (as with 2, 3, and 4 in Czech; or numbers ending 2, 3, or 4 but not
	// 12, 13, or 14 in Polish).
	Few *LocalizedStringBundle `json:"few,omitempty"`

	// Many: When the language requires special treatment of "large" numbers
	// (as with numbers ending 11-99 in Maltese).
	Many *LocalizedStringBundle `json:"many,omitempty"`

	// One: When the language requires special treatment of numbers like one
	// (as with the number 1 in English and most other languages; in
	// Russian, any number ending in 1 but not ending in 11 is in this
	// class).
	One *LocalizedStringBundle `json:"one,omitempty"`

	// Other: When the language does not require special treatment of the
	// given quantity (as with all numbers in Chinese, or 42 in English).
	Other *LocalizedStringBundle `json:"other,omitempty"`

	// Two: When the language requires special treatment of numbers like two
	// (as with 2 in Welsh, or 102 in Slovenian).
	Two *LocalizedStringBundle `json:"two,omitempty"`

	// Zero: When the language requires special treatment of the number 0
	// (as in Arabic).
	Zero *LocalizedStringBundle `json:"zero,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Few") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GamesNumberAffixConfiguration) MarshalJSON() ([]byte, error) {
	type noMethod GamesNumberAffixConfiguration
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GamesNumberFormatConfiguration: This is a JSON template for a number
// format resource.
type GamesNumberFormatConfiguration struct {
	// CurrencyCode: The curreny code string. Only used for CURRENCY format
	// type.
	CurrencyCode string `json:"currencyCode,omitempty"`

	// NumDecimalPlaces: The number of decimal places for number. Only used
	// for NUMERIC format type.
	NumDecimalPlaces int64 `json:"numDecimalPlaces,omitempty"`

	// NumberFormatType: The formatting for the number.
	// Possible values are:
	// - "NUMERIC" - Numbers are formatted to have no digits or a fixed
	// number of digits after the decimal point according to locale. An
	// optional custom unit can be added.
	// - "TIME_DURATION" - Numbers are formatted to hours, minutes and
	// seconds.
	// - "CURRENCY" - Numbers are formatted to currency according to locale.
	NumberFormatType string `json:"numberFormatType,omitempty"`

	// Suffix: An optional suffix for the NUMERIC format type. These strings
	// follow the same  plural rules as all Android string resources.
	Suffix *GamesNumberAffixConfiguration `json:"suffix,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CurrencyCode") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GamesNumberFormatConfiguration) MarshalJSON() ([]byte, error) {
	type noMethod GamesNumberFormatConfiguration
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ImageConfiguration: This is a JSON template for an image
// configuration resource.
type ImageConfiguration struct {
	// ImageType: The image type for the image.
	ImageType string `json:"imageType,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesConfiguration#imageConfiguration.
	Kind string `json:"kind,omitempty"`

	// ResourceId: The resource ID of resource which the image belongs to.
	ResourceId string `json:"resourceId,omitempty"`

	// Url: The url for this image.
	Url string `json:"url,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ImageType") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ImageConfiguration) MarshalJSON() ([]byte, error) {
	type noMethod ImageConfiguration
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LeaderboardConfiguration: This is a JSON template for an leaderboard
// configuration resource.
type LeaderboardConfiguration struct {
	// Draft: The draft data of the leaderboard.
	Draft *LeaderboardConfigurationDetail `json:"draft,omitempty"`

	// Id: The ID of the leaderboard.
	Id string `json:"id,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesConfiguration#leaderboardConfiguration.
	Kind string `json:"kind,omitempty"`

	// Published: The read-only published data of the leaderboard.
	Published *LeaderboardConfigurationDetail `json:"published,omitempty"`

	// ScoreMax: Maximum score that can be posted to this leaderboard.
	ScoreMax int64 `json:"scoreMax,omitempty,string"`

	// ScoreMin: Minimum score that can be posted to this leaderboard.
	ScoreMin int64 `json:"scoreMin,omitempty,string"`

	// ScoreOrder: The type of the leaderboard.
	// Possible values are:
	// - "LARGER_IS_BETTER" - Larger scores posted are ranked higher.
	// - "SMALLER_IS_BETTER" - Smaller scores posted are ranked higher.
	ScoreOrder string `json:"scoreOrder,omitempty"`

	// Token: The token for this resource.
	Token string `json:"token,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Draft") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LeaderboardConfiguration) MarshalJSON() ([]byte, error) {
	type noMethod LeaderboardConfiguration
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LeaderboardConfigurationDetail: This is a JSON template for a
// leaderboard configuration detail.
type LeaderboardConfigurationDetail struct {
	// IconUrl: The icon url of this leaderboard. Writes to this field are
	// ignored.
	IconUrl string `json:"iconUrl,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesConfiguration#leaderboardConfigurationDetail.
	Kind string `json:"kind,omitempty"`

	// Name: Localized strings for the leaderboard name.
	Name *LocalizedStringBundle `json:"name,omitempty"`

	// ScoreFormat: The score formatting for the leaderboard.
	ScoreFormat *GamesNumberFormatConfiguration `json:"scoreFormat,omitempty"`

	// SortRank: The sort rank of this leaderboard. Writes to this field are
	// ignored.
	SortRank int64 `json:"sortRank,omitempty"`

	// ForceSendFields is a list of field names (e.g. "IconUrl") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LeaderboardConfigurationDetail) MarshalJSON() ([]byte, error) {
	type noMethod LeaderboardConfigurationDetail
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LeaderboardConfigurationListResponse: This is a JSON template for a
// ListConfigurations response.
type LeaderboardConfigurationListResponse struct {
	// Items: The leaderboard configurations.
	Items []*LeaderboardConfiguration `json:"items,omitempty"`

	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string games#leaderboardConfigurationListResponse.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The pagination token for the next page of results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Items") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LeaderboardConfigurationListResponse) MarshalJSON() ([]byte, error) {
	type noMethod LeaderboardConfigurationListResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LocalizedString: This is a JSON template for a localized string
// resource.
type LocalizedString struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesConfiguration#localizedString.
	Kind string `json:"kind,omitempty"`

	// Locale: The locale string.
	Locale string `json:"locale,omitempty"`

	// Value: The string value.
	Value string `json:"value,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LocalizedString) MarshalJSON() ([]byte, error) {
	type noMethod LocalizedString
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LocalizedStringBundle: This is a JSON template for a localized string
// bundle resource.
type LocalizedStringBundle struct {
	// Kind: Uniquely identifies the type of this resource. Value is always
	// the fixed string gamesConfiguration#localizedStringBundle.
	Kind string `json:"kind,omitempty"`

	// Translations: The locale strings.
	Translations []*LocalizedString `json:"translations,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Kind") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LocalizedStringBundle) MarshalJSON() ([]byte, error) {
	type noMethod LocalizedStringBundle
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "gamesConfiguration.achievementConfigurations.delete":

type AchievementConfigurationsDeleteCall struct {
	s             *Service
	achievementId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Delete: Delete the achievement configuration with the given ID.
func (r *AchievementConfigurationsService) Delete(achievementId string) *AchievementConfigurationsDeleteCall {
	c := &AchievementConfigurationsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.achievementId = achievementId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementConfigurationsDeleteCall) Fields(s ...googleapi.Field) *AchievementConfigurationsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementConfigurationsDeleteCall) Context(ctx context.Context) *AchievementConfigurationsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementConfigurationsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/{achievementId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"achievementId": c.achievementId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesConfiguration.achievementConfigurations.delete" call.
func (c *AchievementConfigurationsDeleteCall) Do() error {
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
	//   "description": "Delete the achievement configuration with the given ID.",
	//   "httpMethod": "DELETE",
	//   "id": "gamesConfiguration.achievementConfigurations.delete",
	//   "parameterOrder": [
	//     "achievementId"
	//   ],
	//   "parameters": {
	//     "achievementId": {
	//       "description": "The ID of the achievement used by this method.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "achievements/{achievementId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/androidpublisher"
	//   ]
	// }

}

// method id "gamesConfiguration.achievementConfigurations.get":

type AchievementConfigurationsGetCall struct {
	s             *Service
	achievementId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Get: Retrieves the metadata of the achievement configuration with the
// given ID.
func (r *AchievementConfigurationsService) Get(achievementId string) *AchievementConfigurationsGetCall {
	c := &AchievementConfigurationsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.achievementId = achievementId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementConfigurationsGetCall) Fields(s ...googleapi.Field) *AchievementConfigurationsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AchievementConfigurationsGetCall) IfNoneMatch(entityTag string) *AchievementConfigurationsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementConfigurationsGetCall) Context(ctx context.Context) *AchievementConfigurationsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementConfigurationsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/{achievementId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"achievementId": c.achievementId,
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

// Do executes the "gamesConfiguration.achievementConfigurations.get" call.
// Exactly one of *AchievementConfiguration or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *AchievementConfiguration.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AchievementConfigurationsGetCall) Do() (*AchievementConfiguration, error) {
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
	ret := &AchievementConfiguration{
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
	//   "description": "Retrieves the metadata of the achievement configuration with the given ID.",
	//   "httpMethod": "GET",
	//   "id": "gamesConfiguration.achievementConfigurations.get",
	//   "parameterOrder": [
	//     "achievementId"
	//   ],
	//   "parameters": {
	//     "achievementId": {
	//       "description": "The ID of the achievement used by this method.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "achievements/{achievementId}",
	//   "response": {
	//     "$ref": "AchievementConfiguration"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/androidpublisher"
	//   ]
	// }

}

// method id "gamesConfiguration.achievementConfigurations.insert":

type AchievementConfigurationsInsertCall struct {
	s                        *Service
	applicationId            string
	achievementconfiguration *AchievementConfiguration
	opt_                     map[string]interface{}
	ctx_                     context.Context
}

// Insert: Insert a new achievement configuration in this application.
func (r *AchievementConfigurationsService) Insert(applicationId string, achievementconfiguration *AchievementConfiguration) *AchievementConfigurationsInsertCall {
	c := &AchievementConfigurationsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.applicationId = applicationId
	c.achievementconfiguration = achievementconfiguration
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementConfigurationsInsertCall) Fields(s ...googleapi.Field) *AchievementConfigurationsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementConfigurationsInsertCall) Context(ctx context.Context) *AchievementConfigurationsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementConfigurationsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.achievementconfiguration)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "applications/{applicationId}/achievements")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"applicationId": c.applicationId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesConfiguration.achievementConfigurations.insert" call.
// Exactly one of *AchievementConfiguration or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *AchievementConfiguration.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AchievementConfigurationsInsertCall) Do() (*AchievementConfiguration, error) {
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
	ret := &AchievementConfiguration{
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
	//   "description": "Insert a new achievement configuration in this application.",
	//   "httpMethod": "POST",
	//   "id": "gamesConfiguration.achievementConfigurations.insert",
	//   "parameterOrder": [
	//     "applicationId"
	//   ],
	//   "parameters": {
	//     "applicationId": {
	//       "description": "The application ID from the Google Play developer console.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "applications/{applicationId}/achievements",
	//   "request": {
	//     "$ref": "AchievementConfiguration"
	//   },
	//   "response": {
	//     "$ref": "AchievementConfiguration"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/androidpublisher"
	//   ]
	// }

}

// method id "gamesConfiguration.achievementConfigurations.list":

type AchievementConfigurationsListCall struct {
	s             *Service
	applicationId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: Returns a list of the achievement configurations in this
// application.
func (r *AchievementConfigurationsService) List(applicationId string) *AchievementConfigurationsListCall {
	c := &AchievementConfigurationsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.applicationId = applicationId
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of resource configurations to return in the response, used for
// paging. For any response, the actual number of resources returned may
// be less than the specified maxResults.
func (c *AchievementConfigurationsListCall) MaxResults(maxResults int64) *AchievementConfigurationsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *AchievementConfigurationsListCall) PageToken(pageToken string) *AchievementConfigurationsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementConfigurationsListCall) Fields(s ...googleapi.Field) *AchievementConfigurationsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AchievementConfigurationsListCall) IfNoneMatch(entityTag string) *AchievementConfigurationsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementConfigurationsListCall) Context(ctx context.Context) *AchievementConfigurationsListCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementConfigurationsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "applications/{applicationId}/achievements")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"applicationId": c.applicationId,
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

// Do executes the "gamesConfiguration.achievementConfigurations.list" call.
// Exactly one of *AchievementConfigurationListResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *AchievementConfigurationListResponse.ServerResponse.Header or
// (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *AchievementConfigurationsListCall) Do() (*AchievementConfigurationListResponse, error) {
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
	ret := &AchievementConfigurationListResponse{
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
	//   "description": "Returns a list of the achievement configurations in this application.",
	//   "httpMethod": "GET",
	//   "id": "gamesConfiguration.achievementConfigurations.list",
	//   "parameterOrder": [
	//     "applicationId"
	//   ],
	//   "parameters": {
	//     "applicationId": {
	//       "description": "The application ID from the Google Play developer console.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of resource configurations to return in the response, used for paging. For any response, the actual number of resources returned may be less than the specified maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "200",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "applications/{applicationId}/achievements",
	//   "response": {
	//     "$ref": "AchievementConfigurationListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/androidpublisher"
	//   ]
	// }

}

// method id "gamesConfiguration.achievementConfigurations.patch":

type AchievementConfigurationsPatchCall struct {
	s                        *Service
	achievementId            string
	achievementconfiguration *AchievementConfiguration
	opt_                     map[string]interface{}
	ctx_                     context.Context
}

// Patch: Update the metadata of the achievement configuration with the
// given ID. This method supports patch semantics.
func (r *AchievementConfigurationsService) Patch(achievementId string, achievementconfiguration *AchievementConfiguration) *AchievementConfigurationsPatchCall {
	c := &AchievementConfigurationsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.achievementId = achievementId
	c.achievementconfiguration = achievementconfiguration
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementConfigurationsPatchCall) Fields(s ...googleapi.Field) *AchievementConfigurationsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementConfigurationsPatchCall) Context(ctx context.Context) *AchievementConfigurationsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementConfigurationsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.achievementconfiguration)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/{achievementId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"achievementId": c.achievementId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesConfiguration.achievementConfigurations.patch" call.
// Exactly one of *AchievementConfiguration or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *AchievementConfiguration.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AchievementConfigurationsPatchCall) Do() (*AchievementConfiguration, error) {
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
	ret := &AchievementConfiguration{
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
	//   "description": "Update the metadata of the achievement configuration with the given ID. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "gamesConfiguration.achievementConfigurations.patch",
	//   "parameterOrder": [
	//     "achievementId"
	//   ],
	//   "parameters": {
	//     "achievementId": {
	//       "description": "The ID of the achievement used by this method.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "achievements/{achievementId}",
	//   "request": {
	//     "$ref": "AchievementConfiguration"
	//   },
	//   "response": {
	//     "$ref": "AchievementConfiguration"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/androidpublisher"
	//   ]
	// }

}

// method id "gamesConfiguration.achievementConfigurations.update":

type AchievementConfigurationsUpdateCall struct {
	s                        *Service
	achievementId            string
	achievementconfiguration *AchievementConfiguration
	opt_                     map[string]interface{}
	ctx_                     context.Context
}

// Update: Update the metadata of the achievement configuration with the
// given ID.
func (r *AchievementConfigurationsService) Update(achievementId string, achievementconfiguration *AchievementConfiguration) *AchievementConfigurationsUpdateCall {
	c := &AchievementConfigurationsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.achievementId = achievementId
	c.achievementconfiguration = achievementconfiguration
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AchievementConfigurationsUpdateCall) Fields(s ...googleapi.Field) *AchievementConfigurationsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AchievementConfigurationsUpdateCall) Context(ctx context.Context) *AchievementConfigurationsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *AchievementConfigurationsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.achievementconfiguration)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "achievements/{achievementId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"achievementId": c.achievementId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesConfiguration.achievementConfigurations.update" call.
// Exactly one of *AchievementConfiguration or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *AchievementConfiguration.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AchievementConfigurationsUpdateCall) Do() (*AchievementConfiguration, error) {
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
	ret := &AchievementConfiguration{
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
	//   "description": "Update the metadata of the achievement configuration with the given ID.",
	//   "httpMethod": "PUT",
	//   "id": "gamesConfiguration.achievementConfigurations.update",
	//   "parameterOrder": [
	//     "achievementId"
	//   ],
	//   "parameters": {
	//     "achievementId": {
	//       "description": "The ID of the achievement used by this method.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "achievements/{achievementId}",
	//   "request": {
	//     "$ref": "AchievementConfiguration"
	//   },
	//   "response": {
	//     "$ref": "AchievementConfiguration"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/androidpublisher"
	//   ]
	// }

}

// method id "gamesConfiguration.imageConfigurations.upload":

type ImageConfigurationsUploadCall struct {
	s          *Service
	resourceId string
	imageType  string
	opt_       map[string]interface{}
	media_     io.Reader
	resumable_ googleapi.SizeReaderAt
	mediaType_ string
	protocol_  string
	ctx_       context.Context
}

// Upload: Uploads an image for a resource with the given ID and image
// type.
func (r *ImageConfigurationsService) Upload(resourceId string, imageType string) *ImageConfigurationsUploadCall {
	c := &ImageConfigurationsUploadCall{s: r.s, opt_: make(map[string]interface{})}
	c.resourceId = resourceId
	c.imageType = imageType
	return c
}

// Media specifies the media to upload in a single chunk.
// At most one of Media and ResumableMedia may be set.
func (c *ImageConfigurationsUploadCall) Media(r io.Reader) *ImageConfigurationsUploadCall {
	c.media_ = r
	c.protocol_ = "multipart"
	return c
}

// ResumableMedia specifies the media to upload in chunks and can be canceled with ctx.
// At most one of Media and ResumableMedia may be set.
// mediaType identifies the MIME media type of the upload, such as "image/png".
// If mediaType is "", it will be auto-detected.
// The provided ctx will supersede any context previously provided to
// the Context method.
func (c *ImageConfigurationsUploadCall) ResumableMedia(ctx context.Context, r io.ReaderAt, size int64, mediaType string) *ImageConfigurationsUploadCall {
	c.ctx_ = ctx
	c.resumable_ = io.NewSectionReader(r, 0, size)
	c.mediaType_ = mediaType
	c.protocol_ = "resumable"
	return c
}

// ProgressUpdater provides a callback function that will be called after every chunk.
// It should be a low-latency function in order to not slow down the upload operation.
// This should only be called when using ResumableMedia (as opposed to Media).
func (c *ImageConfigurationsUploadCall) ProgressUpdater(pu googleapi.ProgressUpdater) *ImageConfigurationsUploadCall {
	c.opt_["progressUpdater"] = pu
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ImageConfigurationsUploadCall) Fields(s ...googleapi.Field) *ImageConfigurationsUploadCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
// This context will supersede any context previously provided to
// the ResumableMedia method.
func (c *ImageConfigurationsUploadCall) Context(ctx context.Context) *ImageConfigurationsUploadCall {
	c.ctx_ = ctx
	return c
}

func (c *ImageConfigurationsUploadCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "images/{resourceId}/imageType/{imageType}")
	if c.media_ != nil || c.resumable_ != nil {
		urls = strings.Replace(urls, "https://www.googleapis.com/", "https://www.googleapis.com/upload/", 1)
		params.Set("uploadType", c.protocol_)
	}
	urls += "?" + params.Encode()
	body = new(bytes.Buffer)
	ctype := "application/json"
	if c.protocol_ != "resumable" {
		var cancel func()
		cancel, _ = googleapi.ConditionallyIncludeMedia(c.media_, &body, &ctype)
		if cancel != nil {
			defer cancel()
		}
	}
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"resourceId": c.resourceId,
		"imageType":  c.imageType,
	})
	if c.protocol_ == "resumable" {
		if c.mediaType_ == "" {
			c.mediaType_ = googleapi.DetectMediaType(c.resumable_)
		}
		req.Header.Set("X-Upload-Content-Type", c.mediaType_)
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	} else {
		req.Header.Set("Content-Type", ctype)
	}
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesConfiguration.imageConfigurations.upload" call.
// Exactly one of *ImageConfiguration or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ImageConfiguration.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ImageConfigurationsUploadCall) Do() (*ImageConfiguration, error) {
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
	var progressUpdater_ googleapi.ProgressUpdater
	if v, ok := c.opt_["progressUpdater"]; ok {
		if pu, ok := v.(googleapi.ProgressUpdater); ok {
			progressUpdater_ = pu
		}
	}
	if c.protocol_ == "resumable" {
		loc := res.Header.Get("Location")
		rx := &googleapi.ResumableUpload{
			Client:        c.s.client,
			UserAgent:     c.s.userAgent(),
			URI:           loc,
			Media:         c.resumable_,
			MediaType:     c.mediaType_,
			ContentLength: c.resumable_.Size(),
			Callback:      progressUpdater_,
		}
		res, err = rx.Upload(c.ctx_)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
	}
	ret := &ImageConfiguration{
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
	//   "description": "Uploads an image for a resource with the given ID and image type.",
	//   "httpMethod": "POST",
	//   "id": "gamesConfiguration.imageConfigurations.upload",
	//   "mediaUpload": {
	//     "accept": [
	//       "image/*"
	//     ],
	//     "maxSize": "15MB",
	//     "protocols": {
	//       "resumable": {
	//         "multipart": true,
	//         "path": "/resumable/upload/games/v1configuration/images/{resourceId}/imageType/{imageType}"
	//       },
	//       "simple": {
	//         "multipart": true,
	//         "path": "/upload/games/v1configuration/images/{resourceId}/imageType/{imageType}"
	//       }
	//     }
	//   },
	//   "parameterOrder": [
	//     "resourceId",
	//     "imageType"
	//   ],
	//   "parameters": {
	//     "imageType": {
	//       "description": "Selects which image in a resource for this method.",
	//       "enum": [
	//         "ACHIEVEMENT_ICON",
	//         "LEADERBOARD_ICON"
	//       ],
	//       "enumDescriptions": [
	//         "The icon image for an achievement resource.",
	//         "The icon image for a leaderboard resource."
	//       ],
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "resourceId": {
	//       "description": "The ID of the resource used by this method.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "images/{resourceId}/imageType/{imageType}",
	//   "response": {
	//     "$ref": "ImageConfiguration"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/androidpublisher"
	//   ],
	//   "supportsMediaUpload": true
	// }

}

// method id "gamesConfiguration.leaderboardConfigurations.delete":

type LeaderboardConfigurationsDeleteCall struct {
	s             *Service
	leaderboardId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Delete: Delete the leaderboard configuration with the given ID.
func (r *LeaderboardConfigurationsService) Delete(leaderboardId string) *LeaderboardConfigurationsDeleteCall {
	c := &LeaderboardConfigurationsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.leaderboardId = leaderboardId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LeaderboardConfigurationsDeleteCall) Fields(s ...googleapi.Field) *LeaderboardConfigurationsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LeaderboardConfigurationsDeleteCall) Context(ctx context.Context) *LeaderboardConfigurationsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *LeaderboardConfigurationsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "leaderboards/{leaderboardId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"leaderboardId": c.leaderboardId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesConfiguration.leaderboardConfigurations.delete" call.
func (c *LeaderboardConfigurationsDeleteCall) Do() error {
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
	//   "description": "Delete the leaderboard configuration with the given ID.",
	//   "httpMethod": "DELETE",
	//   "id": "gamesConfiguration.leaderboardConfigurations.delete",
	//   "parameterOrder": [
	//     "leaderboardId"
	//   ],
	//   "parameters": {
	//     "leaderboardId": {
	//       "description": "The ID of the leaderboard.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "leaderboards/{leaderboardId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/androidpublisher"
	//   ]
	// }

}

// method id "gamesConfiguration.leaderboardConfigurations.get":

type LeaderboardConfigurationsGetCall struct {
	s             *Service
	leaderboardId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Get: Retrieves the metadata of the leaderboard configuration with the
// given ID.
func (r *LeaderboardConfigurationsService) Get(leaderboardId string) *LeaderboardConfigurationsGetCall {
	c := &LeaderboardConfigurationsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.leaderboardId = leaderboardId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LeaderboardConfigurationsGetCall) Fields(s ...googleapi.Field) *LeaderboardConfigurationsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *LeaderboardConfigurationsGetCall) IfNoneMatch(entityTag string) *LeaderboardConfigurationsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LeaderboardConfigurationsGetCall) Context(ctx context.Context) *LeaderboardConfigurationsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *LeaderboardConfigurationsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "leaderboards/{leaderboardId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"leaderboardId": c.leaderboardId,
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

// Do executes the "gamesConfiguration.leaderboardConfigurations.get" call.
// Exactly one of *LeaderboardConfiguration or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *LeaderboardConfiguration.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *LeaderboardConfigurationsGetCall) Do() (*LeaderboardConfiguration, error) {
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
	ret := &LeaderboardConfiguration{
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
	//   "description": "Retrieves the metadata of the leaderboard configuration with the given ID.",
	//   "httpMethod": "GET",
	//   "id": "gamesConfiguration.leaderboardConfigurations.get",
	//   "parameterOrder": [
	//     "leaderboardId"
	//   ],
	//   "parameters": {
	//     "leaderboardId": {
	//       "description": "The ID of the leaderboard.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "leaderboards/{leaderboardId}",
	//   "response": {
	//     "$ref": "LeaderboardConfiguration"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/androidpublisher"
	//   ]
	// }

}

// method id "gamesConfiguration.leaderboardConfigurations.insert":

type LeaderboardConfigurationsInsertCall struct {
	s                        *Service
	applicationId            string
	leaderboardconfiguration *LeaderboardConfiguration
	opt_                     map[string]interface{}
	ctx_                     context.Context
}

// Insert: Insert a new leaderboard configuration in this application.
func (r *LeaderboardConfigurationsService) Insert(applicationId string, leaderboardconfiguration *LeaderboardConfiguration) *LeaderboardConfigurationsInsertCall {
	c := &LeaderboardConfigurationsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.applicationId = applicationId
	c.leaderboardconfiguration = leaderboardconfiguration
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LeaderboardConfigurationsInsertCall) Fields(s ...googleapi.Field) *LeaderboardConfigurationsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LeaderboardConfigurationsInsertCall) Context(ctx context.Context) *LeaderboardConfigurationsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *LeaderboardConfigurationsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.leaderboardconfiguration)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "applications/{applicationId}/leaderboards")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"applicationId": c.applicationId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesConfiguration.leaderboardConfigurations.insert" call.
// Exactly one of *LeaderboardConfiguration or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *LeaderboardConfiguration.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *LeaderboardConfigurationsInsertCall) Do() (*LeaderboardConfiguration, error) {
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
	ret := &LeaderboardConfiguration{
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
	//   "description": "Insert a new leaderboard configuration in this application.",
	//   "httpMethod": "POST",
	//   "id": "gamesConfiguration.leaderboardConfigurations.insert",
	//   "parameterOrder": [
	//     "applicationId"
	//   ],
	//   "parameters": {
	//     "applicationId": {
	//       "description": "The application ID from the Google Play developer console.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "applications/{applicationId}/leaderboards",
	//   "request": {
	//     "$ref": "LeaderboardConfiguration"
	//   },
	//   "response": {
	//     "$ref": "LeaderboardConfiguration"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/androidpublisher"
	//   ]
	// }

}

// method id "gamesConfiguration.leaderboardConfigurations.list":

type LeaderboardConfigurationsListCall struct {
	s             *Service
	applicationId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: Returns a list of the leaderboard configurations in this
// application.
func (r *LeaderboardConfigurationsService) List(applicationId string) *LeaderboardConfigurationsListCall {
	c := &LeaderboardConfigurationsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.applicationId = applicationId
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of resource configurations to return in the response, used for
// paging. For any response, the actual number of resources returned may
// be less than the specified maxResults.
func (c *LeaderboardConfigurationsListCall) MaxResults(maxResults int64) *LeaderboardConfigurationsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The token returned
// by the previous request.
func (c *LeaderboardConfigurationsListCall) PageToken(pageToken string) *LeaderboardConfigurationsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LeaderboardConfigurationsListCall) Fields(s ...googleapi.Field) *LeaderboardConfigurationsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *LeaderboardConfigurationsListCall) IfNoneMatch(entityTag string) *LeaderboardConfigurationsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LeaderboardConfigurationsListCall) Context(ctx context.Context) *LeaderboardConfigurationsListCall {
	c.ctx_ = ctx
	return c
}

func (c *LeaderboardConfigurationsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "applications/{applicationId}/leaderboards")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"applicationId": c.applicationId,
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

// Do executes the "gamesConfiguration.leaderboardConfigurations.list" call.
// Exactly one of *LeaderboardConfigurationListResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *LeaderboardConfigurationListResponse.ServerResponse.Header or
// (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *LeaderboardConfigurationsListCall) Do() (*LeaderboardConfigurationListResponse, error) {
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
	ret := &LeaderboardConfigurationListResponse{
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
	//   "description": "Returns a list of the leaderboard configurations in this application.",
	//   "httpMethod": "GET",
	//   "id": "gamesConfiguration.leaderboardConfigurations.list",
	//   "parameterOrder": [
	//     "applicationId"
	//   ],
	//   "parameters": {
	//     "applicationId": {
	//       "description": "The application ID from the Google Play developer console.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of resource configurations to return in the response, used for paging. For any response, the actual number of resources returned may be less than the specified maxResults.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "200",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The token returned by the previous request.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "applications/{applicationId}/leaderboards",
	//   "response": {
	//     "$ref": "LeaderboardConfigurationListResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/androidpublisher"
	//   ]
	// }

}

// method id "gamesConfiguration.leaderboardConfigurations.patch":

type LeaderboardConfigurationsPatchCall struct {
	s                        *Service
	leaderboardId            string
	leaderboardconfiguration *LeaderboardConfiguration
	opt_                     map[string]interface{}
	ctx_                     context.Context
}

// Patch: Update the metadata of the leaderboard configuration with the
// given ID. This method supports patch semantics.
func (r *LeaderboardConfigurationsService) Patch(leaderboardId string, leaderboardconfiguration *LeaderboardConfiguration) *LeaderboardConfigurationsPatchCall {
	c := &LeaderboardConfigurationsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.leaderboardId = leaderboardId
	c.leaderboardconfiguration = leaderboardconfiguration
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LeaderboardConfigurationsPatchCall) Fields(s ...googleapi.Field) *LeaderboardConfigurationsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LeaderboardConfigurationsPatchCall) Context(ctx context.Context) *LeaderboardConfigurationsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *LeaderboardConfigurationsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.leaderboardconfiguration)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "leaderboards/{leaderboardId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"leaderboardId": c.leaderboardId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesConfiguration.leaderboardConfigurations.patch" call.
// Exactly one of *LeaderboardConfiguration or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *LeaderboardConfiguration.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *LeaderboardConfigurationsPatchCall) Do() (*LeaderboardConfiguration, error) {
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
	ret := &LeaderboardConfiguration{
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
	//   "description": "Update the metadata of the leaderboard configuration with the given ID. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "gamesConfiguration.leaderboardConfigurations.patch",
	//   "parameterOrder": [
	//     "leaderboardId"
	//   ],
	//   "parameters": {
	//     "leaderboardId": {
	//       "description": "The ID of the leaderboard.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "leaderboards/{leaderboardId}",
	//   "request": {
	//     "$ref": "LeaderboardConfiguration"
	//   },
	//   "response": {
	//     "$ref": "LeaderboardConfiguration"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/androidpublisher"
	//   ]
	// }

}

// method id "gamesConfiguration.leaderboardConfigurations.update":

type LeaderboardConfigurationsUpdateCall struct {
	s                        *Service
	leaderboardId            string
	leaderboardconfiguration *LeaderboardConfiguration
	opt_                     map[string]interface{}
	ctx_                     context.Context
}

// Update: Update the metadata of the leaderboard configuration with the
// given ID.
func (r *LeaderboardConfigurationsService) Update(leaderboardId string, leaderboardconfiguration *LeaderboardConfiguration) *LeaderboardConfigurationsUpdateCall {
	c := &LeaderboardConfigurationsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.leaderboardId = leaderboardId
	c.leaderboardconfiguration = leaderboardconfiguration
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *LeaderboardConfigurationsUpdateCall) Fields(s ...googleapi.Field) *LeaderboardConfigurationsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *LeaderboardConfigurationsUpdateCall) Context(ctx context.Context) *LeaderboardConfigurationsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *LeaderboardConfigurationsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.leaderboardconfiguration)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "leaderboards/{leaderboardId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"leaderboardId": c.leaderboardId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "gamesConfiguration.leaderboardConfigurations.update" call.
// Exactly one of *LeaderboardConfiguration or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *LeaderboardConfiguration.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *LeaderboardConfigurationsUpdateCall) Do() (*LeaderboardConfiguration, error) {
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
	ret := &LeaderboardConfiguration{
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
	//   "description": "Update the metadata of the leaderboard configuration with the given ID.",
	//   "httpMethod": "PUT",
	//   "id": "gamesConfiguration.leaderboardConfigurations.update",
	//   "parameterOrder": [
	//     "leaderboardId"
	//   ],
	//   "parameters": {
	//     "leaderboardId": {
	//       "description": "The ID of the leaderboard.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "leaderboards/{leaderboardId}",
	//   "request": {
	//     "$ref": "LeaderboardConfiguration"
	//   },
	//   "response": {
	//     "$ref": "LeaderboardConfiguration"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/androidpublisher"
	//   ]
	// }

}
