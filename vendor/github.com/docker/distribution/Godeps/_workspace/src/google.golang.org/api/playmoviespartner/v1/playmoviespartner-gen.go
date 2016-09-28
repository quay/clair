// Package playmoviespartner provides access to the Google Play Movies Partner API.
//
// See https://developers.google.com/playmoviespartner/
//
// Usage example:
//
//   import "google.golang.org/api/playmoviespartner/v1"
//   ...
//   playmoviespartnerService, err := playmoviespartner.New(oauthHttpClient)
package playmoviespartner // import "google.golang.org/api/playmoviespartner/v1"

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

const apiId = "playmoviespartner:v1"
const apiName = "playmoviespartner"
const apiVersion = "v1"
const basePath = "https://playmoviespartner.googleapis.com/"

// OAuth2 scopes used by this API.
const (
	// View the digital assets you publish on Google Play Movies and TV
	PlaymoviesPartnerReadonlyScope = "https://www.googleapis.com/auth/playmovies_partner.readonly"
)

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.Accounts = NewAccountsService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	Accounts *AccountsService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewAccountsService(s *Service) *AccountsService {
	rs := &AccountsService{s: s}
	rs.Avails = NewAccountsAvailsService(s)
	rs.ExperienceLocales = NewAccountsExperienceLocalesService(s)
	rs.Orders = NewAccountsOrdersService(s)
	rs.StoreInfos = NewAccountsStoreInfosService(s)
	return rs
}

type AccountsService struct {
	s *Service

	Avails *AccountsAvailsService

	ExperienceLocales *AccountsExperienceLocalesService

	Orders *AccountsOrdersService

	StoreInfos *AccountsStoreInfosService
}

func NewAccountsAvailsService(s *Service) *AccountsAvailsService {
	rs := &AccountsAvailsService{s: s}
	return rs
}

type AccountsAvailsService struct {
	s *Service
}

func NewAccountsExperienceLocalesService(s *Service) *AccountsExperienceLocalesService {
	rs := &AccountsExperienceLocalesService{s: s}
	return rs
}

type AccountsExperienceLocalesService struct {
	s *Service
}

func NewAccountsOrdersService(s *Service) *AccountsOrdersService {
	rs := &AccountsOrdersService{s: s}
	return rs
}

type AccountsOrdersService struct {
	s *Service
}

func NewAccountsStoreInfosService(s *Service) *AccountsStoreInfosService {
	rs := &AccountsStoreInfosService{s: s}
	rs.Country = NewAccountsStoreInfosCountryService(s)
	return rs
}

type AccountsStoreInfosService struct {
	s *Service

	Country *AccountsStoreInfosCountryService
}

func NewAccountsStoreInfosCountryService(s *Service) *AccountsStoreInfosCountryService {
	rs := &AccountsStoreInfosCountryService{s: s}
	return rs
}

type AccountsStoreInfosCountryService struct {
	s *Service
}

// Avail: An Avail describes the Availability Window of a specific Edit
// in a given country, which means the period Google is allowed to sell
// or rent the Edit. Avails are exposed in EMA format Version 1.6b
// (available at http://www.movielabs.com/md/avails/) Studios can see
// the Avails for the Titles they own. Post-production houses cannot see
// any Avails.
type Avail struct {
	// AltId: Other identifier referring to the Edit, as defined by partner.
	// Example: "GOOGLER_2006"
	AltId string `json:"altId,omitempty"`

	// CaptionExemption: Communicating an exempt category as defined by FCC
	// regulations. It is not required for non-US Avails. Example: "1"
	CaptionExemption string `json:"captionExemption,omitempty"`

	// CaptionIncluded: Communicating if caption file will be delivered.
	CaptionIncluded bool `json:"captionIncluded,omitempty"`

	// ContentId: Title Identifier. This should be the Title Level EIDR.
	// Example: "10.5240/1489-49A2-3956-4B2D-FE16-5".
	ContentId string `json:"contentId,omitempty"`

	// DisplayName: The name of the studio that owns the Edit referred in
	// the Avail. This is the equivalent of `studio_name` in other
	// resources, but it follows the EMA nomenclature. Example: "Google
	// Films".
	DisplayName string `json:"displayName,omitempty"`

	// EncodeId: Manifestation Identifier. This should be the Manifestation
	// Level EIDR. Example: "10.2340/1489-49A2-3956-4B2D-FE16-7"
	EncodeId string `json:"encodeId,omitempty"`

	// End: End of term in YYYY-MM-DD format in the timezone of the country
	// of the Avail. "Open" if no end date is available. Example:
	// "2019-02-17"
	End string `json:"end,omitempty"`

	// EpisodeAltId: Other identifier referring to the episode, as defined
	// by partner. Only available on TV avails. Example: "rs_googlers_s1_3".
	EpisodeAltId string `json:"episodeAltId,omitempty"`

	// EpisodeNumber: The number assigned to the episode within a season.
	// Only available on TV Avails. Example: "3".
	EpisodeNumber string `json:"episodeNumber,omitempty"`

	// EpisodeTitleInternalAlias: OPTIONAL.TV Only. Title used by involved
	// parties to refer to this episode. Only available on TV Avails.
	// Example: "Coding at Google".
	EpisodeTitleInternalAlias string `json:"episodeTitleInternalAlias,omitempty"`

	// FormatProfile: Indicates the format profile covered by the
	// transaction.
	//
	// Possible values:
	//   "FORMAT_PROFILE_UNSPECIFIED"
	//   "SD"
	//   "HD"
	FormatProfile string `json:"formatProfile,omitempty"`

	// LicenseType: Type of transaction.
	//
	// Possible values:
	//   "LICENSE_TYPE_UNSPECIFIED"
	//   "EST"
	//   "VOD"
	//   "SVOD"
	LicenseType string `json:"licenseType,omitempty"`

	// PphNames: Name of the post-production houses that manage the Avail.
	// Not part of EMA Specs.
	PphNames []string `json:"pphNames,omitempty"`

	// PriceType: Type of pricing that should be applied to this Avail based
	// on how the partner classify them. Example: "Tier", "WSP", "SRP", or
	// "Category".
	PriceType string `json:"priceType,omitempty"`

	// PriceValue: Value to be applied to the pricing type. Example: "4" or
	// "2.99"
	PriceValue string `json:"priceValue,omitempty"`

	// ProductId: Edit Identifier. This should be the Edit Level EIDR.
	// Example: "10.2340/1489-49A2-3956-4B2D-FE16-6"
	ProductId string `json:"productId,omitempty"`

	// RatingReason: Value representing the rating reason. Rating reasons
	// should be formatted as per [EMA ratings
	// spec](http://www.movielabs.com/md/ratings/) and comma-separated for
	// inclusion of multiple reasons. Example: "L, S, V"
	RatingReason string `json:"ratingReason,omitempty"`

	// RatingSystem: Rating system applied to the version of title within
	// territory of Avail. Rating systems should be formatted as per [EMA
	// ratings spec](http://www.movielabs.com/md/ratings/) Example: "MPAA"
	RatingSystem string `json:"ratingSystem,omitempty"`

	// RatingValue: Value representing the rating. Ratings should be
	// formatted as per http://www.movielabs.com/md/ratings/ Example: "PG"
	RatingValue string `json:"ratingValue,omitempty"`

	// ReleaseDate: Release date of the Title in earliest released
	// territory. Typically it is just the year, but it is free-form as per
	// EMA spec. Examples: "1979", "Oct 2014"
	ReleaseDate string `json:"releaseDate,omitempty"`

	// SeasonAltId: Other identifier referring to the season, as defined by
	// partner. Only available on TV avails. Example: "rs_googlers_s1".
	SeasonAltId string `json:"seasonAltId,omitempty"`

	// SeasonNumber: The number assigned to the season within a series. Only
	// available on TV Avails. Example: "1".
	SeasonNumber string `json:"seasonNumber,omitempty"`

	// SeasonTitleInternalAlias: Title used by involved parties to refer to
	// this season. Only available on TV Avails. Example: "Googlers, The".
	SeasonTitleInternalAlias string `json:"seasonTitleInternalAlias,omitempty"`

	// SeriesAltId: Other identifier referring to the series, as defined by
	// partner. Only available on TV avails. Example: "rs_googlers".
	SeriesAltId string `json:"seriesAltId,omitempty"`

	// SeriesTitleInternalAlias: Title used by involved parties to refer to
	// this series. Only available on TV Avails. Example: "Googlers, The".
	SeriesTitleInternalAlias string `json:"seriesTitleInternalAlias,omitempty"`

	// Start: Start of term in YYYY-MM-DD format in the timezone of the
	// country of the Avail. Example: "2013-05-14".
	Start string `json:"start,omitempty"`

	// StoreLanguage: Spoken language of the intended audience. Language
	// shall be encoded in accordance with RFC 5646. Example: "fr".
	StoreLanguage string `json:"storeLanguage,omitempty"`

	// SuppressionLiftDate: First date an Edit could be publically announced
	// as becoming available at a specific future date in territory of
	// Avail. *Not* the Avail start date or pre-order start date. Format is
	// YYYY-MM-DD. Only available for pre-orders. Example: "2012-12-10"
	SuppressionLiftDate string `json:"suppressionLiftDate,omitempty"`

	// Territory: ISO 3166-1 alpha-2 country code for the country or
	// territory of this Avail. For Avails, we use Territory in lieu of
	// Country to comply with EMA specifications. But please note that
	// Territory and Country identify the same thing. Example: "US".
	Territory string `json:"territory,omitempty"`

	// TitleInternalAlias: Title used by involved parties to refer to this
	// content. Example: "Googlers, The". Only available on Movie Avails.
	TitleInternalAlias string `json:"titleInternalAlias,omitempty"`

	// VideoId: Google-generated ID identifying the video linked to this
	// Avail, once delivered. Not part of EMA Specs. Example: 'gtry456_xc'
	VideoId string `json:"videoId,omitempty"`

	// WorkType: Work type as enumerated in EMA.
	//
	// Possible values:
	//   "TITLE_TYPE_UNSPECIFIED"
	//   "MOVIE"
	//   "SEASON"
	//   "EPISODE"
	WorkType string `json:"workType,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AltId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Avail) MarshalJSON() ([]byte, error) {
	type noMethod Avail
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ExperienceLocale: An ExperienceLocale tracks the fulfillment of a
// Title in a country using a specific language, when delivered using
// component-based delivery. For example, a Title in Switzerland might
// have 3 ExperienceLocales: they both share the same country ("CH"),
// but each has different languages ("de", "fr", and "it"). Each
// ExperienceLocale is uniquely identified by an `el_id`, which is
// generated by Google. Externally, an ExperienceLocale can also be
// identified by partners using its EIDR IDs, AltCutID or `custom_id`
// (when provided).
type ExperienceLocale struct {
	// AltCutId: Alternative Cut ID, sometimes available in lieu of the main
	// Edit-level EIDR ID. This is not an EIDR ID, but a Partner-provided
	// ID. Example: "206346_79838".
	AltCutId string `json:"altCutId,omitempty"`

	// ApprovedTime: Timestamp when the ExperienceLocale was approved.
	ApprovedTime string `json:"approvedTime,omitempty"`

	// ChannelId: YouTube Channel ID linked to the ExperienceLocale.
	// Example: "UCRG64darCZhb".
	ChannelId string `json:"channelId,omitempty"`

	// Country: Country where the ExperienceLocale is available, using the
	// "ISO 3166-1 alpha-2" format. Example: "US".
	Country string `json:"country,omitempty"`

	// CreatedTime: Timestamp when the ExperienceLocale was created.
	CreatedTime string `json:"createdTime,omitempty"`

	// CustomIds: List of custom IDs (defined by the partner) linked to this
	// ExperienceLocale. Example: "R86241"
	CustomIds []string `json:"customIds,omitempty"`

	// EarliestAvailStartTime: Timestamp of the earliest start date of the
	// Avails linked to this ExperienceLocale.
	EarliestAvailStartTime string `json:"earliestAvailStartTime,omitempty"`

	// EditLevelEidr: Edit-level EIDR ID. Example:
	// "10.5240/1489-49A2-3956-4B2D-FE16-6".
	EditLevelEidr string `json:"editLevelEidr,omitempty"`

	// ElId: ID internally generated by Google to uniquely identify a
	// ExperienceLocale. Example: 'KRZiVjY9h7t'
	ElId string `json:"elId,omitempty"`

	// InventoryId: InventoryID as defined in the EMA specs.
	InventoryId string `json:"inventoryId,omitempty"`

	// Language: Language of the ExperienceLocale, using the "BCP 47"
	// format. Examples: "en", "en-US", "es", "es-419".
	Language string `json:"language,omitempty"`

	// Name: Default Edit name, usually in the language of the country of
	// origin. Example: "Googlers, The".
	Name string `json:"name,omitempty"`

	// NormalizedPriority: A simpler representation of the priority.
	//
	// Possible values:
	//   "NORMALIZED_PRIORITY_UNSPECIFIED"
	//   "LOW_PRIORITY"
	//   "HIGH_PRIORITY"
	NormalizedPriority string `json:"normalizedPriority,omitempty"`

	// PlayableSequenceId: PlayableSequenceID as defined in the EMA specs.
	PlayableSequenceId string `json:"playableSequenceId,omitempty"`

	// PphNames: Name of the post-production houses that manage the
	// ExperienceLocale.
	PphNames []string `json:"pphNames,omitempty"`

	// PresentationId: PresentationID as defined in the EMA specs.
	PresentationId string `json:"presentationId,omitempty"`

	// Priority: ExperienceLocale priority, as defined by Google. The higher
	// the value, the higher the priority. Example: 90
	Priority float64 `json:"priority,omitempty"`

	// Status: High-level status of the ExperienceLocale.
	//
	// Possible values:
	//   "STATUS_UNSPECIFIED"
	//   "STATUS_APPROVED"
	//   "STATUS_FAILED"
	//   "STATUS_PROCESSING"
	//   "STATUS_UNFULFILLED"
	//   "STATUS_NOT_AVAILABLE"
	Status string `json:"status,omitempty"`

	// StudioName: Name of the studio that owns the ExperienceLocale.
	StudioName string `json:"studioName,omitempty"`

	// TitleLevelEidr: Title-level EIDR ID. Example:
	// "10.5240/1489-49A2-3956-4B2D-FE16-5".
	TitleLevelEidr string `json:"titleLevelEidr,omitempty"`

	// TrailerId: Trailer ID, as defined by Google, linked to the trailer
	// video in the ExperienceLocale. Example: 'gtry457_tr'.
	TrailerId string `json:"trailerId,omitempty"`

	// Type: Type of the Edit linked to the ExperienceLocale.
	//
	// Possible values:
	//   "TITLE_TYPE_UNSPECIFIED"
	//   "MOVIE"
	//   "SEASON"
	//   "EPISODE"
	Type string `json:"type,omitempty"`

	// VideoId: Video ID, as defined by Google, linked to the feature video
	// in the ExperienceLocale. Example: 'gtry456_xc'.
	VideoId string `json:"videoId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AltCutId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ExperienceLocale) MarshalJSON() ([]byte, error) {
	type noMethod ExperienceLocale
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ListAvailsResponse: Response to the 'ListAvails' method.
type ListAvailsResponse struct {
	// Avails: List of Avails that match the request criteria.
	Avails []*Avail `json:"avails,omitempty"`

	// NextPageToken: See _List methods rules_ for info about this field.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Avails") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ListAvailsResponse) MarshalJSON() ([]byte, error) {
	type noMethod ListAvailsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ListExperienceLocalesResponse: Response to the
// 'ListExperienceLocales' method.
type ListExperienceLocalesResponse struct {
	// ExperienceLocales: List of ExperienceLocales that match the request
	// criteria.
	ExperienceLocales []*ExperienceLocale `json:"experienceLocales,omitempty"`

	// NextPageToken: See _List methods rules_ for info about this field.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ExperienceLocales")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ListExperienceLocalesResponse) MarshalJSON() ([]byte, error) {
	type noMethod ListExperienceLocalesResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ListOrdersResponse: Response to the 'ListOrders' method.
type ListOrdersResponse struct {
	// NextPageToken: See _List methods rules_ for info about this field.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// Orders: List of Orders that match the request criteria.
	Orders []*Order `json:"orders,omitempty"`

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

func (s *ListOrdersResponse) MarshalJSON() ([]byte, error) {
	type noMethod ListOrdersResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ListStoreInfosResponse: Response to the 'ListStoreInfos' method.
type ListStoreInfosResponse struct {
	// NextPageToken: See 'List methods rules' for info about this field.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// StoreInfos: List of StoreInfos that match the request criteria.
	StoreInfos []*StoreInfo `json:"storeInfos,omitempty"`

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

func (s *ListStoreInfosResponse) MarshalJSON() ([]byte, error) {
	type noMethod ListStoreInfosResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Order: An Order tracks the fulfillment of an Edit when delivered
// using the legacy, non-component-based delivery. Each Order is
// uniquely identified by an `order_id`, which is generated by Google.
// Externally, Orders can also be identified by partners using its
// `custom_id` (when provided).
type Order struct {
	// ApprovedTime: Timestamp when the Order was approved.
	ApprovedTime string `json:"approvedTime,omitempty"`

	// ChannelId: YouTube Channel ID that should be used to fulfill the
	// Order. Example: "UCRG64darCZhb".
	ChannelId string `json:"channelId,omitempty"`

	// ChannelName: YouTube Channel Name that should be used to fulfill the
	// Order. Example: "Google_channel".
	ChannelName string `json:"channelName,omitempty"`

	// Countries: Countries where the Order is available, using the "ISO
	// 3166-1 alpha-2" format (example: "US").
	Countries []string `json:"countries,omitempty"`

	// CustomId: ID that can be used to externally identify an Order. This
	// ID is provided by partners when submitting the Avails. Example:
	// 'GOOGLER_2006'
	CustomId string `json:"customId,omitempty"`

	// EarliestAvailStartTime: Timestamp of the earliest start date of the
	// Avails linked to this Order.
	EarliestAvailStartTime string `json:"earliestAvailStartTime,omitempty"`

	// EpisodeName: Default Episode name, usually in the language of the
	// country of origin. Only available for TV Edits Example: "Googlers,
	// The - Pilot".
	EpisodeName string `json:"episodeName,omitempty"`

	// LegacyPriority: Legacy Order priority, as defined by Google. Example:
	// 'P0'
	LegacyPriority string `json:"legacyPriority,omitempty"`

	// Name: Default Edit name, usually in the language of the country of
	// origin. Example: "Googlers, The".
	Name string `json:"name,omitempty"`

	// NormalizedPriority: A simpler representation of the priority.
	//
	// Possible values:
	//   "NORMALIZED_PRIORITY_UNSPECIFIED"
	//   "LOW_PRIORITY"
	//   "HIGH_PRIORITY"
	NormalizedPriority string `json:"normalizedPriority,omitempty"`

	// OrderId: ID internally generated by Google to uniquely identify an
	// Order. Example: 'abcde12_x'
	OrderId string `json:"orderId,omitempty"`

	// OrderedTime: Timestamp when the Order was created.
	OrderedTime string `json:"orderedTime,omitempty"`

	// PphName: Name of the post-production house that manages the Edit
	// ordered.
	PphName string `json:"pphName,omitempty"`

	// Priority: Order priority, as defined by Google. The higher the value,
	// the higher the priority. Example: 90
	Priority float64 `json:"priority,omitempty"`

	// ReceivedTime: Timestamp when the Order was fulfilled.
	ReceivedTime string `json:"receivedTime,omitempty"`

	// RejectionNote: Field explaining why an Order has been rejected.
	// Example: "Trailer audio is 2ch mono, please re-deliver in stereo".
	RejectionNote string `json:"rejectionNote,omitempty"`

	// SeasonName: Default Season name, usually in the language of the
	// country of origin. Only available for TV Edits Example: "Googlers,
	// The - A Brave New World".
	SeasonName string `json:"seasonName,omitempty"`

	// ShowName: Default Show name, usually in the language of the country
	// of origin. Only available for TV Edits Example: "Googlers, The".
	ShowName string `json:"showName,omitempty"`

	// Status: High-level status of the order.
	//
	// Possible values:
	//   "STATUS_UNSPECIFIED"
	//   "STATUS_APPROVED"
	//   "STATUS_FAILED"
	//   "STATUS_PROCESSING"
	//   "STATUS_UNFULFILLED"
	//   "STATUS_NOT_AVAILABLE"
	Status string `json:"status,omitempty"`

	// StatusDetail: Detailed status of the order
	//
	// Possible values:
	//   "ORDER_STATUS_UNSPECIFIED"
	//   "ORDER_STATUS_QC_APPROVED"
	//   "ORDER_STATUS_QC_REJECTION"
	//   "ORDER_STATUS_INTERNAL_FIX"
	//   "ORDER_STATUS_OPEN_ORDER"
	//   "ORDER_STATUS_NOT_AVAILABLE"
	//   "ORDER_STATUS_AWAITING_REDELIVERY"
	//   "ORDER_STATUS_READY_FOR_QC"
	StatusDetail string `json:"statusDetail,omitempty"`

	// StudioName: Name of the studio that owns the Edit ordered.
	StudioName string `json:"studioName,omitempty"`

	// Type: Type of the Edit linked to the Order.
	//
	// Possible values:
	//   "TITLE_TYPE_UNSPECIFIED"
	//   "MOVIE"
	//   "SEASON"
	//   "EPISODE"
	Type string `json:"type,omitempty"`

	// VideoId: Google-generated ID identifying the video linked to this
	// Order, once delivered. Example: 'gtry456_xc'.
	VideoId string `json:"videoId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ApprovedTime") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Order) MarshalJSON() ([]byte, error) {
	type noMethod Order
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// StoreInfo: Information about a playable sequence (video) associated
// with an Edit and available at the Google Play Store. Internally, each
// StoreInfo is uniquely identified by a `video_id` and `country`.
// Externally, Title-level EIDR or Edit-level EIDR, if provided, can
// also be used to identify a specific title or edit in a country.
type StoreInfo struct {
	// AudioTracks: Audio tracks available for this Edit.
	AudioTracks []string `json:"audioTracks,omitempty"`

	// Country: Country where Edit is available in ISO 3166-1 alpha-2
	// country code. Example: "US".
	Country string `json:"country,omitempty"`

	// EditLevelEidr: Edit-level EIDR ID. Example:
	// "10.5240/1489-49A2-3956-4B2D-FE16-6".
	EditLevelEidr string `json:"editLevelEidr,omitempty"`

	// EpisodeNumber: The number assigned to the episode within a season.
	// Only available on TV Edits. Example: "1".
	EpisodeNumber string `json:"episodeNumber,omitempty"`

	// HasAudio51: Whether the Edit has a 5.1 channel audio track.
	HasAudio51 bool `json:"hasAudio51,omitempty"`

	// HasEstOffer: Whether the Edit has a EST offer.
	HasEstOffer bool `json:"hasEstOffer,omitempty"`

	// HasHdOffer: Whether the Edit has a HD offer.
	HasHdOffer bool `json:"hasHdOffer,omitempty"`

	// HasInfoCards: Whether the Edit has info cards.
	HasInfoCards bool `json:"hasInfoCards,omitempty"`

	// HasSdOffer: Whether the Edit has a SD offer.
	HasSdOffer bool `json:"hasSdOffer,omitempty"`

	// HasVodOffer: Whether the Edit has a VOD offer.
	HasVodOffer bool `json:"hasVodOffer,omitempty"`

	// LiveTime: Timestamp when the Edit went live on the Store.
	LiveTime string `json:"liveTime,omitempty"`

	// Mid: Knowledge Graph ID associated to this Edit, if available. This
	// ID links the Edit to its knowledge entity, externally accessible at
	// http://freebase.com. In the absense of Title EIDR or Edit EIDR, this
	// ID helps link together multiple Edits across countries. Example:
	// '/m/0ffx29'
	Mid string `json:"mid,omitempty"`

	// Name: Default Edit name, usually in the language of the country of
	// origin. Example: "Googlers, The".
	Name string `json:"name,omitempty"`

	// PphNames: Name of the post-production houses that manage the Edit.
	PphNames []string `json:"pphNames,omitempty"`

	// SeasonId: Google-generated ID identifying the season linked to the
	// Edit. Only available for TV Edits. Example: 'ster23ex'
	SeasonId string `json:"seasonId,omitempty"`

	// SeasonName: Default Season name, usually in the language of the
	// country of origin. Only available for TV Edits Example: "Googlers,
	// The - A Brave New World".
	SeasonName string `json:"seasonName,omitempty"`

	// SeasonNumber: The number assigned to the season within a show. Only
	// available on TV Edits. Example: "1".
	SeasonNumber string `json:"seasonNumber,omitempty"`

	// ShowId: Google-generated ID identifying the show linked to the Edit.
	// Only available for TV Edits. Example: 'et2hsue_x'
	ShowId string `json:"showId,omitempty"`

	// ShowName: Default Show name, usually in the language of the country
	// of origin. Only available for TV Edits Example: "Googlers, The".
	ShowName string `json:"showName,omitempty"`

	// StudioName: Name of the studio that owns the Edit ordered.
	StudioName string `json:"studioName,omitempty"`

	// Subtitles: Subtitles available for this Edit.
	Subtitles []string `json:"subtitles,omitempty"`

	// TitleLevelEidr: Title-level EIDR ID. Example:
	// "10.5240/1489-49A2-3956-4B2D-FE16-5".
	TitleLevelEidr string `json:"titleLevelEidr,omitempty"`

	// TrailerId: Google-generated ID identifying the trailer linked to the
	// Edit. Example: 'bhd_4e_cx'
	TrailerId string `json:"trailerId,omitempty"`

	// Type: Edit type, like Movie, Episode or Season.
	//
	// Possible values:
	//   "TITLE_TYPE_UNSPECIFIED"
	//   "MOVIE"
	//   "SEASON"
	//   "EPISODE"
	Type string `json:"type,omitempty"`

	// VideoId: Google-generated ID identifying the video linked to the
	// Edit. Example: 'gtry456_xc'
	VideoId string `json:"videoId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AudioTracks") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *StoreInfo) MarshalJSON() ([]byte, error) {
	type noMethod StoreInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "playmoviespartner.accounts.avails.list":

type AccountsAvailsListCall struct {
	s         *Service
	accountId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// List: List Avails owned or managed by the partner. See
// _Authentication and Authorization rules_ and _List methods rules_ for
// more information about this method.
func (r *AccountsAvailsService) List(accountId string) *AccountsAvailsListCall {
	c := &AccountsAvailsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	return c
}

// AltId sets the optional parameter "altId": Filter Avails that match a
// case-insensitive, partner-specific custom id.
func (c *AccountsAvailsListCall) AltId(altId string) *AccountsAvailsListCall {
	c.opt_["altId"] = altId
	return c
}

// PageSize sets the optional parameter "pageSize": See _List methods
// rules_ for info about this field.
func (c *AccountsAvailsListCall) PageSize(pageSize int64) *AccountsAvailsListCall {
	c.opt_["pageSize"] = pageSize
	return c
}

// PageToken sets the optional parameter "pageToken": See _List methods
// rules_ for info about this field.
func (c *AccountsAvailsListCall) PageToken(pageToken string) *AccountsAvailsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// PphNames sets the optional parameter "pphNames": See _List methods
// rules_ for info about this field.
func (c *AccountsAvailsListCall) PphNames(pphNames string) *AccountsAvailsListCall {
	c.opt_["pphNames"] = pphNames
	return c
}

// StudioNames sets the optional parameter "studioNames": See _List
// methods rules_ for info about this field.
func (c *AccountsAvailsListCall) StudioNames(studioNames string) *AccountsAvailsListCall {
	c.opt_["studioNames"] = studioNames
	return c
}

// Territories sets the optional parameter "territories": Filter Avails
// that match (case-insensitive) any of the given country codes, using
// the "ISO 3166-1 alpha-2" format (examples: "US", "us", "Us").
func (c *AccountsAvailsListCall) Territories(territories string) *AccountsAvailsListCall {
	c.opt_["territories"] = territories
	return c
}

// Title sets the optional parameter "title": Filter Avails that match a
// case-insensitive substring of the default Title name.
func (c *AccountsAvailsListCall) Title(title string) *AccountsAvailsListCall {
	c.opt_["title"] = title
	return c
}

// VideoIds sets the optional parameter "videoIds": Filter Avails that
// match any of the given `video_id`s.
func (c *AccountsAvailsListCall) VideoIds(videoIds string) *AccountsAvailsListCall {
	c.opt_["videoIds"] = videoIds
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AccountsAvailsListCall) Fields(s ...googleapi.Field) *AccountsAvailsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AccountsAvailsListCall) IfNoneMatch(entityTag string) *AccountsAvailsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AccountsAvailsListCall) Context(ctx context.Context) *AccountsAvailsListCall {
	c.ctx_ = ctx
	return c
}

func (c *AccountsAvailsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["altId"]; ok {
		params.Set("altId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageSize"]; ok {
		params.Set("pageSize", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pphNames"]; ok {
		params.Set("pphNames", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["studioNames"]; ok {
		params.Set("studioNames", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["territories"]; ok {
		params.Set("territories", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["title"]; ok {
		params.Set("title", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoIds"]; ok {
		params.Set("videoIds", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/accounts/{accountId}/avails")
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

// Do executes the "playmoviespartner.accounts.avails.list" call.
// Exactly one of *ListAvailsResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ListAvailsResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AccountsAvailsListCall) Do() (*ListAvailsResponse, error) {
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
	ret := &ListAvailsResponse{
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
	//   "description": "List Avails owned or managed by the partner. See _Authentication and Authorization rules_ and _List methods rules_ for more information about this method.",
	//   "httpMethod": "GET",
	//   "id": "playmoviespartner.accounts.avails.list",
	//   "parameterOrder": [
	//     "accountId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "REQUIRED. See _General rules_ for more information about this field.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "altId": {
	//       "description": "Filter Avails that match a case-insensitive, partner-specific custom id.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageSize": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pphNames": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "studioNames": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "territories": {
	//       "description": "Filter Avails that match (case-insensitive) any of the given country codes, using the \"ISO 3166-1 alpha-2\" format (examples: \"US\", \"us\", \"Us\").",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "title": {
	//       "description": "Filter Avails that match a case-insensitive substring of the default Title name.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoIds": {
	//       "description": "Filter Avails that match any of the given `video_id`s.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/accounts/{accountId}/avails",
	//   "response": {
	//     "$ref": "ListAvailsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/playmovies_partner.readonly"
	//   ]
	// }

}

// method id "playmoviespartner.accounts.experienceLocales.get":

type AccountsExperienceLocalesGetCall struct {
	s         *Service
	accountId string
	elId      string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Get an ExperienceLocale given its id. See _Authentication and
// Authorization rules_ and _Get methods rules_ for more information
// about this method.
func (r *AccountsExperienceLocalesService) Get(accountId string, elId string) *AccountsExperienceLocalesGetCall {
	c := &AccountsExperienceLocalesGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.elId = elId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AccountsExperienceLocalesGetCall) Fields(s ...googleapi.Field) *AccountsExperienceLocalesGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AccountsExperienceLocalesGetCall) IfNoneMatch(entityTag string) *AccountsExperienceLocalesGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AccountsExperienceLocalesGetCall) Context(ctx context.Context) *AccountsExperienceLocalesGetCall {
	c.ctx_ = ctx
	return c
}

func (c *AccountsExperienceLocalesGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/accounts/{accountId}/experienceLocales/{elId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId": c.accountId,
		"elId":      c.elId,
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

// Do executes the "playmoviespartner.accounts.experienceLocales.get" call.
// Exactly one of *ExperienceLocale or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ExperienceLocale.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AccountsExperienceLocalesGetCall) Do() (*ExperienceLocale, error) {
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
	ret := &ExperienceLocale{
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
	//   "description": "Get an ExperienceLocale given its id. See _Authentication and Authorization rules_ and _Get methods rules_ for more information about this method.",
	//   "httpMethod": "GET",
	//   "id": "playmoviespartner.accounts.experienceLocales.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "elId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "REQUIRED. See _General rules_ for more information about this field.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "elId": {
	//       "description": "REQUIRED. ExperienceLocale ID, as defined by Google.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/accounts/{accountId}/experienceLocales/{elId}",
	//   "response": {
	//     "$ref": "ExperienceLocale"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/playmovies_partner.readonly"
	//   ]
	// }

}

// method id "playmoviespartner.accounts.experienceLocales.list":

type AccountsExperienceLocalesListCall struct {
	s         *Service
	accountId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// List: List ExperienceLocales owned or managed by the partner. See
// _Authentication and Authorization rules_ and _List methods rules_ for
// more information about this method.
func (r *AccountsExperienceLocalesService) List(accountId string) *AccountsExperienceLocalesListCall {
	c := &AccountsExperienceLocalesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	return c
}

// AltCutId sets the optional parameter "altCutId": Filter
// ExperienceLocales that match a case-insensitive, partner-specific
// Alternative Cut ID.
func (c *AccountsExperienceLocalesListCall) AltCutId(altCutId string) *AccountsExperienceLocalesListCall {
	c.opt_["altCutId"] = altCutId
	return c
}

// CustomId sets the optional parameter "customId": Filter
// ExperienceLocales that match a case-insensitive, partner-specific
// custom id.
func (c *AccountsExperienceLocalesListCall) CustomId(customId string) *AccountsExperienceLocalesListCall {
	c.opt_["customId"] = customId
	return c
}

// EditLevelEidr sets the optional parameter "editLevelEidr": Filter
// ExperienceLocales that match a given edit-level EIDR.
func (c *AccountsExperienceLocalesListCall) EditLevelEidr(editLevelEidr string) *AccountsExperienceLocalesListCall {
	c.opt_["editLevelEidr"] = editLevelEidr
	return c
}

// PageSize sets the optional parameter "pageSize": See _List methods
// rules_ for info about this field.
func (c *AccountsExperienceLocalesListCall) PageSize(pageSize int64) *AccountsExperienceLocalesListCall {
	c.opt_["pageSize"] = pageSize
	return c
}

// PageToken sets the optional parameter "pageToken": See _List methods
// rules_ for info about this field.
func (c *AccountsExperienceLocalesListCall) PageToken(pageToken string) *AccountsExperienceLocalesListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// PphNames sets the optional parameter "pphNames": See _List methods
// rules_ for info about this field.
func (c *AccountsExperienceLocalesListCall) PphNames(pphNames string) *AccountsExperienceLocalesListCall {
	c.opt_["pphNames"] = pphNames
	return c
}

// Status sets the optional parameter "status": Filter ExperienceLocales
// that match one of the given status.
//
// Possible values:
//   "STATUS_UNSPECIFIED"
//   "STATUS_APPROVED"
//   "STATUS_FAILED"
//   "STATUS_PROCESSING"
//   "STATUS_UNFULFILLED"
//   "STATUS_NOT_AVAILABLE"
func (c *AccountsExperienceLocalesListCall) Status(status string) *AccountsExperienceLocalesListCall {
	c.opt_["status"] = status
	return c
}

// StudioNames sets the optional parameter "studioNames": See _List
// methods rules_ for info about this field.
func (c *AccountsExperienceLocalesListCall) StudioNames(studioNames string) *AccountsExperienceLocalesListCall {
	c.opt_["studioNames"] = studioNames
	return c
}

// TitleLevelEidr sets the optional parameter "titleLevelEidr": Filter
// ExperienceLocales that match a given title-level EIDR.
func (c *AccountsExperienceLocalesListCall) TitleLevelEidr(titleLevelEidr string) *AccountsExperienceLocalesListCall {
	c.opt_["titleLevelEidr"] = titleLevelEidr
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AccountsExperienceLocalesListCall) Fields(s ...googleapi.Field) *AccountsExperienceLocalesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AccountsExperienceLocalesListCall) IfNoneMatch(entityTag string) *AccountsExperienceLocalesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AccountsExperienceLocalesListCall) Context(ctx context.Context) *AccountsExperienceLocalesListCall {
	c.ctx_ = ctx
	return c
}

func (c *AccountsExperienceLocalesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["altCutId"]; ok {
		params.Set("altCutId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["customId"]; ok {
		params.Set("customId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["editLevelEidr"]; ok {
		params.Set("editLevelEidr", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageSize"]; ok {
		params.Set("pageSize", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pphNames"]; ok {
		params.Set("pphNames", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["status"]; ok {
		params.Set("status", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["studioNames"]; ok {
		params.Set("studioNames", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["titleLevelEidr"]; ok {
		params.Set("titleLevelEidr", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/accounts/{accountId}/experienceLocales")
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

// Do executes the "playmoviespartner.accounts.experienceLocales.list" call.
// Exactly one of *ListExperienceLocalesResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *ListExperienceLocalesResponse.ServerResponse.Header or (if a
// response was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AccountsExperienceLocalesListCall) Do() (*ListExperienceLocalesResponse, error) {
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
	ret := &ListExperienceLocalesResponse{
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
	//   "description": "List ExperienceLocales owned or managed by the partner. See _Authentication and Authorization rules_ and _List methods rules_ for more information about this method.",
	//   "httpMethod": "GET",
	//   "id": "playmoviespartner.accounts.experienceLocales.list",
	//   "parameterOrder": [
	//     "accountId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "REQUIRED. See _General rules_ for more information about this field.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "altCutId": {
	//       "description": "Filter ExperienceLocales that match a case-insensitive, partner-specific Alternative Cut ID.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "customId": {
	//       "description": "Filter ExperienceLocales that match a case-insensitive, partner-specific custom id.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "editLevelEidr": {
	//       "description": "Filter ExperienceLocales that match a given edit-level EIDR.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageSize": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pphNames": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "status": {
	//       "description": "Filter ExperienceLocales that match one of the given status.",
	//       "enum": [
	//         "STATUS_UNSPECIFIED",
	//         "STATUS_APPROVED",
	//         "STATUS_FAILED",
	//         "STATUS_PROCESSING",
	//         "STATUS_UNFULFILLED",
	//         "STATUS_NOT_AVAILABLE"
	//       ],
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "studioNames": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "titleLevelEidr": {
	//       "description": "Filter ExperienceLocales that match a given title-level EIDR.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/accounts/{accountId}/experienceLocales",
	//   "response": {
	//     "$ref": "ListExperienceLocalesResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/playmovies_partner.readonly"
	//   ]
	// }

}

// method id "playmoviespartner.accounts.orders.get":

type AccountsOrdersGetCall struct {
	s         *Service
	accountId string
	orderId   string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Get an Order given its id. See _Authentication and Authorization
// rules_ and _Get methods rules_ for more information about this
// method.
func (r *AccountsOrdersService) Get(accountId string, orderId string) *AccountsOrdersGetCall {
	c := &AccountsOrdersGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.orderId = orderId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AccountsOrdersGetCall) Fields(s ...googleapi.Field) *AccountsOrdersGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AccountsOrdersGetCall) IfNoneMatch(entityTag string) *AccountsOrdersGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AccountsOrdersGetCall) Context(ctx context.Context) *AccountsOrdersGetCall {
	c.ctx_ = ctx
	return c
}

func (c *AccountsOrdersGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/accounts/{accountId}/orders/{orderId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId": c.accountId,
		"orderId":   c.orderId,
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

// Do executes the "playmoviespartner.accounts.orders.get" call.
// Exactly one of *Order or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Order.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *AccountsOrdersGetCall) Do() (*Order, error) {
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
	ret := &Order{
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
	//   "description": "Get an Order given its id. See _Authentication and Authorization rules_ and _Get methods rules_ for more information about this method.",
	//   "httpMethod": "GET",
	//   "id": "playmoviespartner.accounts.orders.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "orderId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "REQUIRED. See _General rules_ for more information about this field.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "orderId": {
	//       "description": "REQUIRED. Order ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/accounts/{accountId}/orders/{orderId}",
	//   "response": {
	//     "$ref": "Order"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/playmovies_partner.readonly"
	//   ]
	// }

}

// method id "playmoviespartner.accounts.orders.list":

type AccountsOrdersListCall struct {
	s         *Service
	accountId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// List: List Orders owned or managed by the partner. See
// _Authentication and Authorization rules_ and _List methods rules_ for
// more information about this method.
func (r *AccountsOrdersService) List(accountId string) *AccountsOrdersListCall {
	c := &AccountsOrdersListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	return c
}

// CustomId sets the optional parameter "customId": Filter Orders that
// match a case-insensitive, partner-specific custom id.
func (c *AccountsOrdersListCall) CustomId(customId string) *AccountsOrdersListCall {
	c.opt_["customId"] = customId
	return c
}

// Name sets the optional parameter "name": Filter Orders that match a
// title name (case-insensitive, sub-string match).
func (c *AccountsOrdersListCall) Name(name string) *AccountsOrdersListCall {
	c.opt_["name"] = name
	return c
}

// PageSize sets the optional parameter "pageSize": See _List methods
// rules_ for info about this field.
func (c *AccountsOrdersListCall) PageSize(pageSize int64) *AccountsOrdersListCall {
	c.opt_["pageSize"] = pageSize
	return c
}

// PageToken sets the optional parameter "pageToken": See _List methods
// rules_ for info about this field.
func (c *AccountsOrdersListCall) PageToken(pageToken string) *AccountsOrdersListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// PphNames sets the optional parameter "pphNames": See _List methods
// rules_ for info about this field.
func (c *AccountsOrdersListCall) PphNames(pphNames string) *AccountsOrdersListCall {
	c.opt_["pphNames"] = pphNames
	return c
}

// Status sets the optional parameter "status": Filter Orders that match
// one of the given status.
//
// Possible values:
//   "STATUS_UNSPECIFIED"
//   "STATUS_APPROVED"
//   "STATUS_FAILED"
//   "STATUS_PROCESSING"
//   "STATUS_UNFULFILLED"
//   "STATUS_NOT_AVAILABLE"
func (c *AccountsOrdersListCall) Status(status string) *AccountsOrdersListCall {
	c.opt_["status"] = status
	return c
}

// StudioNames sets the optional parameter "studioNames": See _List
// methods rules_ for info about this field.
func (c *AccountsOrdersListCall) StudioNames(studioNames string) *AccountsOrdersListCall {
	c.opt_["studioNames"] = studioNames
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AccountsOrdersListCall) Fields(s ...googleapi.Field) *AccountsOrdersListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AccountsOrdersListCall) IfNoneMatch(entityTag string) *AccountsOrdersListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AccountsOrdersListCall) Context(ctx context.Context) *AccountsOrdersListCall {
	c.ctx_ = ctx
	return c
}

func (c *AccountsOrdersListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["customId"]; ok {
		params.Set("customId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["name"]; ok {
		params.Set("name", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageSize"]; ok {
		params.Set("pageSize", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pphNames"]; ok {
		params.Set("pphNames", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["status"]; ok {
		params.Set("status", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["studioNames"]; ok {
		params.Set("studioNames", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/accounts/{accountId}/orders")
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

// Do executes the "playmoviespartner.accounts.orders.list" call.
// Exactly one of *ListOrdersResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ListOrdersResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AccountsOrdersListCall) Do() (*ListOrdersResponse, error) {
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
	ret := &ListOrdersResponse{
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
	//   "description": "List Orders owned or managed by the partner. See _Authentication and Authorization rules_ and _List methods rules_ for more information about this method.",
	//   "httpMethod": "GET",
	//   "id": "playmoviespartner.accounts.orders.list",
	//   "parameterOrder": [
	//     "accountId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "REQUIRED. See _General rules_ for more information about this field.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "customId": {
	//       "description": "Filter Orders that match a case-insensitive, partner-specific custom id.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "name": {
	//       "description": "Filter Orders that match a title name (case-insensitive, sub-string match).",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageSize": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pphNames": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "status": {
	//       "description": "Filter Orders that match one of the given status.",
	//       "enum": [
	//         "STATUS_UNSPECIFIED",
	//         "STATUS_APPROVED",
	//         "STATUS_FAILED",
	//         "STATUS_PROCESSING",
	//         "STATUS_UNFULFILLED",
	//         "STATUS_NOT_AVAILABLE"
	//       ],
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "studioNames": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/accounts/{accountId}/orders",
	//   "response": {
	//     "$ref": "ListOrdersResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/playmovies_partner.readonly"
	//   ]
	// }

}

// method id "playmoviespartner.accounts.storeInfos.list":

type AccountsStoreInfosListCall struct {
	s         *Service
	accountId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// List: List StoreInfos owned or managed by the partner. See
// _Authentication and Authorization rules_ and _List methods rules_ for
// more information about this method.
func (r *AccountsStoreInfosService) List(accountId string) *AccountsStoreInfosListCall {
	c := &AccountsStoreInfosListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	return c
}

// Countries sets the optional parameter "countries": Filter StoreInfos
// that match (case-insensitive) any of the given country codes, using
// the "ISO 3166-1 alpha-2" format (examples: "US", "us", "Us").
func (c *AccountsStoreInfosListCall) Countries(countries string) *AccountsStoreInfosListCall {
	c.opt_["countries"] = countries
	return c
}

// Name sets the optional parameter "name": Filter StoreInfos that match
// a case-insensitive substring of the default name.
func (c *AccountsStoreInfosListCall) Name(name string) *AccountsStoreInfosListCall {
	c.opt_["name"] = name
	return c
}

// PageSize sets the optional parameter "pageSize": See _List methods
// rules_ for info about this field.
func (c *AccountsStoreInfosListCall) PageSize(pageSize int64) *AccountsStoreInfosListCall {
	c.opt_["pageSize"] = pageSize
	return c
}

// PageToken sets the optional parameter "pageToken": See _List methods
// rules_ for info about this field.
func (c *AccountsStoreInfosListCall) PageToken(pageToken string) *AccountsStoreInfosListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// PphNames sets the optional parameter "pphNames": See _List methods
// rules_ for info about this field.
func (c *AccountsStoreInfosListCall) PphNames(pphNames string) *AccountsStoreInfosListCall {
	c.opt_["pphNames"] = pphNames
	return c
}

// StudioNames sets the optional parameter "studioNames": See _List
// methods rules_ for info about this field.
func (c *AccountsStoreInfosListCall) StudioNames(studioNames string) *AccountsStoreInfosListCall {
	c.opt_["studioNames"] = studioNames
	return c
}

// VideoId sets the optional parameter "videoId": Filter StoreInfos that
// match a given `video_id`. NOTE: this field is deprecated and will be
// removed on V2; `video_ids` should be used instead.
func (c *AccountsStoreInfosListCall) VideoId(videoId string) *AccountsStoreInfosListCall {
	c.opt_["videoId"] = videoId
	return c
}

// VideoIds sets the optional parameter "videoIds": Filter StoreInfos
// that match any of the given `video_id`s.
func (c *AccountsStoreInfosListCall) VideoIds(videoIds string) *AccountsStoreInfosListCall {
	c.opt_["videoIds"] = videoIds
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AccountsStoreInfosListCall) Fields(s ...googleapi.Field) *AccountsStoreInfosListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AccountsStoreInfosListCall) IfNoneMatch(entityTag string) *AccountsStoreInfosListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AccountsStoreInfosListCall) Context(ctx context.Context) *AccountsStoreInfosListCall {
	c.ctx_ = ctx
	return c
}

func (c *AccountsStoreInfosListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["countries"]; ok {
		params.Set("countries", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["name"]; ok {
		params.Set("name", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageSize"]; ok {
		params.Set("pageSize", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pphNames"]; ok {
		params.Set("pphNames", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["studioNames"]; ok {
		params.Set("studioNames", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoId"]; ok {
		params.Set("videoId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["videoIds"]; ok {
		params.Set("videoIds", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/accounts/{accountId}/storeInfos")
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

// Do executes the "playmoviespartner.accounts.storeInfos.list" call.
// Exactly one of *ListStoreInfosResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ListStoreInfosResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AccountsStoreInfosListCall) Do() (*ListStoreInfosResponse, error) {
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
	ret := &ListStoreInfosResponse{
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
	//   "description": "List StoreInfos owned or managed by the partner. See _Authentication and Authorization rules_ and _List methods rules_ for more information about this method.",
	//   "httpMethod": "GET",
	//   "id": "playmoviespartner.accounts.storeInfos.list",
	//   "parameterOrder": [
	//     "accountId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "REQUIRED. See _General rules_ for more information about this field.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "countries": {
	//       "description": "Filter StoreInfos that match (case-insensitive) any of the given country codes, using the \"ISO 3166-1 alpha-2\" format (examples: \"US\", \"us\", \"Us\").",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "name": {
	//       "description": "Filter StoreInfos that match a case-insensitive substring of the default name.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageSize": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pphNames": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "studioNames": {
	//       "description": "See _List methods rules_ for info about this field.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "videoId": {
	//       "description": "Filter StoreInfos that match a given `video_id`. NOTE: this field is deprecated and will be removed on V2; `video_ids` should be used instead.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "videoIds": {
	//       "description": "Filter StoreInfos that match any of the given `video_id`s.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/accounts/{accountId}/storeInfos",
	//   "response": {
	//     "$ref": "ListStoreInfosResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/playmovies_partner.readonly"
	//   ]
	// }

}

// method id "playmoviespartner.accounts.storeInfos.country.get":

type AccountsStoreInfosCountryGetCall struct {
	s         *Service
	accountId string
	videoId   string
	country   string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Get a StoreInfo given its video id and country. See
// _Authentication and Authorization rules_ and _Get methods rules_ for
// more information about this method.
func (r *AccountsStoreInfosCountryService) Get(accountId string, videoId string, country string) *AccountsStoreInfosCountryGetCall {
	c := &AccountsStoreInfosCountryGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.videoId = videoId
	c.country = country
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AccountsStoreInfosCountryGetCall) Fields(s ...googleapi.Field) *AccountsStoreInfosCountryGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AccountsStoreInfosCountryGetCall) IfNoneMatch(entityTag string) *AccountsStoreInfosCountryGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AccountsStoreInfosCountryGetCall) Context(ctx context.Context) *AccountsStoreInfosCountryGetCall {
	c.ctx_ = ctx
	return c
}

func (c *AccountsStoreInfosCountryGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/accounts/{accountId}/storeInfos/{videoId}/country/{country}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId": c.accountId,
		"videoId":   c.videoId,
		"country":   c.country,
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

// Do executes the "playmoviespartner.accounts.storeInfos.country.get" call.
// Exactly one of *StoreInfo or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *StoreInfo.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *AccountsStoreInfosCountryGetCall) Do() (*StoreInfo, error) {
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
	ret := &StoreInfo{
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
	//   "description": "Get a StoreInfo given its video id and country. See _Authentication and Authorization rules_ and _Get methods rules_ for more information about this method.",
	//   "httpMethod": "GET",
	//   "id": "playmoviespartner.accounts.storeInfos.country.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "videoId",
	//     "country"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "REQUIRED. See _General rules_ for more information about this field.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "country": {
	//       "description": "REQUIRED. Edit country.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "videoId": {
	//       "description": "REQUIRED. Video ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/accounts/{accountId}/storeInfos/{videoId}/country/{country}",
	//   "response": {
	//     "$ref": "StoreInfo"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/playmovies_partner.readonly"
	//   ]
	// }

}
