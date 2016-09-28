// Package adexchangeseller provides access to the Ad Exchange Seller API.
//
// See https://developers.google.com/ad-exchange/seller-rest/
//
// Usage example:
//
//   import "google.golang.org/api/adexchangeseller/v1.1"
//   ...
//   adexchangesellerService, err := adexchangeseller.New(oauthHttpClient)
package adexchangeseller // import "google.golang.org/api/adexchangeseller/v1.1"

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

const apiId = "adexchangeseller:v1.1"
const apiName = "adexchangeseller"
const apiVersion = "v1.1"
const basePath = "https://www.googleapis.com/adexchangeseller/v1.1/"

// OAuth2 scopes used by this API.
const (
	// View and manage your Ad Exchange data
	AdexchangeSellerScope = "https://www.googleapis.com/auth/adexchange.seller"

	// View your Ad Exchange data
	AdexchangeSellerReadonlyScope = "https://www.googleapis.com/auth/adexchange.seller.readonly"
)

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.Accounts = NewAccountsService(s)
	s.Adclients = NewAdclientsService(s)
	s.Adunits = NewAdunitsService(s)
	s.Alerts = NewAlertsService(s)
	s.Customchannels = NewCustomchannelsService(s)
	s.Metadata = NewMetadataService(s)
	s.Preferreddeals = NewPreferreddealsService(s)
	s.Reports = NewReportsService(s)
	s.Urlchannels = NewUrlchannelsService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	Accounts *AccountsService

	Adclients *AdclientsService

	Adunits *AdunitsService

	Alerts *AlertsService

	Customchannels *CustomchannelsService

	Metadata *MetadataService

	Preferreddeals *PreferreddealsService

	Reports *ReportsService

	Urlchannels *UrlchannelsService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewAccountsService(s *Service) *AccountsService {
	rs := &AccountsService{s: s}
	return rs
}

type AccountsService struct {
	s *Service
}

func NewAdclientsService(s *Service) *AdclientsService {
	rs := &AdclientsService{s: s}
	return rs
}

type AdclientsService struct {
	s *Service
}

func NewAdunitsService(s *Service) *AdunitsService {
	rs := &AdunitsService{s: s}
	rs.Customchannels = NewAdunitsCustomchannelsService(s)
	return rs
}

type AdunitsService struct {
	s *Service

	Customchannels *AdunitsCustomchannelsService
}

func NewAdunitsCustomchannelsService(s *Service) *AdunitsCustomchannelsService {
	rs := &AdunitsCustomchannelsService{s: s}
	return rs
}

type AdunitsCustomchannelsService struct {
	s *Service
}

func NewAlertsService(s *Service) *AlertsService {
	rs := &AlertsService{s: s}
	return rs
}

type AlertsService struct {
	s *Service
}

func NewCustomchannelsService(s *Service) *CustomchannelsService {
	rs := &CustomchannelsService{s: s}
	rs.Adunits = NewCustomchannelsAdunitsService(s)
	return rs
}

type CustomchannelsService struct {
	s *Service

	Adunits *CustomchannelsAdunitsService
}

func NewCustomchannelsAdunitsService(s *Service) *CustomchannelsAdunitsService {
	rs := &CustomchannelsAdunitsService{s: s}
	return rs
}

type CustomchannelsAdunitsService struct {
	s *Service
}

func NewMetadataService(s *Service) *MetadataService {
	rs := &MetadataService{s: s}
	rs.Dimensions = NewMetadataDimensionsService(s)
	rs.Metrics = NewMetadataMetricsService(s)
	return rs
}

type MetadataService struct {
	s *Service

	Dimensions *MetadataDimensionsService

	Metrics *MetadataMetricsService
}

func NewMetadataDimensionsService(s *Service) *MetadataDimensionsService {
	rs := &MetadataDimensionsService{s: s}
	return rs
}

type MetadataDimensionsService struct {
	s *Service
}

func NewMetadataMetricsService(s *Service) *MetadataMetricsService {
	rs := &MetadataMetricsService{s: s}
	return rs
}

type MetadataMetricsService struct {
	s *Service
}

func NewPreferreddealsService(s *Service) *PreferreddealsService {
	rs := &PreferreddealsService{s: s}
	return rs
}

type PreferreddealsService struct {
	s *Service
}

func NewReportsService(s *Service) *ReportsService {
	rs := &ReportsService{s: s}
	rs.Saved = NewReportsSavedService(s)
	return rs
}

type ReportsService struct {
	s *Service

	Saved *ReportsSavedService
}

func NewReportsSavedService(s *Service) *ReportsSavedService {
	rs := &ReportsSavedService{s: s}
	return rs
}

type ReportsSavedService struct {
	s *Service
}

func NewUrlchannelsService(s *Service) *UrlchannelsService {
	rs := &UrlchannelsService{s: s}
	return rs
}

type UrlchannelsService struct {
	s *Service
}

type Account struct {
	// Id: Unique identifier of this account.
	Id string `json:"id,omitempty"`

	// Kind: Kind of resource this is, in this case
	// adexchangeseller#account.
	Kind string `json:"kind,omitempty"`

	// Name: Name of this account.
	Name string `json:"name,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Account) MarshalJSON() ([]byte, error) {
	type noMethod Account
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type AdClient struct {
	// ArcOptIn: Whether this ad client is opted in to ARC.
	ArcOptIn bool `json:"arcOptIn,omitempty"`

	// Id: Unique identifier of this ad client.
	Id string `json:"id,omitempty"`

	// Kind: Kind of resource this is, in this case
	// adexchangeseller#adClient.
	Kind string `json:"kind,omitempty"`

	// ProductCode: This ad client's product code, which corresponds to the
	// PRODUCT_CODE report dimension.
	ProductCode string `json:"productCode,omitempty"`

	// SupportsReporting: Whether this ad client supports being reported on.
	SupportsReporting bool `json:"supportsReporting,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ArcOptIn") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AdClient) MarshalJSON() ([]byte, error) {
	type noMethod AdClient
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type AdClients struct {
	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Items: The ad clients returned in this list response.
	Items []*AdClient `json:"items,omitempty"`

	// Kind: Kind of list this is, in this case adexchangeseller#adClients.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: Continuation token used to page through ad clients. To
	// retrieve the next page of results, set the next request's "pageToken"
	// value to this.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Etag") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AdClients) MarshalJSON() ([]byte, error) {
	type noMethod AdClients
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type AdUnit struct {
	// Code: Identity code of this ad unit, not necessarily unique across ad
	// clients.
	Code string `json:"code,omitempty"`

	// Id: Unique identifier of this ad unit. This should be considered an
	// opaque identifier; it is not safe to rely on it being in any
	// particular format.
	Id string `json:"id,omitempty"`

	// Kind: Kind of resource this is, in this case adexchangeseller#adUnit.
	Kind string `json:"kind,omitempty"`

	// Name: Name of this ad unit.
	Name string `json:"name,omitempty"`

	// Status: Status of this ad unit. Possible values are:
	// NEW: Indicates that the ad unit was created within the last seven
	// days and does not yet have any activity associated with it.
	//
	// ACTIVE: Indicates that there has been activity on this ad unit in the
	// last seven days.
	//
	// INACTIVE: Indicates that there has been no activity on this ad unit
	// in the last seven days.
	Status string `json:"status,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Code") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AdUnit) MarshalJSON() ([]byte, error) {
	type noMethod AdUnit
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type AdUnits struct {
	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Items: The ad units returned in this list response.
	Items []*AdUnit `json:"items,omitempty"`

	// Kind: Kind of list this is, in this case adexchangeseller#adUnits.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: Continuation token used to page through ad units. To
	// retrieve the next page of results, set the next request's "pageToken"
	// value to this.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Etag") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AdUnits) MarshalJSON() ([]byte, error) {
	type noMethod AdUnits
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type Alert struct {
	// Id: Unique identifier of this alert. This should be considered an
	// opaque identifier; it is not safe to rely on it being in any
	// particular format.
	Id string `json:"id,omitempty"`

	// Kind: Kind of resource this is, in this case adexchangeseller#alert.
	Kind string `json:"kind,omitempty"`

	// Message: The localized alert message.
	Message string `json:"message,omitempty"`

	// Severity: Severity of this alert. Possible values: INFO, WARNING,
	// SEVERE.
	Severity string `json:"severity,omitempty"`

	// Type: Type of this alert. Possible values: SELF_HOLD,
	// MIGRATED_TO_BILLING3, ADDRESS_PIN_VERIFICATION,
	// PHONE_PIN_VERIFICATION, CORPORATE_ENTITY, GRAYLISTED_PUBLISHER,
	// API_HOLD.
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Alert) MarshalJSON() ([]byte, error) {
	type noMethod Alert
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type Alerts struct {
	// Items: The alerts returned in this list response.
	Items []*Alert `json:"items,omitempty"`

	// Kind: Kind of list this is, in this case adexchangeseller#alerts.
	Kind string `json:"kind,omitempty"`

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

func (s *Alerts) MarshalJSON() ([]byte, error) {
	type noMethod Alerts
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type CustomChannel struct {
	// Code: Code of this custom channel, not necessarily unique across ad
	// clients.
	Code string `json:"code,omitempty"`

	// Id: Unique identifier of this custom channel. This should be
	// considered an opaque identifier; it is not safe to rely on it being
	// in any particular format.
	Id string `json:"id,omitempty"`

	// Kind: Kind of resource this is, in this case
	// adexchangeseller#customChannel.
	Kind string `json:"kind,omitempty"`

	// Name: Name of this custom channel.
	Name string `json:"name,omitempty"`

	// TargetingInfo: The targeting information of this custom channel, if
	// activated.
	TargetingInfo *CustomChannelTargetingInfo `json:"targetingInfo,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Code") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CustomChannel) MarshalJSON() ([]byte, error) {
	type noMethod CustomChannel
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CustomChannelTargetingInfo: The targeting information of this custom
// channel, if activated.
type CustomChannelTargetingInfo struct {
	// AdsAppearOn: The name used to describe this channel externally.
	AdsAppearOn string `json:"adsAppearOn,omitempty"`

	// Description: The external description of the channel.
	Description string `json:"description,omitempty"`

	// Location: The locations in which ads appear. (Only valid for content
	// and mobile content ads). Acceptable values for content ads are:
	// TOP_LEFT, TOP_CENTER, TOP_RIGHT, MIDDLE_LEFT, MIDDLE_CENTER,
	// MIDDLE_RIGHT, BOTTOM_LEFT, BOTTOM_CENTER, BOTTOM_RIGHT,
	// MULTIPLE_LOCATIONS. Acceptable values for mobile content ads are:
	// TOP, MIDDLE, BOTTOM, MULTIPLE_LOCATIONS.
	Location string `json:"location,omitempty"`

	// SiteLanguage: The language of the sites ads will be displayed on.
	SiteLanguage string `json:"siteLanguage,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AdsAppearOn") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CustomChannelTargetingInfo) MarshalJSON() ([]byte, error) {
	type noMethod CustomChannelTargetingInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type CustomChannels struct {
	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Items: The custom channels returned in this list response.
	Items []*CustomChannel `json:"items,omitempty"`

	// Kind: Kind of list this is, in this case
	// adexchangeseller#customChannels.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: Continuation token used to page through custom
	// channels. To retrieve the next page of results, set the next
	// request's "pageToken" value to this.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Etag") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CustomChannels) MarshalJSON() ([]byte, error) {
	type noMethod CustomChannels
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type Metadata struct {
	Items []*ReportingMetadataEntry `json:"items,omitempty"`

	// Kind: Kind of list this is, in this case adexchangeseller#metadata.
	Kind string `json:"kind,omitempty"`

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

func (s *Metadata) MarshalJSON() ([]byte, error) {
	type noMethod Metadata
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PreferredDeal struct {
	// AdvertiserName: The name of the advertiser this deal is for.
	AdvertiserName string `json:"advertiserName,omitempty"`

	// BuyerNetworkName: The name of the buyer network this deal is for.
	BuyerNetworkName string `json:"buyerNetworkName,omitempty"`

	// CurrencyCode: The currency code that applies to the fixed_cpm value.
	// If not set then assumed to be USD.
	CurrencyCode string `json:"currencyCode,omitempty"`

	// EndTime: Time when this deal stops being active in seconds since the
	// epoch (GMT). If not set then this deal is valid until manually
	// disabled by the publisher.
	EndTime uint64 `json:"endTime,omitempty,string"`

	// FixedCpm: The fixed price for this preferred deal. In cpm micros of
	// currency according to currencyCode. If set, then this preferred deal
	// is eligible for the fixed price tier of buying (highest priority, pay
	// exactly the configured fixed price).
	FixedCpm int64 `json:"fixedCpm,omitempty,string"`

	// Id: Unique identifier of this preferred deal.
	Id int64 `json:"id,omitempty,string"`

	// Kind: Kind of resource this is, in this case
	// adexchangeseller#preferredDeal.
	Kind string `json:"kind,omitempty"`

	// StartTime: Time when this deal becomes active in seconds since the
	// epoch (GMT). If not set then this deal is active immediately upon
	// creation.
	StartTime uint64 `json:"startTime,omitempty,string"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AdvertiserName") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PreferredDeal) MarshalJSON() ([]byte, error) {
	type noMethod PreferredDeal
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PreferredDeals struct {
	// Items: The preferred deals returned in this list response.
	Items []*PreferredDeal `json:"items,omitempty"`

	// Kind: Kind of list this is, in this case
	// adexchangeseller#preferredDeals.
	Kind string `json:"kind,omitempty"`

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

func (s *PreferredDeals) MarshalJSON() ([]byte, error) {
	type noMethod PreferredDeals
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type Report struct {
	// Averages: The averages of the report. This is the same length as any
	// other row in the report; cells corresponding to dimension columns are
	// empty.
	Averages []string `json:"averages,omitempty"`

	// Headers: The header information of the columns requested in the
	// report. This is a list of headers; one for each dimension in the
	// request, followed by one for each metric in the request.
	Headers []*ReportHeaders `json:"headers,omitempty"`

	// Kind: Kind this is, in this case adexchangeseller#report.
	Kind string `json:"kind,omitempty"`

	// Rows: The output rows of the report. Each row is a list of cells; one
	// for each dimension in the request, followed by one for each metric in
	// the request. The dimension cells contain strings, and the metric
	// cells contain numbers.
	Rows [][]string `json:"rows,omitempty"`

	// TotalMatchedRows: The total number of rows matched by the report
	// request. Fewer rows may be returned in the response due to being
	// limited by the row count requested or the report row limit.
	TotalMatchedRows int64 `json:"totalMatchedRows,omitempty,string"`

	// Totals: The totals of the report. This is the same length as any
	// other row in the report; cells corresponding to dimension columns are
	// empty.
	Totals []string `json:"totals,omitempty"`

	// Warnings: Any warnings associated with generation of the report.
	Warnings []string `json:"warnings,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Averages") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Report) MarshalJSON() ([]byte, error) {
	type noMethod Report
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ReportHeaders struct {
	// Currency: The currency of this column. Only present if the header
	// type is METRIC_CURRENCY.
	Currency string `json:"currency,omitempty"`

	// Name: The name of the header.
	Name string `json:"name,omitempty"`

	// Type: The type of the header; one of DIMENSION, METRIC_TALLY,
	// METRIC_RATIO, or METRIC_CURRENCY.
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Currency") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ReportHeaders) MarshalJSON() ([]byte, error) {
	type noMethod ReportHeaders
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ReportingMetadataEntry struct {
	// CompatibleDimensions: For metrics this is a list of dimension IDs
	// which the metric is compatible with, for dimensions it is a list of
	// compatibility groups the dimension belongs to.
	CompatibleDimensions []string `json:"compatibleDimensions,omitempty"`

	// CompatibleMetrics: The names of the metrics the dimension or metric
	// this reporting metadata entry describes is compatible with.
	CompatibleMetrics []string `json:"compatibleMetrics,omitempty"`

	// Id: Unique identifier of this reporting metadata entry, corresponding
	// to the name of the appropriate dimension or metric.
	Id string `json:"id,omitempty"`

	// Kind: Kind of resource this is, in this case
	// adexchangeseller#reportingMetadataEntry.
	Kind string `json:"kind,omitempty"`

	// RequiredDimensions: The names of the dimensions which the dimension
	// or metric this reporting metadata entry describes requires to also be
	// present in order for the report to be valid. Omitting these will not
	// cause an error or warning, but may result in data which cannot be
	// correctly interpreted.
	RequiredDimensions []string `json:"requiredDimensions,omitempty"`

	// RequiredMetrics: The names of the metrics which the dimension or
	// metric this reporting metadata entry describes requires to also be
	// present in order for the report to be valid. Omitting these will not
	// cause an error or warning, but may result in data which cannot be
	// correctly interpreted.
	RequiredMetrics []string `json:"requiredMetrics,omitempty"`

	// SupportedProducts: The codes of the projects supported by the
	// dimension or metric this reporting metadata entry describes.
	SupportedProducts []string `json:"supportedProducts,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "CompatibleDimensions") to unconditionally include in API requests.
	// By default, fields with empty values are omitted from API requests.
	// However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ReportingMetadataEntry) MarshalJSON() ([]byte, error) {
	type noMethod ReportingMetadataEntry
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type SavedReport struct {
	// Id: Unique identifier of this saved report.
	Id string `json:"id,omitempty"`

	// Kind: Kind of resource this is, in this case
	// adexchangeseller#savedReport.
	Kind string `json:"kind,omitempty"`

	// Name: This saved report's name.
	Name string `json:"name,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SavedReport) MarshalJSON() ([]byte, error) {
	type noMethod SavedReport
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type SavedReports struct {
	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Items: The saved reports returned in this list response.
	Items []*SavedReport `json:"items,omitempty"`

	// Kind: Kind of list this is, in this case
	// adexchangeseller#savedReports.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: Continuation token used to page through saved reports.
	// To retrieve the next page of results, set the next request's
	// "pageToken" value to this.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Etag") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SavedReports) MarshalJSON() ([]byte, error) {
	type noMethod SavedReports
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type UrlChannel struct {
	// Id: Unique identifier of this URL channel. This should be considered
	// an opaque identifier; it is not safe to rely on it being in any
	// particular format.
	Id string `json:"id,omitempty"`

	// Kind: Kind of resource this is, in this case
	// adexchangeseller#urlChannel.
	Kind string `json:"kind,omitempty"`

	// UrlPattern: URL Pattern of this URL channel. Does not include
	// "http://" or "https://". Example: www.example.com/home
	UrlPattern string `json:"urlPattern,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *UrlChannel) MarshalJSON() ([]byte, error) {
	type noMethod UrlChannel
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type UrlChannels struct {
	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Items: The URL channels returned in this list response.
	Items []*UrlChannel `json:"items,omitempty"`

	// Kind: Kind of list this is, in this case
	// adexchangeseller#urlChannels.
	Kind string `json:"kind,omitempty"`

	// NextPageToken: Continuation token used to page through URL channels.
	// To retrieve the next page of results, set the next request's
	// "pageToken" value to this.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Etag") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *UrlChannels) MarshalJSON() ([]byte, error) {
	type noMethod UrlChannels
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "adexchangeseller.accounts.get":

type AccountsGetCall struct {
	s         *Service
	accountId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Get information about the selected Ad Exchange account.
func (r *AccountsService) Get(accountId string) *AccountsGetCall {
	c := &AccountsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AccountsGetCall) Fields(s ...googleapi.Field) *AccountsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AccountsGetCall) IfNoneMatch(entityTag string) *AccountsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AccountsGetCall) Context(ctx context.Context) *AccountsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *AccountsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "accounts/{accountId}")
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

// Do executes the "adexchangeseller.accounts.get" call.
// Exactly one of *Account or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Account.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *AccountsGetCall) Do() (*Account, error) {
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
	ret := &Account{
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
	//   "description": "Get information about the selected Ad Exchange account.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.accounts.get",
	//   "parameterOrder": [
	//     "accountId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account to get information about. Tip: 'myaccount' is a valid ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "accounts/{accountId}",
	//   "response": {
	//     "$ref": "Account"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.adclients.list":

type AdclientsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: List all ad clients in this Ad Exchange account.
func (r *AdclientsService) List() *AdclientsListCall {
	c := &AdclientsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of ad clients to include in the response, used for paging.
func (c *AdclientsListCall) MaxResults(maxResults int64) *AdclientsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": A continuation
// token, used to page through ad clients. To retrieve the next page,
// set this parameter to the value of "nextPageToken" from the previous
// response.
func (c *AdclientsListCall) PageToken(pageToken string) *AdclientsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AdclientsListCall) Fields(s ...googleapi.Field) *AdclientsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AdclientsListCall) IfNoneMatch(entityTag string) *AdclientsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AdclientsListCall) Context(ctx context.Context) *AdclientsListCall {
	c.ctx_ = ctx
	return c
}

func (c *AdclientsListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "adclients")
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

// Do executes the "adexchangeseller.adclients.list" call.
// Exactly one of *AdClients or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *AdClients.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *AdclientsListCall) Do() (*AdClients, error) {
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
	ret := &AdClients{
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
	//   "description": "List all ad clients in this Ad Exchange account.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.adclients.list",
	//   "parameters": {
	//     "maxResults": {
	//       "description": "The maximum number of ad clients to include in the response, used for paging.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "10000",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "A continuation token, used to page through ad clients. To retrieve the next page, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "adclients",
	//   "response": {
	//     "$ref": "AdClients"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.adunits.get":

type AdunitsGetCall struct {
	s          *Service
	adClientId string
	adUnitId   string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// Get: Gets the specified ad unit in the specified ad client.
func (r *AdunitsService) Get(adClientId string, adUnitId string) *AdunitsGetCall {
	c := &AdunitsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.adClientId = adClientId
	c.adUnitId = adUnitId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AdunitsGetCall) Fields(s ...googleapi.Field) *AdunitsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AdunitsGetCall) IfNoneMatch(entityTag string) *AdunitsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AdunitsGetCall) Context(ctx context.Context) *AdunitsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *AdunitsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "adclients/{adClientId}/adunits/{adUnitId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"adClientId": c.adClientId,
		"adUnitId":   c.adUnitId,
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

// Do executes the "adexchangeseller.adunits.get" call.
// Exactly one of *AdUnit or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *AdUnit.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *AdunitsGetCall) Do() (*AdUnit, error) {
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
	ret := &AdUnit{
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
	//   "description": "Gets the specified ad unit in the specified ad client.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.adunits.get",
	//   "parameterOrder": [
	//     "adClientId",
	//     "adUnitId"
	//   ],
	//   "parameters": {
	//     "adClientId": {
	//       "description": "Ad client for which to get the ad unit.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "adUnitId": {
	//       "description": "Ad unit to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "adclients/{adClientId}/adunits/{adUnitId}",
	//   "response": {
	//     "$ref": "AdUnit"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.adunits.list":

type AdunitsListCall struct {
	s          *Service
	adClientId string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// List: List all ad units in the specified ad client for this Ad
// Exchange account.
func (r *AdunitsService) List(adClientId string) *AdunitsListCall {
	c := &AdunitsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.adClientId = adClientId
	return c
}

// IncludeInactive sets the optional parameter "includeInactive":
// Whether to include inactive ad units. Default: true.
func (c *AdunitsListCall) IncludeInactive(includeInactive bool) *AdunitsListCall {
	c.opt_["includeInactive"] = includeInactive
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of ad units to include in the response, used for paging.
func (c *AdunitsListCall) MaxResults(maxResults int64) *AdunitsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": A continuation
// token, used to page through ad units. To retrieve the next page, set
// this parameter to the value of "nextPageToken" from the previous
// response.
func (c *AdunitsListCall) PageToken(pageToken string) *AdunitsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AdunitsListCall) Fields(s ...googleapi.Field) *AdunitsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AdunitsListCall) IfNoneMatch(entityTag string) *AdunitsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AdunitsListCall) Context(ctx context.Context) *AdunitsListCall {
	c.ctx_ = ctx
	return c
}

func (c *AdunitsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["includeInactive"]; ok {
		params.Set("includeInactive", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "adclients/{adClientId}/adunits")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"adClientId": c.adClientId,
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

// Do executes the "adexchangeseller.adunits.list" call.
// Exactly one of *AdUnits or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *AdUnits.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *AdunitsListCall) Do() (*AdUnits, error) {
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
	ret := &AdUnits{
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
	//   "description": "List all ad units in the specified ad client for this Ad Exchange account.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.adunits.list",
	//   "parameterOrder": [
	//     "adClientId"
	//   ],
	//   "parameters": {
	//     "adClientId": {
	//       "description": "Ad client for which to list ad units.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "includeInactive": {
	//       "description": "Whether to include inactive ad units. Default: true.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of ad units to include in the response, used for paging.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "10000",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "A continuation token, used to page through ad units. To retrieve the next page, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "adclients/{adClientId}/adunits",
	//   "response": {
	//     "$ref": "AdUnits"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.adunits.customchannels.list":

type AdunitsCustomchannelsListCall struct {
	s          *Service
	adClientId string
	adUnitId   string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// List: List all custom channels which the specified ad unit belongs
// to.
func (r *AdunitsCustomchannelsService) List(adClientId string, adUnitId string) *AdunitsCustomchannelsListCall {
	c := &AdunitsCustomchannelsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.adClientId = adClientId
	c.adUnitId = adUnitId
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of custom channels to include in the response, used for
// paging.
func (c *AdunitsCustomchannelsListCall) MaxResults(maxResults int64) *AdunitsCustomchannelsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": A continuation
// token, used to page through custom channels. To retrieve the next
// page, set this parameter to the value of "nextPageToken" from the
// previous response.
func (c *AdunitsCustomchannelsListCall) PageToken(pageToken string) *AdunitsCustomchannelsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AdunitsCustomchannelsListCall) Fields(s ...googleapi.Field) *AdunitsCustomchannelsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AdunitsCustomchannelsListCall) IfNoneMatch(entityTag string) *AdunitsCustomchannelsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AdunitsCustomchannelsListCall) Context(ctx context.Context) *AdunitsCustomchannelsListCall {
	c.ctx_ = ctx
	return c
}

func (c *AdunitsCustomchannelsListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "adclients/{adClientId}/adunits/{adUnitId}/customchannels")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"adClientId": c.adClientId,
		"adUnitId":   c.adUnitId,
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

// Do executes the "adexchangeseller.adunits.customchannels.list" call.
// Exactly one of *CustomChannels or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CustomChannels.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AdunitsCustomchannelsListCall) Do() (*CustomChannels, error) {
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
	ret := &CustomChannels{
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
	//   "description": "List all custom channels which the specified ad unit belongs to.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.adunits.customchannels.list",
	//   "parameterOrder": [
	//     "adClientId",
	//     "adUnitId"
	//   ],
	//   "parameters": {
	//     "adClientId": {
	//       "description": "Ad client which contains the ad unit.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "adUnitId": {
	//       "description": "Ad unit for which to list custom channels.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of custom channels to include in the response, used for paging.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "10000",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "A continuation token, used to page through custom channels. To retrieve the next page, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "adclients/{adClientId}/adunits/{adUnitId}/customchannels",
	//   "response": {
	//     "$ref": "CustomChannels"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.alerts.list":

type AlertsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: List the alerts for this Ad Exchange account.
func (r *AlertsService) List() *AlertsListCall {
	c := &AlertsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Locale sets the optional parameter "locale": The locale to use for
// translating alert messages. The account locale will be used if this
// is not supplied. The AdSense default (English) will be used if the
// supplied locale is invalid or unsupported.
func (c *AlertsListCall) Locale(locale string) *AlertsListCall {
	c.opt_["locale"] = locale
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AlertsListCall) Fields(s ...googleapi.Field) *AlertsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AlertsListCall) IfNoneMatch(entityTag string) *AlertsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AlertsListCall) Context(ctx context.Context) *AlertsListCall {
	c.ctx_ = ctx
	return c
}

func (c *AlertsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["locale"]; ok {
		params.Set("locale", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "alerts")
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

// Do executes the "adexchangeseller.alerts.list" call.
// Exactly one of *Alerts or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Alerts.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *AlertsListCall) Do() (*Alerts, error) {
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
	ret := &Alerts{
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
	//   "description": "List the alerts for this Ad Exchange account.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.alerts.list",
	//   "parameters": {
	//     "locale": {
	//       "description": "The locale to use for translating alert messages. The account locale will be used if this is not supplied. The AdSense default (English) will be used if the supplied locale is invalid or unsupported.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "alerts",
	//   "response": {
	//     "$ref": "Alerts"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.customchannels.get":

type CustomchannelsGetCall struct {
	s               *Service
	adClientId      string
	customChannelId string
	opt_            map[string]interface{}
	ctx_            context.Context
}

// Get: Get the specified custom channel from the specified ad client.
func (r *CustomchannelsService) Get(adClientId string, customChannelId string) *CustomchannelsGetCall {
	c := &CustomchannelsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.adClientId = adClientId
	c.customChannelId = customChannelId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CustomchannelsGetCall) Fields(s ...googleapi.Field) *CustomchannelsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *CustomchannelsGetCall) IfNoneMatch(entityTag string) *CustomchannelsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CustomchannelsGetCall) Context(ctx context.Context) *CustomchannelsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *CustomchannelsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "adclients/{adClientId}/customchannels/{customChannelId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"adClientId":      c.adClientId,
		"customChannelId": c.customChannelId,
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

// Do executes the "adexchangeseller.customchannels.get" call.
// Exactly one of *CustomChannel or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CustomChannel.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *CustomchannelsGetCall) Do() (*CustomChannel, error) {
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
	ret := &CustomChannel{
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
	//   "description": "Get the specified custom channel from the specified ad client.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.customchannels.get",
	//   "parameterOrder": [
	//     "adClientId",
	//     "customChannelId"
	//   ],
	//   "parameters": {
	//     "adClientId": {
	//       "description": "Ad client which contains the custom channel.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "customChannelId": {
	//       "description": "Custom channel to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "adclients/{adClientId}/customchannels/{customChannelId}",
	//   "response": {
	//     "$ref": "CustomChannel"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.customchannels.list":

type CustomchannelsListCall struct {
	s          *Service
	adClientId string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// List: List all custom channels in the specified ad client for this Ad
// Exchange account.
func (r *CustomchannelsService) List(adClientId string) *CustomchannelsListCall {
	c := &CustomchannelsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.adClientId = adClientId
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of custom channels to include in the response, used for
// paging.
func (c *CustomchannelsListCall) MaxResults(maxResults int64) *CustomchannelsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": A continuation
// token, used to page through custom channels. To retrieve the next
// page, set this parameter to the value of "nextPageToken" from the
// previous response.
func (c *CustomchannelsListCall) PageToken(pageToken string) *CustomchannelsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CustomchannelsListCall) Fields(s ...googleapi.Field) *CustomchannelsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *CustomchannelsListCall) IfNoneMatch(entityTag string) *CustomchannelsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CustomchannelsListCall) Context(ctx context.Context) *CustomchannelsListCall {
	c.ctx_ = ctx
	return c
}

func (c *CustomchannelsListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "adclients/{adClientId}/customchannels")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"adClientId": c.adClientId,
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

// Do executes the "adexchangeseller.customchannels.list" call.
// Exactly one of *CustomChannels or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CustomChannels.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *CustomchannelsListCall) Do() (*CustomChannels, error) {
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
	ret := &CustomChannels{
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
	//   "description": "List all custom channels in the specified ad client for this Ad Exchange account.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.customchannels.list",
	//   "parameterOrder": [
	//     "adClientId"
	//   ],
	//   "parameters": {
	//     "adClientId": {
	//       "description": "Ad client for which to list custom channels.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of custom channels to include in the response, used for paging.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "10000",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "A continuation token, used to page through custom channels. To retrieve the next page, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "adclients/{adClientId}/customchannels",
	//   "response": {
	//     "$ref": "CustomChannels"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.customchannels.adunits.list":

type CustomchannelsAdunitsListCall struct {
	s               *Service
	adClientId      string
	customChannelId string
	opt_            map[string]interface{}
	ctx_            context.Context
}

// List: List all ad units in the specified custom channel.
func (r *CustomchannelsAdunitsService) List(adClientId string, customChannelId string) *CustomchannelsAdunitsListCall {
	c := &CustomchannelsAdunitsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.adClientId = adClientId
	c.customChannelId = customChannelId
	return c
}

// IncludeInactive sets the optional parameter "includeInactive":
// Whether to include inactive ad units. Default: true.
func (c *CustomchannelsAdunitsListCall) IncludeInactive(includeInactive bool) *CustomchannelsAdunitsListCall {
	c.opt_["includeInactive"] = includeInactive
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of ad units to include in the response, used for paging.
func (c *CustomchannelsAdunitsListCall) MaxResults(maxResults int64) *CustomchannelsAdunitsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": A continuation
// token, used to page through ad units. To retrieve the next page, set
// this parameter to the value of "nextPageToken" from the previous
// response.
func (c *CustomchannelsAdunitsListCall) PageToken(pageToken string) *CustomchannelsAdunitsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CustomchannelsAdunitsListCall) Fields(s ...googleapi.Field) *CustomchannelsAdunitsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *CustomchannelsAdunitsListCall) IfNoneMatch(entityTag string) *CustomchannelsAdunitsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CustomchannelsAdunitsListCall) Context(ctx context.Context) *CustomchannelsAdunitsListCall {
	c.ctx_ = ctx
	return c
}

func (c *CustomchannelsAdunitsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["includeInactive"]; ok {
		params.Set("includeInactive", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "adclients/{adClientId}/customchannels/{customChannelId}/adunits")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"adClientId":      c.adClientId,
		"customChannelId": c.customChannelId,
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

// Do executes the "adexchangeseller.customchannels.adunits.list" call.
// Exactly one of *AdUnits or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *AdUnits.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CustomchannelsAdunitsListCall) Do() (*AdUnits, error) {
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
	ret := &AdUnits{
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
	//   "description": "List all ad units in the specified custom channel.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.customchannels.adunits.list",
	//   "parameterOrder": [
	//     "adClientId",
	//     "customChannelId"
	//   ],
	//   "parameters": {
	//     "adClientId": {
	//       "description": "Ad client which contains the custom channel.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "customChannelId": {
	//       "description": "Custom channel for which to list ad units.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "includeInactive": {
	//       "description": "Whether to include inactive ad units. Default: true.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of ad units to include in the response, used for paging.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "10000",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "A continuation token, used to page through ad units. To retrieve the next page, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "adclients/{adClientId}/customchannels/{customChannelId}/adunits",
	//   "response": {
	//     "$ref": "AdUnits"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.metadata.dimensions.list":

type MetadataDimensionsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: List the metadata for the dimensions available to this
// AdExchange account.
func (r *MetadataDimensionsService) List() *MetadataDimensionsListCall {
	c := &MetadataDimensionsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *MetadataDimensionsListCall) Fields(s ...googleapi.Field) *MetadataDimensionsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *MetadataDimensionsListCall) IfNoneMatch(entityTag string) *MetadataDimensionsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *MetadataDimensionsListCall) Context(ctx context.Context) *MetadataDimensionsListCall {
	c.ctx_ = ctx
	return c
}

func (c *MetadataDimensionsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "metadata/dimensions")
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

// Do executes the "adexchangeseller.metadata.dimensions.list" call.
// Exactly one of *Metadata or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Metadata.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *MetadataDimensionsListCall) Do() (*Metadata, error) {
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
	ret := &Metadata{
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
	//   "description": "List the metadata for the dimensions available to this AdExchange account.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.metadata.dimensions.list",
	//   "path": "metadata/dimensions",
	//   "response": {
	//     "$ref": "Metadata"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.metadata.metrics.list":

type MetadataMetricsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: List the metadata for the metrics available to this AdExchange
// account.
func (r *MetadataMetricsService) List() *MetadataMetricsListCall {
	c := &MetadataMetricsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *MetadataMetricsListCall) Fields(s ...googleapi.Field) *MetadataMetricsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *MetadataMetricsListCall) IfNoneMatch(entityTag string) *MetadataMetricsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *MetadataMetricsListCall) Context(ctx context.Context) *MetadataMetricsListCall {
	c.ctx_ = ctx
	return c
}

func (c *MetadataMetricsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "metadata/metrics")
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

// Do executes the "adexchangeseller.metadata.metrics.list" call.
// Exactly one of *Metadata or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Metadata.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *MetadataMetricsListCall) Do() (*Metadata, error) {
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
	ret := &Metadata{
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
	//   "description": "List the metadata for the metrics available to this AdExchange account.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.metadata.metrics.list",
	//   "path": "metadata/metrics",
	//   "response": {
	//     "$ref": "Metadata"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.preferreddeals.get":

type PreferreddealsGetCall struct {
	s      *Service
	dealId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Get: Get information about the selected Ad Exchange Preferred Deal.
func (r *PreferreddealsService) Get(dealId string) *PreferreddealsGetCall {
	c := &PreferreddealsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.dealId = dealId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PreferreddealsGetCall) Fields(s ...googleapi.Field) *PreferreddealsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PreferreddealsGetCall) IfNoneMatch(entityTag string) *PreferreddealsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PreferreddealsGetCall) Context(ctx context.Context) *PreferreddealsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *PreferreddealsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "preferreddeals/{dealId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"dealId": c.dealId,
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

// Do executes the "adexchangeseller.preferreddeals.get" call.
// Exactly one of *PreferredDeal or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *PreferredDeal.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *PreferreddealsGetCall) Do() (*PreferredDeal, error) {
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
	ret := &PreferredDeal{
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
	//   "description": "Get information about the selected Ad Exchange Preferred Deal.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.preferreddeals.get",
	//   "parameterOrder": [
	//     "dealId"
	//   ],
	//   "parameters": {
	//     "dealId": {
	//       "description": "Preferred deal to get information about.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "preferreddeals/{dealId}",
	//   "response": {
	//     "$ref": "PreferredDeal"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.preferreddeals.list":

type PreferreddealsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: List the preferred deals for this Ad Exchange account.
func (r *PreferreddealsService) List() *PreferreddealsListCall {
	c := &PreferreddealsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PreferreddealsListCall) Fields(s ...googleapi.Field) *PreferreddealsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PreferreddealsListCall) IfNoneMatch(entityTag string) *PreferreddealsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PreferreddealsListCall) Context(ctx context.Context) *PreferreddealsListCall {
	c.ctx_ = ctx
	return c
}

func (c *PreferreddealsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "preferreddeals")
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

// Do executes the "adexchangeseller.preferreddeals.list" call.
// Exactly one of *PreferredDeals or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *PreferredDeals.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *PreferreddealsListCall) Do() (*PreferredDeals, error) {
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
	ret := &PreferredDeals{
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
	//   "description": "List the preferred deals for this Ad Exchange account.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.preferreddeals.list",
	//   "path": "preferreddeals",
	//   "response": {
	//     "$ref": "PreferredDeals"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.reports.generate":

type ReportsGenerateCall struct {
	s         *Service
	startDate string
	endDate   string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Generate: Generate an Ad Exchange report based on the report request
// sent in the query parameters. Returns the result as JSON; to retrieve
// output in CSV format specify "alt=csv" as a query parameter.
func (r *ReportsService) Generate(startDate string, endDate string) *ReportsGenerateCall {
	c := &ReportsGenerateCall{s: r.s, opt_: make(map[string]interface{})}
	c.startDate = startDate
	c.endDate = endDate
	return c
}

// Dimension sets the optional parameter "dimension": Dimensions to base
// the report on.
func (c *ReportsGenerateCall) Dimension(dimension string) *ReportsGenerateCall {
	c.opt_["dimension"] = dimension
	return c
}

// Filter sets the optional parameter "filter": Filters to be run on the
// report.
func (c *ReportsGenerateCall) Filter(filter string) *ReportsGenerateCall {
	c.opt_["filter"] = filter
	return c
}

// Locale sets the optional parameter "locale": Optional locale to use
// for translating report output to a local language. Defaults to
// "en_US" if not specified.
func (c *ReportsGenerateCall) Locale(locale string) *ReportsGenerateCall {
	c.opt_["locale"] = locale
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of rows of report data to return.
func (c *ReportsGenerateCall) MaxResults(maxResults int64) *ReportsGenerateCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// Metric sets the optional parameter "metric": Numeric columns to
// include in the report.
func (c *ReportsGenerateCall) Metric(metric string) *ReportsGenerateCall {
	c.opt_["metric"] = metric
	return c
}

// Sort sets the optional parameter "sort": The name of a dimension or
// metric to sort the resulting report on, optionally prefixed with "+"
// to sort ascending or "-" to sort descending. If no prefix is
// specified, the column is sorted ascending.
func (c *ReportsGenerateCall) Sort(sort string) *ReportsGenerateCall {
	c.opt_["sort"] = sort
	return c
}

// StartIndex sets the optional parameter "startIndex": Index of the
// first row of report data to return.
func (c *ReportsGenerateCall) StartIndex(startIndex int64) *ReportsGenerateCall {
	c.opt_["startIndex"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReportsGenerateCall) Fields(s ...googleapi.Field) *ReportsGenerateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ReportsGenerateCall) IfNoneMatch(entityTag string) *ReportsGenerateCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do and Download methods.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReportsGenerateCall) Context(ctx context.Context) *ReportsGenerateCall {
	c.ctx_ = ctx
	return c
}

func (c *ReportsGenerateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("endDate", fmt.Sprintf("%v", c.endDate))
	params.Set("startDate", fmt.Sprintf("%v", c.startDate))
	if v, ok := c.opt_["dimension"]; ok {
		params.Set("dimension", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["filter"]; ok {
		params.Set("filter", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["locale"]; ok {
		params.Set("locale", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["metric"]; ok {
		params.Set("metric", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["sort"]; ok {
		params.Set("sort", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["startIndex"]; ok {
		params.Set("startIndex", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "reports")
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
func (c *ReportsGenerateCall) Download() (*http.Response, error) {
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

// Do executes the "adexchangeseller.reports.generate" call.
// Exactly one of *Report or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Report.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ReportsGenerateCall) Do() (*Report, error) {
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
	ret := &Report{
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
	//   "description": "Generate an Ad Exchange report based on the report request sent in the query parameters. Returns the result as JSON; to retrieve output in CSV format specify \"alt=csv\" as a query parameter.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.reports.generate",
	//   "parameterOrder": [
	//     "startDate",
	//     "endDate"
	//   ],
	//   "parameters": {
	//     "dimension": {
	//       "description": "Dimensions to base the report on.",
	//       "location": "query",
	//       "pattern": "[a-zA-Z_]+",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "endDate": {
	//       "description": "End of the date range to report on in \"YYYY-MM-DD\" format, inclusive.",
	//       "location": "query",
	//       "pattern": "\\d{4}-\\d{2}-\\d{2}|(today|startOfMonth|startOfYear)(([\\-\\+]\\d+[dwmy]){0,3}?)",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "filter": {
	//       "description": "Filters to be run on the report.",
	//       "location": "query",
	//       "pattern": "[a-zA-Z_]+(==|=@).+",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "locale": {
	//       "description": "Optional locale to use for translating report output to a local language. Defaults to \"en_US\" if not specified.",
	//       "location": "query",
	//       "pattern": "[a-zA-Z_]+",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of rows of report data to return.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "50000",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "metric": {
	//       "description": "Numeric columns to include in the report.",
	//       "location": "query",
	//       "pattern": "[a-zA-Z_]+",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "sort": {
	//       "description": "The name of a dimension or metric to sort the resulting report on, optionally prefixed with \"+\" to sort ascending or \"-\" to sort descending. If no prefix is specified, the column is sorted ascending.",
	//       "location": "query",
	//       "pattern": "(\\+|-)?[a-zA-Z_]+",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "startDate": {
	//       "description": "Start of the date range to report on in \"YYYY-MM-DD\" format, inclusive.",
	//       "location": "query",
	//       "pattern": "\\d{4}-\\d{2}-\\d{2}|(today|startOfMonth|startOfYear)(([\\-\\+]\\d+[dwmy]){0,3}?)",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "startIndex": {
	//       "description": "Index of the first row of report data to return.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "5000",
	//       "minimum": "0",
	//       "type": "integer"
	//     }
	//   },
	//   "path": "reports",
	//   "response": {
	//     "$ref": "Report"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ],
	//   "supportsMediaDownload": true
	// }

}

// method id "adexchangeseller.reports.saved.generate":

type ReportsSavedGenerateCall struct {
	s             *Service
	savedReportId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Generate: Generate an Ad Exchange report based on the saved report ID
// sent in the query parameters.
func (r *ReportsSavedService) Generate(savedReportId string) *ReportsSavedGenerateCall {
	c := &ReportsSavedGenerateCall{s: r.s, opt_: make(map[string]interface{})}
	c.savedReportId = savedReportId
	return c
}

// Locale sets the optional parameter "locale": Optional locale to use
// for translating report output to a local language. Defaults to
// "en_US" if not specified.
func (c *ReportsSavedGenerateCall) Locale(locale string) *ReportsSavedGenerateCall {
	c.opt_["locale"] = locale
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of rows of report data to return.
func (c *ReportsSavedGenerateCall) MaxResults(maxResults int64) *ReportsSavedGenerateCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// StartIndex sets the optional parameter "startIndex": Index of the
// first row of report data to return.
func (c *ReportsSavedGenerateCall) StartIndex(startIndex int64) *ReportsSavedGenerateCall {
	c.opt_["startIndex"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReportsSavedGenerateCall) Fields(s ...googleapi.Field) *ReportsSavedGenerateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ReportsSavedGenerateCall) IfNoneMatch(entityTag string) *ReportsSavedGenerateCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReportsSavedGenerateCall) Context(ctx context.Context) *ReportsSavedGenerateCall {
	c.ctx_ = ctx
	return c
}

func (c *ReportsSavedGenerateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["locale"]; ok {
		params.Set("locale", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["startIndex"]; ok {
		params.Set("startIndex", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "reports/{savedReportId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"savedReportId": c.savedReportId,
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

// Do executes the "adexchangeseller.reports.saved.generate" call.
// Exactly one of *Report or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Report.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ReportsSavedGenerateCall) Do() (*Report, error) {
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
	ret := &Report{
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
	//   "description": "Generate an Ad Exchange report based on the saved report ID sent in the query parameters.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.reports.saved.generate",
	//   "parameterOrder": [
	//     "savedReportId"
	//   ],
	//   "parameters": {
	//     "locale": {
	//       "description": "Optional locale to use for translating report output to a local language. Defaults to \"en_US\" if not specified.",
	//       "location": "query",
	//       "pattern": "[a-zA-Z_]+",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of rows of report data to return.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "50000",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "savedReportId": {
	//       "description": "The saved report to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "startIndex": {
	//       "description": "Index of the first row of report data to return.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "5000",
	//       "minimum": "0",
	//       "type": "integer"
	//     }
	//   },
	//   "path": "reports/{savedReportId}",
	//   "response": {
	//     "$ref": "Report"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.reports.saved.list":

type ReportsSavedListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: List all saved reports in this Ad Exchange account.
func (r *ReportsSavedService) List() *ReportsSavedListCall {
	c := &ReportsSavedListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of saved reports to include in the response, used for paging.
func (c *ReportsSavedListCall) MaxResults(maxResults int64) *ReportsSavedListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": A continuation
// token, used to page through saved reports. To retrieve the next page,
// set this parameter to the value of "nextPageToken" from the previous
// response.
func (c *ReportsSavedListCall) PageToken(pageToken string) *ReportsSavedListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReportsSavedListCall) Fields(s ...googleapi.Field) *ReportsSavedListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ReportsSavedListCall) IfNoneMatch(entityTag string) *ReportsSavedListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReportsSavedListCall) Context(ctx context.Context) *ReportsSavedListCall {
	c.ctx_ = ctx
	return c
}

func (c *ReportsSavedListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "reports/saved")
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

// Do executes the "adexchangeseller.reports.saved.list" call.
// Exactly one of *SavedReports or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *SavedReports.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ReportsSavedListCall) Do() (*SavedReports, error) {
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
	ret := &SavedReports{
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
	//   "description": "List all saved reports in this Ad Exchange account.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.reports.saved.list",
	//   "parameters": {
	//     "maxResults": {
	//       "description": "The maximum number of saved reports to include in the response, used for paging.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "A continuation token, used to page through saved reports. To retrieve the next page, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "reports/saved",
	//   "response": {
	//     "$ref": "SavedReports"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}

// method id "adexchangeseller.urlchannels.list":

type UrlchannelsListCall struct {
	s          *Service
	adClientId string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// List: List all URL channels in the specified ad client for this Ad
// Exchange account.
func (r *UrlchannelsService) List(adClientId string) *UrlchannelsListCall {
	c := &UrlchannelsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.adClientId = adClientId
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of URL channels to include in the response, used for paging.
func (c *UrlchannelsListCall) MaxResults(maxResults int64) *UrlchannelsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": A continuation
// token, used to page through URL channels. To retrieve the next page,
// set this parameter to the value of "nextPageToken" from the previous
// response.
func (c *UrlchannelsListCall) PageToken(pageToken string) *UrlchannelsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *UrlchannelsListCall) Fields(s ...googleapi.Field) *UrlchannelsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *UrlchannelsListCall) IfNoneMatch(entityTag string) *UrlchannelsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *UrlchannelsListCall) Context(ctx context.Context) *UrlchannelsListCall {
	c.ctx_ = ctx
	return c
}

func (c *UrlchannelsListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "adclients/{adClientId}/urlchannels")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"adClientId": c.adClientId,
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

// Do executes the "adexchangeseller.urlchannels.list" call.
// Exactly one of *UrlChannels or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *UrlChannels.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *UrlchannelsListCall) Do() (*UrlChannels, error) {
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
	ret := &UrlChannels{
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
	//   "description": "List all URL channels in the specified ad client for this Ad Exchange account.",
	//   "httpMethod": "GET",
	//   "id": "adexchangeseller.urlchannels.list",
	//   "parameterOrder": [
	//     "adClientId"
	//   ],
	//   "parameters": {
	//     "adClientId": {
	//       "description": "Ad client for which to list URL channels.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "description": "The maximum number of URL channels to include in the response, used for paging.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "10000",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "A continuation token, used to page through URL channels. To retrieve the next page, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "adclients/{adClientId}/urlchannels",
	//   "response": {
	//     "$ref": "UrlChannels"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/adexchange.seller",
	//     "https://www.googleapis.com/auth/adexchange.seller.readonly"
	//   ]
	// }

}
