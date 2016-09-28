// Package analytics provides access to the Google Analytics API.
//
// See https://developers.google.com/analytics/
//
// Usage example:
//
//   import "google.golang.org/api/analytics/v3"
//   ...
//   analyticsService, err := analytics.New(oauthHttpClient)
package analytics // import "google.golang.org/api/analytics/v3"

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

const apiId = "analytics:v3"
const apiName = "analytics"
const apiVersion = "v3"
const basePath = "https://www.googleapis.com/analytics/v3/"

// OAuth2 scopes used by this API.
const (
	// View and manage your Google Analytics data
	AnalyticsScope = "https://www.googleapis.com/auth/analytics"

	// Edit Google Analytics management entities
	AnalyticsEditScope = "https://www.googleapis.com/auth/analytics.edit"

	// Manage Google Analytics Account users by email address
	AnalyticsManageUsersScope = "https://www.googleapis.com/auth/analytics.manage.users"

	// View Google Analytics user permissions
	AnalyticsManageUsersReadonlyScope = "https://www.googleapis.com/auth/analytics.manage.users.readonly"

	// Create a new Google Analytics account along with its default property
	// and view
	AnalyticsProvisionScope = "https://www.googleapis.com/auth/analytics.provision"

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
	s.Metadata = NewMetadataService(s)
	s.Provisioning = NewProvisioningService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	Data *DataService

	Management *ManagementService

	Metadata *MetadataService

	Provisioning *ProvisioningService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewDataService(s *Service) *DataService {
	rs := &DataService{s: s}
	rs.Ga = NewDataGaService(s)
	rs.Mcf = NewDataMcfService(s)
	rs.Realtime = NewDataRealtimeService(s)
	return rs
}

type DataService struct {
	s *Service

	Ga *DataGaService

	Mcf *DataMcfService

	Realtime *DataRealtimeService
}

func NewDataGaService(s *Service) *DataGaService {
	rs := &DataGaService{s: s}
	return rs
}

type DataGaService struct {
	s *Service
}

func NewDataMcfService(s *Service) *DataMcfService {
	rs := &DataMcfService{s: s}
	return rs
}

type DataMcfService struct {
	s *Service
}

func NewDataRealtimeService(s *Service) *DataRealtimeService {
	rs := &DataRealtimeService{s: s}
	return rs
}

type DataRealtimeService struct {
	s *Service
}

func NewManagementService(s *Service) *ManagementService {
	rs := &ManagementService{s: s}
	rs.AccountSummaries = NewManagementAccountSummariesService(s)
	rs.AccountUserLinks = NewManagementAccountUserLinksService(s)
	rs.Accounts = NewManagementAccountsService(s)
	rs.CustomDataSources = NewManagementCustomDataSourcesService(s)
	rs.CustomDimensions = NewManagementCustomDimensionsService(s)
	rs.CustomMetrics = NewManagementCustomMetricsService(s)
	rs.Experiments = NewManagementExperimentsService(s)
	rs.Filters = NewManagementFiltersService(s)
	rs.Goals = NewManagementGoalsService(s)
	rs.ProfileFilterLinks = NewManagementProfileFilterLinksService(s)
	rs.ProfileUserLinks = NewManagementProfileUserLinksService(s)
	rs.Profiles = NewManagementProfilesService(s)
	rs.Segments = NewManagementSegmentsService(s)
	rs.UnsampledReports = NewManagementUnsampledReportsService(s)
	rs.Uploads = NewManagementUploadsService(s)
	rs.WebPropertyAdWordsLinks = NewManagementWebPropertyAdWordsLinksService(s)
	rs.Webproperties = NewManagementWebpropertiesService(s)
	rs.WebpropertyUserLinks = NewManagementWebpropertyUserLinksService(s)
	return rs
}

type ManagementService struct {
	s *Service

	AccountSummaries *ManagementAccountSummariesService

	AccountUserLinks *ManagementAccountUserLinksService

	Accounts *ManagementAccountsService

	CustomDataSources *ManagementCustomDataSourcesService

	CustomDimensions *ManagementCustomDimensionsService

	CustomMetrics *ManagementCustomMetricsService

	Experiments *ManagementExperimentsService

	Filters *ManagementFiltersService

	Goals *ManagementGoalsService

	ProfileFilterLinks *ManagementProfileFilterLinksService

	ProfileUserLinks *ManagementProfileUserLinksService

	Profiles *ManagementProfilesService

	Segments *ManagementSegmentsService

	UnsampledReports *ManagementUnsampledReportsService

	Uploads *ManagementUploadsService

	WebPropertyAdWordsLinks *ManagementWebPropertyAdWordsLinksService

	Webproperties *ManagementWebpropertiesService

	WebpropertyUserLinks *ManagementWebpropertyUserLinksService
}

func NewManagementAccountSummariesService(s *Service) *ManagementAccountSummariesService {
	rs := &ManagementAccountSummariesService{s: s}
	return rs
}

type ManagementAccountSummariesService struct {
	s *Service
}

func NewManagementAccountUserLinksService(s *Service) *ManagementAccountUserLinksService {
	rs := &ManagementAccountUserLinksService{s: s}
	return rs
}

type ManagementAccountUserLinksService struct {
	s *Service
}

func NewManagementAccountsService(s *Service) *ManagementAccountsService {
	rs := &ManagementAccountsService{s: s}
	return rs
}

type ManagementAccountsService struct {
	s *Service
}

func NewManagementCustomDataSourcesService(s *Service) *ManagementCustomDataSourcesService {
	rs := &ManagementCustomDataSourcesService{s: s}
	return rs
}

type ManagementCustomDataSourcesService struct {
	s *Service
}

func NewManagementCustomDimensionsService(s *Service) *ManagementCustomDimensionsService {
	rs := &ManagementCustomDimensionsService{s: s}
	return rs
}

type ManagementCustomDimensionsService struct {
	s *Service
}

func NewManagementCustomMetricsService(s *Service) *ManagementCustomMetricsService {
	rs := &ManagementCustomMetricsService{s: s}
	return rs
}

type ManagementCustomMetricsService struct {
	s *Service
}

func NewManagementExperimentsService(s *Service) *ManagementExperimentsService {
	rs := &ManagementExperimentsService{s: s}
	return rs
}

type ManagementExperimentsService struct {
	s *Service
}

func NewManagementFiltersService(s *Service) *ManagementFiltersService {
	rs := &ManagementFiltersService{s: s}
	return rs
}

type ManagementFiltersService struct {
	s *Service
}

func NewManagementGoalsService(s *Service) *ManagementGoalsService {
	rs := &ManagementGoalsService{s: s}
	return rs
}

type ManagementGoalsService struct {
	s *Service
}

func NewManagementProfileFilterLinksService(s *Service) *ManagementProfileFilterLinksService {
	rs := &ManagementProfileFilterLinksService{s: s}
	return rs
}

type ManagementProfileFilterLinksService struct {
	s *Service
}

func NewManagementProfileUserLinksService(s *Service) *ManagementProfileUserLinksService {
	rs := &ManagementProfileUserLinksService{s: s}
	return rs
}

type ManagementProfileUserLinksService struct {
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

func NewManagementUnsampledReportsService(s *Service) *ManagementUnsampledReportsService {
	rs := &ManagementUnsampledReportsService{s: s}
	return rs
}

type ManagementUnsampledReportsService struct {
	s *Service
}

func NewManagementUploadsService(s *Service) *ManagementUploadsService {
	rs := &ManagementUploadsService{s: s}
	return rs
}

type ManagementUploadsService struct {
	s *Service
}

func NewManagementWebPropertyAdWordsLinksService(s *Service) *ManagementWebPropertyAdWordsLinksService {
	rs := &ManagementWebPropertyAdWordsLinksService{s: s}
	return rs
}

type ManagementWebPropertyAdWordsLinksService struct {
	s *Service
}

func NewManagementWebpropertiesService(s *Service) *ManagementWebpropertiesService {
	rs := &ManagementWebpropertiesService{s: s}
	return rs
}

type ManagementWebpropertiesService struct {
	s *Service
}

func NewManagementWebpropertyUserLinksService(s *Service) *ManagementWebpropertyUserLinksService {
	rs := &ManagementWebpropertyUserLinksService{s: s}
	return rs
}

type ManagementWebpropertyUserLinksService struct {
	s *Service
}

func NewMetadataService(s *Service) *MetadataService {
	rs := &MetadataService{s: s}
	rs.Columns = NewMetadataColumnsService(s)
	return rs
}

type MetadataService struct {
	s *Service

	Columns *MetadataColumnsService
}

func NewMetadataColumnsService(s *Service) *MetadataColumnsService {
	rs := &MetadataColumnsService{s: s}
	return rs
}

type MetadataColumnsService struct {
	s *Service
}

func NewProvisioningService(s *Service) *ProvisioningService {
	rs := &ProvisioningService{s: s}
	return rs
}

type ProvisioningService struct {
	s *Service
}

// Account: JSON template for Analytics account entry.
type Account struct {
	// ChildLink: Child link for an account entry. Points to the list of web
	// properties for this account.
	ChildLink *AccountChildLink `json:"childLink,omitempty"`

	// Created: Time the account was created.
	Created string `json:"created,omitempty"`

	// Id: Account ID.
	Id string `json:"id,omitempty"`

	// Kind: Resource type for Analytics account.
	Kind string `json:"kind,omitempty"`

	// Name: Account name.
	Name string `json:"name,omitempty"`

	// Permissions: Permissions the user has for this account.
	Permissions *AccountPermissions `json:"permissions,omitempty"`

	// SelfLink: Link for this account.
	SelfLink string `json:"selfLink,omitempty"`

	// Updated: Time the account was last modified.
	Updated string `json:"updated,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChildLink") to
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

// AccountChildLink: Child link for an account entry. Points to the list
// of web properties for this account.
type AccountChildLink struct {
	// Href: Link to the list of web properties for this account.
	Href string `json:"href,omitempty"`

	// Type: Type of the child link. Its value is "analytics#webproperties".
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Href") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AccountChildLink) MarshalJSON() ([]byte, error) {
	type noMethod AccountChildLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AccountPermissions: Permissions the user has for this account.
type AccountPermissions struct {
	// Effective: All the permissions that the user has for this account.
	// These include any implied permissions (e.g., EDIT implies VIEW).
	Effective []string `json:"effective,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Effective") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AccountPermissions) MarshalJSON() ([]byte, error) {
	type noMethod AccountPermissions
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AccountRef: JSON template for a linked account.
type AccountRef struct {
	// Href: Link for this account.
	Href string `json:"href,omitempty"`

	// Id: Account ID.
	Id string `json:"id,omitempty"`

	// Kind: Analytics account reference.
	Kind string `json:"kind,omitempty"`

	// Name: Account name.
	Name string `json:"name,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Href") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AccountRef) MarshalJSON() ([]byte, error) {
	type noMethod AccountRef
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AccountSummaries: An AccountSummary collection lists a summary of
// accounts, properties and views (profiles) to which the user has
// access. Each resource in the collection corresponds to a single
// AccountSummary.
type AccountSummaries struct {
	// Items: A list of AccountSummaries.
	Items []*AccountSummary `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of resources the response can
	// contain, regardless of the actual number of resources returned. Its
	// value ranges from 1 to 1000 with a value of 1000 by default, or
	// otherwise specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this AccountSummary collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this AccountSummary
	// collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the resources, which is 1 by
	// default or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of results in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// Username: Email ID of the authenticated user
	Username string `json:"username,omitempty"`

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

func (s *AccountSummaries) MarshalJSON() ([]byte, error) {
	type noMethod AccountSummaries
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AccountSummary: JSON template for an Analytics AccountSummary. An
// AccountSummary is a lightweight tree comprised of
// properties/profiles.
type AccountSummary struct {
	// Id: Account ID.
	Id string `json:"id,omitempty"`

	// Kind: Resource type for Analytics AccountSummary.
	Kind string `json:"kind,omitempty"`

	// Name: Account name.
	Name string `json:"name,omitempty"`

	// WebProperties: List of web properties under this account.
	WebProperties []*WebPropertySummary `json:"webProperties,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AccountSummary) MarshalJSON() ([]byte, error) {
	type noMethod AccountSummary
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AccountTicket: JSON template for an Analytics account ticket. The
// account ticket consists of the ticket ID and the basic information
// for the account, property and profile.
type AccountTicket struct {
	// Account: Account for this ticket.
	Account *Account `json:"account,omitempty"`

	// Id: Account ticket ID used to access the account ticket.
	Id string `json:"id,omitempty"`

	// Kind: Resource type for account ticket.
	Kind string `json:"kind,omitempty"`

	// Profile: View (Profile) for the account.
	Profile *Profile `json:"profile,omitempty"`

	// RedirectUri: Redirect URI where the user will be sent after accepting
	// Terms of Service. Must be configured in APIs console as a callback
	// URL.
	RedirectUri string `json:"redirectUri,omitempty"`

	// Webproperty: Web property for the account.
	Webproperty *Webproperty `json:"webproperty,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Account") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AccountTicket) MarshalJSON() ([]byte, error) {
	type noMethod AccountTicket
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Accounts: An account collection provides a list of Analytics accounts
// to which a user has access. The account collection is the entry point
// to all management information. Each resource in the collection
// corresponds to a single Analytics account.
type Accounts struct {
	// Items: A list of accounts.
	Items []*Account `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of entries the response can contain,
	// regardless of the actual number of entries returned. Its value ranges
	// from 1 to 1000 with a value of 1000 by default, or otherwise
	// specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Next link for this account collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Previous link for this account collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the entries, which is 1 by default
	// or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of results in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// Username: Email ID of the authenticated user
	Username string `json:"username,omitempty"`

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

func (s *Accounts) MarshalJSON() ([]byte, error) {
	type noMethod Accounts
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AdWordsAccount: JSON template for an AdWords account.
type AdWordsAccount struct {
	// AutoTaggingEnabled: True if auto-tagging is enabled on the AdWords
	// account. Read-only after the insert operation.
	AutoTaggingEnabled bool `json:"autoTaggingEnabled,omitempty"`

	// CustomerId: Customer ID. This field is required when creating an
	// AdWords link.
	CustomerId string `json:"customerId,omitempty"`

	// Kind: Resource type for AdWords account.
	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AutoTaggingEnabled")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AdWordsAccount) MarshalJSON() ([]byte, error) {
	type noMethod AdWordsAccount
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AnalyticsDataimportDeleteUploadDataRequest: Request template for the
// delete upload data request.
type AnalyticsDataimportDeleteUploadDataRequest struct {
	// CustomDataImportUids: A list of upload UIDs.
	CustomDataImportUids []string `json:"customDataImportUids,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "CustomDataImportUids") to unconditionally include in API requests.
	// By default, fields with empty values are omitted from API requests.
	// However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AnalyticsDataimportDeleteUploadDataRequest) MarshalJSON() ([]byte, error) {
	type noMethod AnalyticsDataimportDeleteUploadDataRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Column: JSON template for a metadata column.
type Column struct {
	// Attributes: Map of attribute name and value for this column.
	Attributes map[string]string `json:"attributes,omitempty"`

	// Id: Column id.
	Id string `json:"id,omitempty"`

	// Kind: Resource type for Analytics column.
	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Attributes") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Column) MarshalJSON() ([]byte, error) {
	type noMethod Column
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Columns: Lists columns (dimensions and metrics) for a particular
// report type.
type Columns struct {
	// AttributeNames: List of attributes names returned by columns.
	AttributeNames []string `json:"attributeNames,omitempty"`

	// Etag: Etag of collection. This etag can be compared with the last
	// response etag to check if response has changed.
	Etag string `json:"etag,omitempty"`

	// Items: List of columns for a report type.
	Items []*Column `json:"items,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// TotalResults: Total number of columns returned in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AttributeNames") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Columns) MarshalJSON() ([]byte, error) {
	type noMethod Columns
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CustomDataSource: JSON template for an Analytics custom data source.
type CustomDataSource struct {
	// AccountId: Account ID to which this custom data source belongs.
	AccountId string `json:"accountId,omitempty"`

	ChildLink *CustomDataSourceChildLink `json:"childLink,omitempty"`

	// Created: Time this custom data source was created.
	Created string `json:"created,omitempty"`

	// Description: Description of custom data source.
	Description string `json:"description,omitempty"`

	// Id: Custom data source ID.
	Id string `json:"id,omitempty"`

	ImportBehavior string `json:"importBehavior,omitempty"`

	// Kind: Resource type for Analytics custom data source.
	Kind string `json:"kind,omitempty"`

	// Name: Name of this custom data source.
	Name string `json:"name,omitempty"`

	// ParentLink: Parent link for this custom data source. Points to the
	// web property to which this custom data source belongs.
	ParentLink *CustomDataSourceParentLink `json:"parentLink,omitempty"`

	// ProfilesLinked: IDs of views (profiles) linked to the custom data
	// source.
	ProfilesLinked []string `json:"profilesLinked,omitempty"`

	// SelfLink: Link for this Analytics custom data source.
	SelfLink string `json:"selfLink,omitempty"`

	// Type: Type of the custom data source.
	Type string `json:"type,omitempty"`

	// Updated: Time this custom data source was last modified.
	Updated string `json:"updated,omitempty"`

	UploadType string `json:"uploadType,omitempty"`

	// WebPropertyId: Web property ID of the form UA-XXXXX-YY to which this
	// custom data source belongs.
	WebPropertyId string `json:"webPropertyId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CustomDataSource) MarshalJSON() ([]byte, error) {
	type noMethod CustomDataSource
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type CustomDataSourceChildLink struct {
	// Href: Link to the list of daily uploads for this custom data source.
	// Link to the list of uploads for this custom data source.
	Href string `json:"href,omitempty"`

	// Type: Value is "analytics#dailyUploads". Value is
	// "analytics#uploads".
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Href") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CustomDataSourceChildLink) MarshalJSON() ([]byte, error) {
	type noMethod CustomDataSourceChildLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CustomDataSourceParentLink: Parent link for this custom data source.
// Points to the web property to which this custom data source belongs.
type CustomDataSourceParentLink struct {
	// Href: Link to the web property to which this custom data source
	// belongs.
	Href string `json:"href,omitempty"`

	// Type: Value is "analytics#webproperty".
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Href") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CustomDataSourceParentLink) MarshalJSON() ([]byte, error) {
	type noMethod CustomDataSourceParentLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CustomDataSources: Lists Analytics custom data sources to which the
// user has access. Each resource in the collection corresponds to a
// single Analytics custom data source.
type CustomDataSources struct {
	// Items: Collection of custom data sources.
	Items []*CustomDataSource `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of resources the response can
	// contain, regardless of the actual number of resources returned. Its
	// value ranges from 1 to 1000 with a value of 1000 by default, or
	// otherwise specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this custom data source collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this custom data source
	// collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the resources, which is 1 by
	// default or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of results in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// Username: Email ID of the authenticated user
	Username string `json:"username,omitempty"`

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

func (s *CustomDataSources) MarshalJSON() ([]byte, error) {
	type noMethod CustomDataSources
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CustomDimension: JSON template for Analytics Custom Dimension.
type CustomDimension struct {
	// AccountId: Account ID.
	AccountId string `json:"accountId,omitempty"`

	// Active: Boolean indicating whether the custom dimension is active.
	Active bool `json:"active,omitempty"`

	// Created: Time the custom dimension was created.
	Created string `json:"created,omitempty"`

	// Id: Custom dimension ID.
	Id string `json:"id,omitempty"`

	// Index: Index of the custom dimension.
	Index int64 `json:"index,omitempty"`

	// Kind: Kind value for a custom dimension. Set to
	// "analytics#customDimension". It is a read-only field.
	Kind string `json:"kind,omitempty"`

	// Name: Name of the custom dimension.
	Name string `json:"name,omitempty"`

	// ParentLink: Parent link for the custom dimension. Points to the
	// property to which the custom dimension belongs.
	ParentLink *CustomDimensionParentLink `json:"parentLink,omitempty"`

	// Scope: Scope of the custom dimension: HIT, SESSION, USER or PRODUCT.
	Scope string `json:"scope,omitempty"`

	// SelfLink: Link for the custom dimension
	SelfLink string `json:"selfLink,omitempty"`

	// Updated: Time the custom dimension was last modified.
	Updated string `json:"updated,omitempty"`

	// WebPropertyId: Property ID.
	WebPropertyId string `json:"webPropertyId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CustomDimension) MarshalJSON() ([]byte, error) {
	type noMethod CustomDimension
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CustomDimensionParentLink: Parent link for the custom dimension.
// Points to the property to which the custom dimension belongs.
type CustomDimensionParentLink struct {
	// Href: Link to the property to which the custom dimension belongs.
	Href string `json:"href,omitempty"`

	// Type: Type of the parent link. Set to "analytics#webproperty".
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Href") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CustomDimensionParentLink) MarshalJSON() ([]byte, error) {
	type noMethod CustomDimensionParentLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CustomDimensions: A custom dimension collection lists Analytics
// custom dimensions to which the user has access. Each resource in the
// collection corresponds to a single Analytics custom dimension.
type CustomDimensions struct {
	// Items: Collection of custom dimensions.
	Items []*CustomDimension `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of resources the response can
	// contain, regardless of the actual number of resources returned. Its
	// value ranges from 1 to 1000 with a value of 1000 by default, or
	// otherwise specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this custom dimension collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this custom dimension
	// collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the resources, which is 1 by
	// default or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of results in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// Username: Email ID of the authenticated user
	Username string `json:"username,omitempty"`

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

func (s *CustomDimensions) MarshalJSON() ([]byte, error) {
	type noMethod CustomDimensions
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CustomMetric: JSON template for Analytics Custom Metric.
type CustomMetric struct {
	// AccountId: Account ID.
	AccountId string `json:"accountId,omitempty"`

	// Active: Boolean indicating whether the custom metric is active.
	Active bool `json:"active,omitempty"`

	// Created: Time the custom metric was created.
	Created string `json:"created,omitempty"`

	// Id: Custom metric ID.
	Id string `json:"id,omitempty"`

	// Index: Index of the custom metric.
	Index int64 `json:"index,omitempty"`

	// Kind: Kind value for a custom metric. Set to
	// "analytics#customMetric". It is a read-only field.
	Kind string `json:"kind,omitempty"`

	// MaxValue: Max value of custom metric.
	MaxValue string `json:"max_value,omitempty"`

	// MinValue: Min value of custom metric.
	MinValue string `json:"min_value,omitempty"`

	// Name: Name of the custom metric.
	Name string `json:"name,omitempty"`

	// ParentLink: Parent link for the custom metric. Points to the property
	// to which the custom metric belongs.
	ParentLink *CustomMetricParentLink `json:"parentLink,omitempty"`

	// Scope: Scope of the custom metric: HIT or PRODUCT.
	Scope string `json:"scope,omitempty"`

	// SelfLink: Link for the custom metric
	SelfLink string `json:"selfLink,omitempty"`

	// Type: Data type of custom metric.
	Type string `json:"type,omitempty"`

	// Updated: Time the custom metric was last modified.
	Updated string `json:"updated,omitempty"`

	// WebPropertyId: Property ID.
	WebPropertyId string `json:"webPropertyId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CustomMetric) MarshalJSON() ([]byte, error) {
	type noMethod CustomMetric
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CustomMetricParentLink: Parent link for the custom metric. Points to
// the property to which the custom metric belongs.
type CustomMetricParentLink struct {
	// Href: Link to the property to which the custom metric belongs.
	Href string `json:"href,omitempty"`

	// Type: Type of the parent link. Set to "analytics#webproperty".
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Href") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CustomMetricParentLink) MarshalJSON() ([]byte, error) {
	type noMethod CustomMetricParentLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CustomMetrics: A custom metric collection lists Analytics custom
// metrics to which the user has access. Each resource in the collection
// corresponds to a single Analytics custom metric.
type CustomMetrics struct {
	// Items: Collection of custom metrics.
	Items []*CustomMetric `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of resources the response can
	// contain, regardless of the actual number of resources returned. Its
	// value ranges from 1 to 1000 with a value of 1000 by default, or
	// otherwise specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this custom metric collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this custom metric
	// collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the resources, which is 1 by
	// default or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of results in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// Username: Email ID of the authenticated user
	Username string `json:"username,omitempty"`

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

func (s *CustomMetrics) MarshalJSON() ([]byte, error) {
	type noMethod CustomMetrics
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EntityAdWordsLink: JSON template for Analytics Entity AdWords Link.
type EntityAdWordsLink struct {
	// AdWordsAccounts: A list of AdWords client accounts. These cannot be
	// MCC accounts. This field is required when creating an AdWords link.
	// It cannot be empty.
	AdWordsAccounts []*AdWordsAccount `json:"adWordsAccounts,omitempty"`

	// Entity: Web property being linked.
	Entity *EntityAdWordsLinkEntity `json:"entity,omitempty"`

	// Id: Entity AdWords link ID
	Id string `json:"id,omitempty"`

	// Kind: Resource type for entity AdWords link.
	Kind string `json:"kind,omitempty"`

	// Name: Name of the link. This field is required when creating an
	// AdWords link.
	Name string `json:"name,omitempty"`

	// ProfileIds: IDs of linked Views (Profiles) represented as strings.
	ProfileIds []string `json:"profileIds,omitempty"`

	// SelfLink: URL link for this Google Analytics - Google AdWords link.
	SelfLink string `json:"selfLink,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AdWordsAccounts") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EntityAdWordsLink) MarshalJSON() ([]byte, error) {
	type noMethod EntityAdWordsLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EntityAdWordsLinkEntity: Web property being linked.
type EntityAdWordsLinkEntity struct {
	WebPropertyRef *WebPropertyRef `json:"webPropertyRef,omitempty"`

	// ForceSendFields is a list of field names (e.g. "WebPropertyRef") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EntityAdWordsLinkEntity) MarshalJSON() ([]byte, error) {
	type noMethod EntityAdWordsLinkEntity
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EntityAdWordsLinks: An entity AdWords link collection provides a list
// of GA-AdWords links Each resource in this collection corresponds to a
// single link.
type EntityAdWordsLinks struct {
	// Items: A list of entity AdWords links.
	Items []*EntityAdWordsLink `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of entries the response can contain,
	// regardless of the actual number of entries returned. Its value ranges
	// from 1 to 1000 with a value of 1000 by default, or otherwise
	// specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Next link for this AdWords link collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Previous link for this AdWords link collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the entries, which is 1 by default
	// or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of results in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

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

func (s *EntityAdWordsLinks) MarshalJSON() ([]byte, error) {
	type noMethod EntityAdWordsLinks
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EntityUserLink: JSON template for an Analytics Entity-User Link.
// Returns permissions that a user has for an entity.
type EntityUserLink struct {
	// Entity: Entity for this link. It can be an account, a web property,
	// or a view (profile).
	Entity *EntityUserLinkEntity `json:"entity,omitempty"`

	// Id: Entity user link ID
	Id string `json:"id,omitempty"`

	// Kind: Resource type for entity user link.
	Kind string `json:"kind,omitempty"`

	// Permissions: Permissions the user has for this entity.
	Permissions *EntityUserLinkPermissions `json:"permissions,omitempty"`

	// SelfLink: Self link for this resource.
	SelfLink string `json:"selfLink,omitempty"`

	// UserRef: User reference.
	UserRef *UserRef `json:"userRef,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Entity") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EntityUserLink) MarshalJSON() ([]byte, error) {
	type noMethod EntityUserLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EntityUserLinkEntity: Entity for this link. It can be an account, a
// web property, or a view (profile).
type EntityUserLinkEntity struct {
	// AccountRef: Account for this link.
	AccountRef *AccountRef `json:"accountRef,omitempty"`

	// ProfileRef: View (Profile) for this link.
	ProfileRef *ProfileRef `json:"profileRef,omitempty"`

	// WebPropertyRef: Web property for this link.
	WebPropertyRef *WebPropertyRef `json:"webPropertyRef,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AccountRef") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EntityUserLinkEntity) MarshalJSON() ([]byte, error) {
	type noMethod EntityUserLinkEntity
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EntityUserLinkPermissions: Permissions the user has for this entity.
type EntityUserLinkPermissions struct {
	// Effective: Effective permissions represent all the permissions that a
	// user has for this entity. These include any implied permissions
	// (e.g., EDIT implies VIEW) or inherited permissions from the parent
	// entity. Effective permissions are read-only.
	Effective []string `json:"effective,omitempty"`

	// Local: Permissions that a user has been assigned at this very level.
	// Does not include any implied or inherited permissions. Local
	// permissions are modifiable.
	Local []string `json:"local,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Effective") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *EntityUserLinkPermissions) MarshalJSON() ([]byte, error) {
	type noMethod EntityUserLinkPermissions
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// EntityUserLinks: An entity user link collection provides a list of
// Analytics ACL links Each resource in this collection corresponds to a
// single link.
type EntityUserLinks struct {
	// Items: A list of entity user links.
	Items []*EntityUserLink `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of entries the response can contain,
	// regardless of the actual number of entries returned. Its value ranges
	// from 1 to 1000 with a value of 1000 by default, or otherwise
	// specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Next link for this account collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Previous link for this account collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the entries, which is 1 by default
	// or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of results in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

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

func (s *EntityUserLinks) MarshalJSON() ([]byte, error) {
	type noMethod EntityUserLinks
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Experiment: JSON template for Analytics experiment resource.
type Experiment struct {
	// AccountId: Account ID to which this experiment belongs. This field is
	// read-only.
	AccountId string `json:"accountId,omitempty"`

	// Created: Time the experiment was created. This field is read-only.
	Created string `json:"created,omitempty"`

	// Description: Notes about this experiment.
	Description string `json:"description,omitempty"`

	// EditableInGaUi: If true, the end user will be able to edit the
	// experiment via the Google Analytics user interface.
	EditableInGaUi bool `json:"editableInGaUi,omitempty"`

	// EndTime: The ending time of the experiment (the time the status
	// changed from RUNNING to ENDED). This field is present only if the
	// experiment has ended. This field is read-only.
	EndTime string `json:"endTime,omitempty"`

	// EqualWeighting: Boolean specifying whether to distribute traffic
	// evenly across all variations. If the value is False, content
	// experiments follows the default behavior of adjusting traffic
	// dynamically based on variation performance. Optional -- defaults to
	// False. This field may not be changed for an experiment whose status
	// is ENDED.
	EqualWeighting bool `json:"equalWeighting,omitempty"`

	// Id: Experiment ID. Required for patch and update. Disallowed for
	// create.
	Id string `json:"id,omitempty"`

	// InternalWebPropertyId: Internal ID for the web property to which this
	// experiment belongs. This field is read-only.
	InternalWebPropertyId string `json:"internalWebPropertyId,omitempty"`

	// Kind: Resource type for an Analytics experiment. This field is
	// read-only.
	Kind string `json:"kind,omitempty"`

	// MinimumExperimentLengthInDays: An integer number in [3, 90].
	// Specifies the minimum length of the experiment. Can be changed for a
	// running experiment. This field may not be changed for an experiments
	// whose status is ENDED.
	MinimumExperimentLengthInDays int64 `json:"minimumExperimentLengthInDays,omitempty"`

	// Name: Experiment name. This field may not be changed for an
	// experiment whose status is ENDED. This field is required when
	// creating an experiment.
	Name string `json:"name,omitempty"`

	// ObjectiveMetric: The metric that the experiment is optimizing. Valid
	// values: "ga:goal(n)Completions", "ga:adsenseAdsClicks",
	// "ga:adsenseAdsViewed", "ga:adsenseRevenue", "ga:bounces",
	// "ga:pageviews", "ga:sessionDuration", "ga:transactions",
	// "ga:transactionRevenue". This field is required if status is
	// "RUNNING" and servingFramework is one of "REDIRECT" or "API".
	ObjectiveMetric string `json:"objectiveMetric,omitempty"`

	// OptimizationType: Whether the objectiveMetric should be minimized or
	// maximized. Possible values: "MAXIMUM", "MINIMUM". Optional--defaults
	// to "MAXIMUM". Cannot be specified without objectiveMetric. Cannot be
	// modified when status is "RUNNING" or "ENDED".
	OptimizationType string `json:"optimizationType,omitempty"`

	// ParentLink: Parent link for an experiment. Points to the view
	// (profile) to which this experiment belongs.
	ParentLink *ExperimentParentLink `json:"parentLink,omitempty"`

	// ProfileId: View (Profile) ID to which this experiment belongs. This
	// field is read-only.
	ProfileId string `json:"profileId,omitempty"`

	// ReasonExperimentEnded: Why the experiment ended. Possible values:
	// "STOPPED_BY_USER", "WINNER_FOUND", "EXPERIMENT_EXPIRED",
	// "ENDED_WITH_NO_WINNER", "GOAL_OBJECTIVE_CHANGED".
	// "ENDED_WITH_NO_WINNER" means that the experiment didn't expire but no
	// winner was projected to be found. If the experiment status is changed
	// via the API to ENDED this field is set to STOPPED_BY_USER. This field
	// is read-only.
	ReasonExperimentEnded string `json:"reasonExperimentEnded,omitempty"`

	// RewriteVariationUrlsAsOriginal: Boolean specifying whether variations
	// URLS are rewritten to match those of the original. This field may not
	// be changed for an experiments whose status is ENDED.
	RewriteVariationUrlsAsOriginal bool `json:"rewriteVariationUrlsAsOriginal,omitempty"`

	// SelfLink: Link for this experiment. This field is read-only.
	SelfLink string `json:"selfLink,omitempty"`

	// ServingFramework: The framework used to serve the experiment
	// variations and evaluate the results. One of:
	// - REDIRECT: Google Analytics redirects traffic to different variation
	// pages, reports the chosen variation and evaluates the results.
	// - API: Google Analytics chooses and reports the variation to serve
	// and evaluates the results; the caller is responsible for serving the
	// selected variation.
	// - EXTERNAL: The variations will be served externally and the chosen
	// variation reported to Google Analytics. The caller is responsible for
	// serving the selected variation and evaluating the results.
	ServingFramework string `json:"servingFramework,omitempty"`

	// Snippet: The snippet of code to include on the control page(s). This
	// field is read-only.
	Snippet string `json:"snippet,omitempty"`

	// StartTime: The starting time of the experiment (the time the status
	// changed from READY_TO_RUN to RUNNING). This field is present only if
	// the experiment has started. This field is read-only.
	StartTime string `json:"startTime,omitempty"`

	// Status: Experiment status. Possible values: "DRAFT", "READY_TO_RUN",
	// "RUNNING", "ENDED". Experiments can be created in the "DRAFT",
	// "READY_TO_RUN" or "RUNNING" state. This field is required when
	// creating an experiment.
	Status string `json:"status,omitempty"`

	// TrafficCoverage: A floating-point number in (0, 1]. Specifies the
	// fraction of the traffic that participates in the experiment. Can be
	// changed for a running experiment. This field may not be changed for
	// an experiments whose status is ENDED.
	TrafficCoverage float64 `json:"trafficCoverage,omitempty"`

	// Updated: Time the experiment was last modified. This field is
	// read-only.
	Updated string `json:"updated,omitempty"`

	// Variations: Array of variations. The first variation in the array is
	// the original. The number of variations may not change once an
	// experiment is in the RUNNING state. At least two variations are
	// required before status can be set to RUNNING.
	Variations []*ExperimentVariations `json:"variations,omitempty"`

	// WebPropertyId: Web property ID to which this experiment belongs. The
	// web property ID is of the form UA-XXXXX-YY. This field is read-only.
	WebPropertyId string `json:"webPropertyId,omitempty"`

	// WinnerConfidenceLevel: A floating-point number in (0, 1). Specifies
	// the necessary confidence level to choose a winner. This field may not
	// be changed for an experiments whose status is ENDED.
	WinnerConfidenceLevel float64 `json:"winnerConfidenceLevel,omitempty"`

	// WinnerFound: Boolean specifying whether a winner has been found for
	// this experiment. This field is read-only.
	WinnerFound bool `json:"winnerFound,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Experiment) MarshalJSON() ([]byte, error) {
	type noMethod Experiment
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ExperimentParentLink: Parent link for an experiment. Points to the
// view (profile) to which this experiment belongs.
type ExperimentParentLink struct {
	// Href: Link to the view (profile) to which this experiment belongs.
	// This field is read-only.
	Href string `json:"href,omitempty"`

	// Type: Value is "analytics#profile". This field is read-only.
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Href") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ExperimentParentLink) MarshalJSON() ([]byte, error) {
	type noMethod ExperimentParentLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ExperimentVariations struct {
	// Name: The name of the variation. This field is required when creating
	// an experiment. This field may not be changed for an experiment whose
	// status is ENDED.
	Name string `json:"name,omitempty"`

	// Status: Status of the variation. Possible values: "ACTIVE",
	// "INACTIVE". INACTIVE variations are not served. This field may not be
	// changed for an experiment whose status is ENDED.
	Status string `json:"status,omitempty"`

	// Url: The URL of the variation. This field may not be changed for an
	// experiment whose status is RUNNING or ENDED.
	Url string `json:"url,omitempty"`

	// Weight: Weight that this variation should receive. Only present if
	// the experiment is running. This field is read-only.
	Weight float64 `json:"weight,omitempty"`

	// Won: True if the experiment has ended and this variation performed
	// (statistically) significantly better than the original. This field is
	// read-only.
	Won bool `json:"won,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Name") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ExperimentVariations) MarshalJSON() ([]byte, error) {
	type noMethod ExperimentVariations
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Experiments: An experiment collection lists Analytics experiments to
// which the user has access. Each view (profile) can have a set of
// experiments. Each resource in the Experiment collection corresponds
// to a single Analytics experiment.
type Experiments struct {
	// Items: A list of experiments.
	Items []*Experiment `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of resources the response can
	// contain, regardless of the actual number of resources returned. Its
	// value ranges from 1 to 1000 with a value of 1000 by default, or
	// otherwise specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this experiment collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this experiment collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the resources, which is 1 by
	// default or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of resources in the result.
	TotalResults int64 `json:"totalResults,omitempty"`

	// Username: Email ID of the authenticated user
	Username string `json:"username,omitempty"`

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

func (s *Experiments) MarshalJSON() ([]byte, error) {
	type noMethod Experiments
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Filter: JSON template for an Analytics account filter.
type Filter struct {
	// AccountId: Account ID to which this filter belongs.
	AccountId string `json:"accountId,omitempty"`

	// AdvancedDetails: Details for the filter of the type ADVANCED.
	AdvancedDetails *FilterAdvancedDetails `json:"advancedDetails,omitempty"`

	// Created: Time this filter was created.
	Created string `json:"created,omitempty"`

	// ExcludeDetails: Details for the filter of the type EXCLUDE.
	ExcludeDetails *FilterExpression `json:"excludeDetails,omitempty"`

	// Id: Filter ID.
	Id string `json:"id,omitempty"`

	// IncludeDetails: Details for the filter of the type INCLUDE.
	IncludeDetails *FilterExpression `json:"includeDetails,omitempty"`

	// Kind: Resource type for Analytics filter.
	Kind string `json:"kind,omitempty"`

	// LowercaseDetails: Details for the filter of the type LOWER.
	LowercaseDetails *FilterLowercaseDetails `json:"lowercaseDetails,omitempty"`

	// Name: Name of this filter.
	Name string `json:"name,omitempty"`

	// ParentLink: Parent link for this filter. Points to the account to
	// which this filter belongs.
	ParentLink *FilterParentLink `json:"parentLink,omitempty"`

	// SearchAndReplaceDetails: Details for the filter of the type
	// SEARCH_AND_REPLACE.
	SearchAndReplaceDetails *FilterSearchAndReplaceDetails `json:"searchAndReplaceDetails,omitempty"`

	// SelfLink: Link for this filter.
	SelfLink string `json:"selfLink,omitempty"`

	// Type: Type of this filter. Possible values are INCLUDE, EXCLUDE,
	// LOWERCASE, UPPERCASE, SEARCH_AND_REPLACE and ADVANCED.
	Type string `json:"type,omitempty"`

	// Updated: Time this filter was last modified.
	Updated string `json:"updated,omitempty"`

	// UppercaseDetails: Details for the filter of the type UPPER.
	UppercaseDetails *FilterUppercaseDetails `json:"uppercaseDetails,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Filter) MarshalJSON() ([]byte, error) {
	type noMethod Filter
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FilterAdvancedDetails: Details for the filter of the type ADVANCED.
type FilterAdvancedDetails struct {
	// CaseSensitive: Indicates if the filter expressions are case
	// sensitive.
	CaseSensitive bool `json:"caseSensitive,omitempty"`

	// ExtractA: Expression to extract from field A.
	ExtractA string `json:"extractA,omitempty"`

	// ExtractB: Expression to extract from field B.
	ExtractB string `json:"extractB,omitempty"`

	// FieldA: Field A.
	FieldA string `json:"fieldA,omitempty"`

	// FieldAIndex: The Index of the custom dimension. Required if field is
	// a CUSTOM_DIMENSION.
	FieldAIndex int64 `json:"fieldAIndex,omitempty"`

	// FieldARequired: Indicates if field A is required to match.
	FieldARequired bool `json:"fieldARequired,omitempty"`

	// FieldB: Field B.
	FieldB string `json:"fieldB,omitempty"`

	// FieldBIndex: The Index of the custom dimension. Required if field is
	// a CUSTOM_DIMENSION.
	FieldBIndex int64 `json:"fieldBIndex,omitempty"`

	// FieldBRequired: Indicates if field B is required to match.
	FieldBRequired bool `json:"fieldBRequired,omitempty"`

	// OutputConstructor: Expression used to construct the output value.
	OutputConstructor string `json:"outputConstructor,omitempty"`

	// OutputToField: Output field.
	OutputToField string `json:"outputToField,omitempty"`

	// OutputToFieldIndex: The Index of the custom dimension. Required if
	// field is a CUSTOM_DIMENSION.
	OutputToFieldIndex int64 `json:"outputToFieldIndex,omitempty"`

	// OverrideOutputField: Indicates if the existing value of the output
	// field, if any, should be overridden by the output expression.
	OverrideOutputField bool `json:"overrideOutputField,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CaseSensitive") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FilterAdvancedDetails) MarshalJSON() ([]byte, error) {
	type noMethod FilterAdvancedDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FilterLowercaseDetails: Details for the filter of the type LOWER.
type FilterLowercaseDetails struct {
	// Field: Field to use in the filter.
	Field string `json:"field,omitempty"`

	// FieldIndex: The Index of the custom dimension. Required if field is a
	// CUSTOM_DIMENSION.
	FieldIndex int64 `json:"fieldIndex,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Field") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FilterLowercaseDetails) MarshalJSON() ([]byte, error) {
	type noMethod FilterLowercaseDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FilterParentLink: Parent link for this filter. Points to the account
// to which this filter belongs.
type FilterParentLink struct {
	// Href: Link to the account to which this filter belongs.
	Href string `json:"href,omitempty"`

	// Type: Value is "analytics#account".
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Href") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FilterParentLink) MarshalJSON() ([]byte, error) {
	type noMethod FilterParentLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FilterSearchAndReplaceDetails: Details for the filter of the type
// SEARCH_AND_REPLACE.
type FilterSearchAndReplaceDetails struct {
	// CaseSensitive: Determines if the filter is case sensitive.
	CaseSensitive bool `json:"caseSensitive,omitempty"`

	// Field: Field to use in the filter.
	Field string `json:"field,omitempty"`

	// FieldIndex: The Index of the custom dimension. Required if field is a
	// CUSTOM_DIMENSION.
	FieldIndex int64 `json:"fieldIndex,omitempty"`

	// ReplaceString: Term to replace the search term with.
	ReplaceString string `json:"replaceString,omitempty"`

	// SearchString: Term to search.
	SearchString string `json:"searchString,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CaseSensitive") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FilterSearchAndReplaceDetails) MarshalJSON() ([]byte, error) {
	type noMethod FilterSearchAndReplaceDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FilterUppercaseDetails: Details for the filter of the type UPPER.
type FilterUppercaseDetails struct {
	// Field: Field to use in the filter.
	Field string `json:"field,omitempty"`

	// FieldIndex: The Index of the custom dimension. Required if field is a
	// CUSTOM_DIMENSION.
	FieldIndex int64 `json:"fieldIndex,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Field") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FilterUppercaseDetails) MarshalJSON() ([]byte, error) {
	type noMethod FilterUppercaseDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FilterExpression: JSON template for an Analytics filter expression.
type FilterExpression struct {
	// CaseSensitive: Determines if the filter is case sensitive.
	CaseSensitive bool `json:"caseSensitive,omitempty"`

	// ExpressionValue: Filter expression value
	ExpressionValue string `json:"expressionValue,omitempty"`

	// Field: Field to filter. Possible values:
	// - Content and Traffic
	// - PAGE_REQUEST_URI,
	// - PAGE_HOSTNAME,
	// - PAGE_TITLE,
	// - REFERRAL,
	// - COST_DATA_URI (Campaign target URL),
	// - HIT_TYPE,
	// - INTERNAL_SEARCH_TERM,
	// - INTERNAL_SEARCH_TYPE,
	// - SOURCE_PROPERTY_TRACKING_ID,
	// - Campaign or AdGroup
	// - CAMPAIGN_SOURCE,
	// - CAMPAIGN_MEDIUM,
	// - CAMPAIGN_NAME,
	// - CAMPAIGN_AD_GROUP,
	// - CAMPAIGN_TERM,
	// - CAMPAIGN_CONTENT,
	// - CAMPAIGN_CODE,
	// - CAMPAIGN_REFERRAL_PATH,
	// - E-Commerce
	// - TRANSACTION_COUNTRY,
	// - TRANSACTION_REGION,
	// - TRANSACTION_CITY,
	// - TRANSACTION_AFFILIATION (Store or order location),
	// - ITEM_NAME,
	// - ITEM_CODE,
	// - ITEM_VARIATION,
	// - TRANSACTION_ID,
	// - TRANSACTION_CURRENCY_CODE,
	// - PRODUCT_ACTION_TYPE,
	// - Audience/Users
	// - BROWSER,
	// - BROWSER_VERSION,
	// - BROWSER_SIZE,
	// - PLATFORM,
	// - PLATFORM_VERSION,
	// - LANGUAGE,
	// - SCREEN_RESOLUTION,
	// - SCREEN_COLORS,
	// - JAVA_ENABLED (Boolean Field),
	// - FLASH_VERSION,
	// - GEO_SPEED (Connection speed),
	// - VISITOR_TYPE,
	// - GEO_ORGANIZATION (ISP organization),
	// - GEO_DOMAIN,
	// - GEO_IP_ADDRESS,
	// - GEO_IP_VERSION,
	// - Location
	// - GEO_COUNTRY,
	// - GEO_REGION,
	// - GEO_CITY,
	// - Event
	// - EVENT_CATEGORY,
	// - EVENT_ACTION,
	// - EVENT_LABEL,
	// - Other
	// - CUSTOM_FIELD_1,
	// - CUSTOM_FIELD_2,
	// - USER_DEFINED_VALUE,
	// - Application
	// - APP_ID,
	// - APP_INSTALLER_ID,
	// - APP_NAME,
	// - APP_VERSION,
	// - SCREEN,
	// - IS_APP (Boolean Field),
	// - IS_FATAL_EXCEPTION (Boolean Field),
	// - EXCEPTION_DESCRIPTION,
	// - Mobile device
	// - IS_MOBILE (Boolean Field, Deprecated. Use DEVICE_CATEGORY=mobile),
	//
	// - IS_TABLET (Boolean Field, Deprecated. Use DEVICE_CATEGORY=tablet),
	//
	// - DEVICE_CATEGORY,
	// - MOBILE_HAS_QWERTY_KEYBOARD (Boolean Field),
	// - MOBILE_HAS_NFC_SUPPORT (Boolean Field),
	// - MOBILE_HAS_CELLULAR_RADIO (Boolean Field),
	// - MOBILE_HAS_WIFI_SUPPORT (Boolean Field),
	// - MOBILE_BRAND_NAME,
	// - MOBILE_MODEL_NAME,
	// - MOBILE_MARKETING_NAME,
	// - MOBILE_POINTING_METHOD,
	// - Social
	// - SOCIAL_NETWORK,
	// - SOCIAL_ACTION,
	// - SOCIAL_ACTION_TARGET,
	// - Custom dimension
	// - CUSTOM_DIMENSION (See accompanying field index),
	Field string `json:"field,omitempty"`

	// FieldIndex: The Index of the custom dimension. Set only if the field
	// is a is CUSTOM_DIMENSION.
	FieldIndex int64 `json:"fieldIndex,omitempty"`

	// Kind: Kind value for filter expression
	Kind string `json:"kind,omitempty"`

	// MatchType: Match type for this filter. Possible values are
	// BEGINS_WITH, EQUAL, ENDS_WITH, CONTAINS, or MATCHES. GEO_DOMAIN,
	// GEO_IP_ADDRESS, PAGE_REQUEST_URI, or PAGE_HOSTNAME filters can use
	// any match type; all other filters must use MATCHES.
	MatchType string `json:"matchType,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CaseSensitive") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FilterExpression) MarshalJSON() ([]byte, error) {
	type noMethod FilterExpression
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FilterRef: JSON template for a profile filter link.
type FilterRef struct {
	// AccountId: Account ID to which this filter belongs.
	AccountId string `json:"accountId,omitempty"`

	// Href: Link for this filter.
	Href string `json:"href,omitempty"`

	// Id: Filter ID.
	Id string `json:"id,omitempty"`

	// Kind: Kind value for filter reference.
	Kind string `json:"kind,omitempty"`

	// Name: Name of this filter.
	Name string `json:"name,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FilterRef) MarshalJSON() ([]byte, error) {
	type noMethod FilterRef
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Filters: A filter collection lists filters created by users in an
// Analytics account. Each resource in the collection corresponds to a
// filter.
type Filters struct {
	// Items: A list of filters.
	Items []*Filter `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of resources the response can
	// contain, regardless of the actual number of resources returned. Its
	// value ranges from 1 to 1,000 with a value of 1000 by default, or
	// otherwise specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this filter collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this filter collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the resources, which is 1 by
	// default or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of results in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// Username: Email ID of the authenticated user
	Username string `json:"username,omitempty"`

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

func (s *Filters) MarshalJSON() ([]byte, error) {
	type noMethod Filters
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GaData: Analytics data for a given view (profile).
type GaData struct {
	// ColumnHeaders: Column headers that list dimension names followed by
	// the metric names. The order of dimensions and metrics is same as
	// specified in the request.
	ColumnHeaders []*GaDataColumnHeaders `json:"columnHeaders,omitempty"`

	// ContainsSampledData: Determines if Analytics data contains samples.
	ContainsSampledData bool `json:"containsSampledData,omitempty"`

	DataTable *GaDataDataTable `json:"dataTable,omitempty"`

	// Id: Unique ID for this data response.
	Id string `json:"id,omitempty"`

	// ItemsPerPage: The maximum number of rows the response can contain,
	// regardless of the actual number of rows returned. Its value ranges
	// from 1 to 10,000 with a value of 1000 by default, or otherwise
	// specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Resource type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this Analytics data query.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this Analytics data query.
	PreviousLink string `json:"previousLink,omitempty"`

	// ProfileInfo: Information for the view (profile), for which the
	// Analytics data was requested.
	ProfileInfo *GaDataProfileInfo `json:"profileInfo,omitempty"`

	// Query: Analytics data request query parameters.
	Query *GaDataQuery `json:"query,omitempty"`

	// Rows: Analytics data rows, where each row contains a list of
	// dimension values followed by the metric values. The order of
	// dimensions and metrics is same as specified in the request.
	Rows [][]string `json:"rows,omitempty"`

	// SampleSize: The number of samples used to calculate the result.
	SampleSize int64 `json:"sampleSize,omitempty,string"`

	// SampleSpace: Total size of the sample space from which the samples
	// were selected.
	SampleSpace int64 `json:"sampleSpace,omitempty,string"`

	// SelfLink: Link to this page.
	SelfLink string `json:"selfLink,omitempty"`

	// TotalResults: The total number of rows for the query, regardless of
	// the number of rows in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// TotalsForAllResults: Total values for the requested metrics over all
	// the results, not just the results returned in this response. The
	// order of the metric totals is same as the metric order specified in
	// the request.
	TotalsForAllResults map[string]string `json:"totalsForAllResults,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ColumnHeaders") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GaData) MarshalJSON() ([]byte, error) {
	type noMethod GaData
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type GaDataColumnHeaders struct {
	// ColumnType: Column Type. Either DIMENSION or METRIC.
	ColumnType string `json:"columnType,omitempty"`

	// DataType: Data type. Dimension column headers have only STRING as the
	// data type. Metric column headers have data types for metric values
	// such as INTEGER, DOUBLE, CURRENCY etc.
	DataType string `json:"dataType,omitempty"`

	// Name: Column name.
	Name string `json:"name,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ColumnType") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GaDataColumnHeaders) MarshalJSON() ([]byte, error) {
	type noMethod GaDataColumnHeaders
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type GaDataDataTable struct {
	Cols []*GaDataDataTableCols `json:"cols,omitempty"`

	Rows []*GaDataDataTableRows `json:"rows,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Cols") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GaDataDataTable) MarshalJSON() ([]byte, error) {
	type noMethod GaDataDataTable
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type GaDataDataTableCols struct {
	Id string `json:"id,omitempty"`

	Label string `json:"label,omitempty"`

	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GaDataDataTableCols) MarshalJSON() ([]byte, error) {
	type noMethod GaDataDataTableCols
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type GaDataDataTableRows struct {
	C []*GaDataDataTableRowsC `json:"c,omitempty"`

	// ForceSendFields is a list of field names (e.g. "C") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GaDataDataTableRows) MarshalJSON() ([]byte, error) {
	type noMethod GaDataDataTableRows
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type GaDataDataTableRowsC struct {
	V string `json:"v,omitempty"`

	// ForceSendFields is a list of field names (e.g. "V") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GaDataDataTableRowsC) MarshalJSON() ([]byte, error) {
	type noMethod GaDataDataTableRowsC
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GaDataProfileInfo: Information for the view (profile), for which the
// Analytics data was requested.
type GaDataProfileInfo struct {
	// AccountId: Account ID to which this view (profile) belongs.
	AccountId string `json:"accountId,omitempty"`

	// InternalWebPropertyId: Internal ID for the web property to which this
	// view (profile) belongs.
	InternalWebPropertyId string `json:"internalWebPropertyId,omitempty"`

	// ProfileId: View (Profile) ID.
	ProfileId string `json:"profileId,omitempty"`

	// ProfileName: View (Profile) name.
	ProfileName string `json:"profileName,omitempty"`

	// TableId: Table ID for view (profile).
	TableId string `json:"tableId,omitempty"`

	// WebPropertyId: Web Property ID to which this view (profile) belongs.
	WebPropertyId string `json:"webPropertyId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GaDataProfileInfo) MarshalJSON() ([]byte, error) {
	type noMethod GaDataProfileInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GaDataQuery: Analytics data request query parameters.
type GaDataQuery struct {
	// Dimensions: List of analytics dimensions.
	Dimensions string `json:"dimensions,omitempty"`

	// EndDate: End date.
	EndDate string `json:"end-date,omitempty"`

	// Filters: Comma-separated list of dimension or metric filters.
	Filters string `json:"filters,omitempty"`

	// Ids: Unique table ID.
	Ids string `json:"ids,omitempty"`

	// MaxResults: Maximum results per page.
	MaxResults int64 `json:"max-results,omitempty"`

	// Metrics: List of analytics metrics.
	Metrics []string `json:"metrics,omitempty"`

	// SamplingLevel: Desired sampling level
	SamplingLevel string `json:"samplingLevel,omitempty"`

	// Segment: Analytics advanced segment.
	Segment string `json:"segment,omitempty"`

	// Sort: List of dimensions or metrics based on which Analytics data is
	// sorted.
	Sort []string `json:"sort,omitempty"`

	// StartDate: Start date.
	StartDate string `json:"start-date,omitempty"`

	// StartIndex: Start index.
	StartIndex int64 `json:"start-index,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Dimensions") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GaDataQuery) MarshalJSON() ([]byte, error) {
	type noMethod GaDataQuery
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Goal: JSON template for Analytics goal resource.
type Goal struct {
	// AccountId: Account ID to which this goal belongs.
	AccountId string `json:"accountId,omitempty"`

	// Active: Determines whether this goal is active.
	Active bool `json:"active,omitempty"`

	// Created: Time this goal was created.
	Created string `json:"created,omitempty"`

	// EventDetails: Details for the goal of the type EVENT.
	EventDetails *GoalEventDetails `json:"eventDetails,omitempty"`

	// Id: Goal ID.
	Id string `json:"id,omitempty"`

	// InternalWebPropertyId: Internal ID for the web property to which this
	// goal belongs.
	InternalWebPropertyId string `json:"internalWebPropertyId,omitempty"`

	// Kind: Resource type for an Analytics goal.
	Kind string `json:"kind,omitempty"`

	// Name: Goal name.
	Name string `json:"name,omitempty"`

	// ParentLink: Parent link for a goal. Points to the view (profile) to
	// which this goal belongs.
	ParentLink *GoalParentLink `json:"parentLink,omitempty"`

	// ProfileId: View (Profile) ID to which this goal belongs.
	ProfileId string `json:"profileId,omitempty"`

	// SelfLink: Link for this goal.
	SelfLink string `json:"selfLink,omitempty"`

	// Type: Goal type. Possible values are URL_DESTINATION,
	// VISIT_TIME_ON_SITE, VISIT_NUM_PAGES, AND EVENT.
	Type string `json:"type,omitempty"`

	// Updated: Time this goal was last modified.
	Updated string `json:"updated,omitempty"`

	// UrlDestinationDetails: Details for the goal of the type
	// URL_DESTINATION.
	UrlDestinationDetails *GoalUrlDestinationDetails `json:"urlDestinationDetails,omitempty"`

	// Value: Goal value.
	Value float64 `json:"value,omitempty"`

	// VisitNumPagesDetails: Details for the goal of the type
	// VISIT_NUM_PAGES.
	VisitNumPagesDetails *GoalVisitNumPagesDetails `json:"visitNumPagesDetails,omitempty"`

	// VisitTimeOnSiteDetails: Details for the goal of the type
	// VISIT_TIME_ON_SITE.
	VisitTimeOnSiteDetails *GoalVisitTimeOnSiteDetails `json:"visitTimeOnSiteDetails,omitempty"`

	// WebPropertyId: Web property ID to which this goal belongs. The web
	// property ID is of the form UA-XXXXX-YY.
	WebPropertyId string `json:"webPropertyId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Goal) MarshalJSON() ([]byte, error) {
	type noMethod Goal
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GoalEventDetails: Details for the goal of the type EVENT.
type GoalEventDetails struct {
	// EventConditions: List of event conditions.
	EventConditions []*GoalEventDetailsEventConditions `json:"eventConditions,omitempty"`

	// UseEventValue: Determines if the event value should be used as the
	// value for this goal.
	UseEventValue bool `json:"useEventValue,omitempty"`

	// ForceSendFields is a list of field names (e.g. "EventConditions") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GoalEventDetails) MarshalJSON() ([]byte, error) {
	type noMethod GoalEventDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type GoalEventDetailsEventConditions struct {
	// ComparisonType: Type of comparison. Possible values are LESS_THAN,
	// GREATER_THAN or EQUAL.
	ComparisonType string `json:"comparisonType,omitempty"`

	// ComparisonValue: Value used for this comparison.
	ComparisonValue int64 `json:"comparisonValue,omitempty,string"`

	// Expression: Expression used for this match.
	Expression string `json:"expression,omitempty"`

	// MatchType: Type of the match to be performed. Possible values are
	// REGEXP, BEGINS_WITH, or EXACT.
	MatchType string `json:"matchType,omitempty"`

	// Type: Type of this event condition. Possible values are CATEGORY,
	// ACTION, LABEL, or VALUE.
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ComparisonType") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GoalEventDetailsEventConditions) MarshalJSON() ([]byte, error) {
	type noMethod GoalEventDetailsEventConditions
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GoalParentLink: Parent link for a goal. Points to the view (profile)
// to which this goal belongs.
type GoalParentLink struct {
	// Href: Link to the view (profile) to which this goal belongs.
	Href string `json:"href,omitempty"`

	// Type: Value is "analytics#profile".
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Href") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GoalParentLink) MarshalJSON() ([]byte, error) {
	type noMethod GoalParentLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GoalUrlDestinationDetails: Details for the goal of the type
// URL_DESTINATION.
type GoalUrlDestinationDetails struct {
	// CaseSensitive: Determines if the goal URL must exactly match the
	// capitalization of visited URLs.
	CaseSensitive bool `json:"caseSensitive,omitempty"`

	// FirstStepRequired: Determines if the first step in this goal is
	// required.
	FirstStepRequired bool `json:"firstStepRequired,omitempty"`

	// MatchType: Match type for the goal URL. Possible values are HEAD,
	// EXACT, or REGEX.
	MatchType string `json:"matchType,omitempty"`

	// Steps: List of steps configured for this goal funnel.
	Steps []*GoalUrlDestinationDetailsSteps `json:"steps,omitempty"`

	// Url: URL for this goal.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CaseSensitive") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GoalUrlDestinationDetails) MarshalJSON() ([]byte, error) {
	type noMethod GoalUrlDestinationDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type GoalUrlDestinationDetailsSteps struct {
	// Name: Step name.
	Name string `json:"name,omitempty"`

	// Number: Step number.
	Number int64 `json:"number,omitempty"`

	// Url: URL for this step.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Name") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GoalUrlDestinationDetailsSteps) MarshalJSON() ([]byte, error) {
	type noMethod GoalUrlDestinationDetailsSteps
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GoalVisitNumPagesDetails: Details for the goal of the type
// VISIT_NUM_PAGES.
type GoalVisitNumPagesDetails struct {
	// ComparisonType: Type of comparison. Possible values are LESS_THAN,
	// GREATER_THAN, or EQUAL.
	ComparisonType string `json:"comparisonType,omitempty"`

	// ComparisonValue: Value used for this comparison.
	ComparisonValue int64 `json:"comparisonValue,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "ComparisonType") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GoalVisitNumPagesDetails) MarshalJSON() ([]byte, error) {
	type noMethod GoalVisitNumPagesDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GoalVisitTimeOnSiteDetails: Details for the goal of the type
// VISIT_TIME_ON_SITE.
type GoalVisitTimeOnSiteDetails struct {
	// ComparisonType: Type of comparison. Possible values are LESS_THAN or
	// GREATER_THAN.
	ComparisonType string `json:"comparisonType,omitempty"`

	// ComparisonValue: Value used for this comparison.
	ComparisonValue int64 `json:"comparisonValue,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "ComparisonType") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GoalVisitTimeOnSiteDetails) MarshalJSON() ([]byte, error) {
	type noMethod GoalVisitTimeOnSiteDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Goals: A goal collection lists Analytics goals to which the user has
// access. Each view (profile) can have a set of goals. Each resource in
// the Goal collection corresponds to a single Analytics goal.
type Goals struct {
	// Items: A list of goals.
	Items []*Goal `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of resources the response can
	// contain, regardless of the actual number of resources returned. Its
	// value ranges from 1 to 1000 with a value of 1000 by default, or
	// otherwise specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this goal collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this goal collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the resources, which is 1 by
	// default or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of resources in the result.
	TotalResults int64 `json:"totalResults,omitempty"`

	// Username: Email ID of the authenticated user
	Username string `json:"username,omitempty"`

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

func (s *Goals) MarshalJSON() ([]byte, error) {
	type noMethod Goals
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// McfData: Multi-Channel Funnels data for a given view (profile).
type McfData struct {
	// ColumnHeaders: Column headers that list dimension names followed by
	// the metric names. The order of dimensions and metrics is same as
	// specified in the request.
	ColumnHeaders []*McfDataColumnHeaders `json:"columnHeaders,omitempty"`

	// ContainsSampledData: Determines if the Analytics data contains
	// sampled data.
	ContainsSampledData bool `json:"containsSampledData,omitempty"`

	// Id: Unique ID for this data response.
	Id string `json:"id,omitempty"`

	// ItemsPerPage: The maximum number of rows the response can contain,
	// regardless of the actual number of rows returned. Its value ranges
	// from 1 to 10,000 with a value of 1000 by default, or otherwise
	// specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Resource type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this Analytics data query.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this Analytics data query.
	PreviousLink string `json:"previousLink,omitempty"`

	// ProfileInfo: Information for the view (profile), for which the
	// Analytics data was requested.
	ProfileInfo *McfDataProfileInfo `json:"profileInfo,omitempty"`

	// Query: Analytics data request query parameters.
	Query *McfDataQuery `json:"query,omitempty"`

	// Rows: Analytics data rows, where each row contains a list of
	// dimension values followed by the metric values. The order of
	// dimensions and metrics is same as specified in the request.
	Rows [][]*McfDataRowsItem `json:"rows,omitempty"`

	// SampleSize: The number of samples used to calculate the result.
	SampleSize int64 `json:"sampleSize,omitempty,string"`

	// SampleSpace: Total size of the sample space from which the samples
	// were selected.
	SampleSpace int64 `json:"sampleSpace,omitempty,string"`

	// SelfLink: Link to this page.
	SelfLink string `json:"selfLink,omitempty"`

	// TotalResults: The total number of rows for the query, regardless of
	// the number of rows in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// TotalsForAllResults: Total values for the requested metrics over all
	// the results, not just the results returned in this response. The
	// order of the metric totals is same as the metric order specified in
	// the request.
	TotalsForAllResults map[string]string `json:"totalsForAllResults,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ColumnHeaders") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *McfData) MarshalJSON() ([]byte, error) {
	type noMethod McfData
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type McfDataColumnHeaders struct {
	// ColumnType: Column Type. Either DIMENSION or METRIC.
	ColumnType string `json:"columnType,omitempty"`

	// DataType: Data type. Dimension and metric values data types such as
	// INTEGER, DOUBLE, CURRENCY, MCF_SEQUENCE etc.
	DataType string `json:"dataType,omitempty"`

	// Name: Column name.
	Name string `json:"name,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ColumnType") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *McfDataColumnHeaders) MarshalJSON() ([]byte, error) {
	type noMethod McfDataColumnHeaders
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// McfDataProfileInfo: Information for the view (profile), for which the
// Analytics data was requested.
type McfDataProfileInfo struct {
	// AccountId: Account ID to which this view (profile) belongs.
	AccountId string `json:"accountId,omitempty"`

	// InternalWebPropertyId: Internal ID for the web property to which this
	// view (profile) belongs.
	InternalWebPropertyId string `json:"internalWebPropertyId,omitempty"`

	// ProfileId: View (Profile) ID.
	ProfileId string `json:"profileId,omitempty"`

	// ProfileName: View (Profile) name.
	ProfileName string `json:"profileName,omitempty"`

	// TableId: Table ID for view (profile).
	TableId string `json:"tableId,omitempty"`

	// WebPropertyId: Web Property ID to which this view (profile) belongs.
	WebPropertyId string `json:"webPropertyId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *McfDataProfileInfo) MarshalJSON() ([]byte, error) {
	type noMethod McfDataProfileInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// McfDataQuery: Analytics data request query parameters.
type McfDataQuery struct {
	// Dimensions: List of analytics dimensions.
	Dimensions string `json:"dimensions,omitempty"`

	// EndDate: End date.
	EndDate string `json:"end-date,omitempty"`

	// Filters: Comma-separated list of dimension or metric filters.
	Filters string `json:"filters,omitempty"`

	// Ids: Unique table ID.
	Ids string `json:"ids,omitempty"`

	// MaxResults: Maximum results per page.
	MaxResults int64 `json:"max-results,omitempty"`

	// Metrics: List of analytics metrics.
	Metrics []string `json:"metrics,omitempty"`

	// SamplingLevel: Desired sampling level
	SamplingLevel string `json:"samplingLevel,omitempty"`

	// Segment: Analytics advanced segment.
	Segment string `json:"segment,omitempty"`

	// Sort: List of dimensions or metrics based on which Analytics data is
	// sorted.
	Sort []string `json:"sort,omitempty"`

	// StartDate: Start date.
	StartDate string `json:"start-date,omitempty"`

	// StartIndex: Start index.
	StartIndex int64 `json:"start-index,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Dimensions") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *McfDataQuery) MarshalJSON() ([]byte, error) {
	type noMethod McfDataQuery
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// McfDataRowsItem: A union object representing a dimension or metric
// value. Only one of "primitiveValue" or "conversionPathValue"
// attribute will be populated.
type McfDataRowsItem struct {
	// ConversionPathValue: A conversion path dimension value, containing a
	// list of interactions with their attributes.
	ConversionPathValue []*McfDataRowsItemConversionPathValue `json:"conversionPathValue,omitempty"`

	// PrimitiveValue: A primitive dimension value. A primitive metric
	// value.
	PrimitiveValue string `json:"primitiveValue,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ConversionPathValue")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *McfDataRowsItem) MarshalJSON() ([]byte, error) {
	type noMethod McfDataRowsItem
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type McfDataRowsItemConversionPathValue struct {
	// InteractionType: Type of an interaction on conversion path. Such as
	// CLICK, IMPRESSION etc.
	InteractionType string `json:"interactionType,omitempty"`

	// NodeValue: Node value of an interaction on conversion path. Such as
	// source, medium etc.
	NodeValue string `json:"nodeValue,omitempty"`

	// ForceSendFields is a list of field names (e.g. "InteractionType") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *McfDataRowsItemConversionPathValue) MarshalJSON() ([]byte, error) {
	type noMethod McfDataRowsItemConversionPathValue
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Profile: JSON template for an Analytics view (profile).
type Profile struct {
	// AccountId: Account ID to which this view (profile) belongs.
	AccountId string `json:"accountId,omitempty"`

	// ChildLink: Child link for this view (profile). Points to the list of
	// goals for this view (profile).
	ChildLink *ProfileChildLink `json:"childLink,omitempty"`

	// Created: Time this view (profile) was created.
	Created string `json:"created,omitempty"`

	// Currency: The currency type associated with this view (profile),
	// defaults to USD. The supported values are:
	// ARS, AUD, BGN, BRL, CAD, CHF, CNY, CZK, DKK, EUR, GBP, HKD, HUF, IDR,
	// INR, JPY, KRW, LTL, MXN, NOK, NZD, PHP, PLN, RUB, SEK, THB, TRY, TWD,
	// USD, VND, ZAR
	Currency string `json:"currency,omitempty"`

	// DefaultPage: Default page for this view (profile).
	DefaultPage string `json:"defaultPage,omitempty"`

	// ECommerceTracking: Indicates whether ecommerce tracking is enabled
	// for this view (profile).
	ECommerceTracking bool `json:"eCommerceTracking,omitempty"`

	// EnhancedECommerceTracking: Indicates whether enhanced ecommerce
	// tracking is enabled for this view (profile). This property can only
	// be enabled if ecommerce tracking is enabled.
	EnhancedECommerceTracking bool `json:"enhancedECommerceTracking,omitempty"`

	// ExcludeQueryParameters: The query parameters that are excluded from
	// this view (profile).
	ExcludeQueryParameters string `json:"excludeQueryParameters,omitempty"`

	// Id: View (Profile) ID.
	Id string `json:"id,omitempty"`

	// InternalWebPropertyId: Internal ID for the web property to which this
	// view (profile) belongs.
	InternalWebPropertyId string `json:"internalWebPropertyId,omitempty"`

	// Kind: Resource type for Analytics view (profile).
	Kind string `json:"kind,omitempty"`

	// Name: Name of this view (profile).
	Name string `json:"name,omitempty"`

	// ParentLink: Parent link for this view (profile). Points to the web
	// property to which this view (profile) belongs.
	ParentLink *ProfileParentLink `json:"parentLink,omitempty"`

	// Permissions: Permissions the user has for this view (profile).
	Permissions *ProfilePermissions `json:"permissions,omitempty"`

	// SelfLink: Link for this view (profile).
	SelfLink string `json:"selfLink,omitempty"`

	// SiteSearchCategoryParameters: Site search category parameters for
	// this view (profile).
	SiteSearchCategoryParameters string `json:"siteSearchCategoryParameters,omitempty"`

	// SiteSearchQueryParameters: The site search query parameters for this
	// view (profile).
	SiteSearchQueryParameters string `json:"siteSearchQueryParameters,omitempty"`

	// StripSiteSearchCategoryParameters: Whether or not Analytics will
	// strip search category parameters from the URLs in your reports.
	StripSiteSearchCategoryParameters bool `json:"stripSiteSearchCategoryParameters,omitempty"`

	// StripSiteSearchQueryParameters: Whether or not Analytics will strip
	// search query parameters from the URLs in your reports.
	StripSiteSearchQueryParameters bool `json:"stripSiteSearchQueryParameters,omitempty"`

	// Timezone: Time zone for which this view (profile) has been
	// configured. Time zones are identified by strings from the TZ
	// database.
	Timezone string `json:"timezone,omitempty"`

	// Type: View (Profile) type. Supported types: WEB or APP.
	Type string `json:"type,omitempty"`

	// Updated: Time this view (profile) was last modified.
	Updated string `json:"updated,omitempty"`

	// WebPropertyId: Web property ID of the form UA-XXXXX-YY to which this
	// view (profile) belongs.
	WebPropertyId string `json:"webPropertyId,omitempty"`

	// WebsiteUrl: Website URL for this view (profile).
	WebsiteUrl string `json:"websiteUrl,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Profile) MarshalJSON() ([]byte, error) {
	type noMethod Profile
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ProfileChildLink: Child link for this view (profile). Points to the
// list of goals for this view (profile).
type ProfileChildLink struct {
	// Href: Link to the list of goals for this view (profile).
	Href string `json:"href,omitempty"`

	// Type: Value is "analytics#goals".
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Href") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ProfileChildLink) MarshalJSON() ([]byte, error) {
	type noMethod ProfileChildLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ProfileParentLink: Parent link for this view (profile). Points to the
// web property to which this view (profile) belongs.
type ProfileParentLink struct {
	// Href: Link to the web property to which this view (profile) belongs.
	Href string `json:"href,omitempty"`

	// Type: Value is "analytics#webproperty".
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Href") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ProfileParentLink) MarshalJSON() ([]byte, error) {
	type noMethod ProfileParentLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ProfilePermissions: Permissions the user has for this view (profile).
type ProfilePermissions struct {
	// Effective: All the permissions that the user has for this view
	// (profile). These include any implied permissions (e.g., EDIT implies
	// VIEW) or inherited permissions from the parent web property.
	Effective []string `json:"effective,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Effective") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ProfilePermissions) MarshalJSON() ([]byte, error) {
	type noMethod ProfilePermissions
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ProfileFilterLink: JSON template for an Analytics profile filter
// link.
type ProfileFilterLink struct {
	// FilterRef: Filter for this link.
	FilterRef *FilterRef `json:"filterRef,omitempty"`

	// Id: Profile filter link ID.
	Id string `json:"id,omitempty"`

	// Kind: Resource type for Analytics filter.
	Kind string `json:"kind,omitempty"`

	// ProfileRef: View (Profile) for this link.
	ProfileRef *ProfileRef `json:"profileRef,omitempty"`

	// Rank: The rank of this profile filter link relative to the other
	// filters linked to the same profile.
	// For readonly (i.e., list and get) operations, the rank always starts
	// at 1.
	// For write (i.e., create, update, or delete) operations, you may
	// specify a value between 0 and 255 inclusively, [0, 255]. In order to
	// insert a link at the end of the list, either don't specify a rank or
	// set a rank to a number greater than the largest rank in the list. In
	// order to insert a link to the beginning of the list specify a rank
	// that is less than or equal to 1. The new link will move all existing
	// filters with the same or lower rank down the list. After the link is
	// inserted/updated/deleted all profile filter links will be renumbered
	// starting at 1.
	Rank int64 `json:"rank,omitempty"`

	// SelfLink: Link for this profile filter link.
	SelfLink string `json:"selfLink,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "FilterRef") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ProfileFilterLink) MarshalJSON() ([]byte, error) {
	type noMethod ProfileFilterLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ProfileFilterLinks: A profile filter link collection lists profile
// filter links between profiles and filters. Each resource in the
// collection corresponds to a profile filter link.
type ProfileFilterLinks struct {
	// Items: A list of profile filter links.
	Items []*ProfileFilterLink `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of resources the response can
	// contain, regardless of the actual number of resources returned. Its
	// value ranges from 1 to 1,000 with a value of 1000 by default, or
	// otherwise specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this profile filter link collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this profile filter link
	// collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the resources, which is 1 by
	// default or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of results in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// Username: Email ID of the authenticated user
	Username string `json:"username,omitempty"`

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

func (s *ProfileFilterLinks) MarshalJSON() ([]byte, error) {
	type noMethod ProfileFilterLinks
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ProfileRef: JSON template for a linked view (profile).
type ProfileRef struct {
	// AccountId: Account ID to which this view (profile) belongs.
	AccountId string `json:"accountId,omitempty"`

	// Href: Link for this view (profile).
	Href string `json:"href,omitempty"`

	// Id: View (Profile) ID.
	Id string `json:"id,omitempty"`

	// InternalWebPropertyId: Internal ID for the web property to which this
	// view (profile) belongs.
	InternalWebPropertyId string `json:"internalWebPropertyId,omitempty"`

	// Kind: Analytics view (profile) reference.
	Kind string `json:"kind,omitempty"`

	// Name: Name of this view (profile).
	Name string `json:"name,omitempty"`

	// WebPropertyId: Web property ID of the form UA-XXXXX-YY to which this
	// view (profile) belongs.
	WebPropertyId string `json:"webPropertyId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ProfileRef) MarshalJSON() ([]byte, error) {
	type noMethod ProfileRef
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ProfileSummary: JSON template for an Analytics ProfileSummary.
// ProfileSummary returns basic information (i.e., summary) for a
// profile.
type ProfileSummary struct {
	// Id: View (profile) ID.
	Id string `json:"id,omitempty"`

	// Kind: Resource type for Analytics ProfileSummary.
	Kind string `json:"kind,omitempty"`

	// Name: View (profile) name.
	Name string `json:"name,omitempty"`

	// Type: View (Profile) type. Supported types: WEB or APP.
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ProfileSummary) MarshalJSON() ([]byte, error) {
	type noMethod ProfileSummary
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Profiles: A view (profile) collection lists Analytics views
// (profiles) to which the user has access. Each resource in the
// collection corresponds to a single Analytics view (profile).
type Profiles struct {
	// Items: A list of views (profiles).
	Items []*Profile `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of resources the response can
	// contain, regardless of the actual number of resources returned. Its
	// value ranges from 1 to 1000 with a value of 1000 by default, or
	// otherwise specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this view (profile) collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this view (profile)
	// collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the resources, which is 1 by
	// default or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of results in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// Username: Email ID of the authenticated user
	Username string `json:"username,omitempty"`

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

func (s *Profiles) MarshalJSON() ([]byte, error) {
	type noMethod Profiles
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RealtimeData: Real time data for a given view (profile).
type RealtimeData struct {
	// ColumnHeaders: Column headers that list dimension names followed by
	// the metric names. The order of dimensions and metrics is same as
	// specified in the request.
	ColumnHeaders []*RealtimeDataColumnHeaders `json:"columnHeaders,omitempty"`

	// Id: Unique ID for this data response.
	Id string `json:"id,omitempty"`

	// Kind: Resource type.
	Kind string `json:"kind,omitempty"`

	// ProfileInfo: Information for the view (profile), for which the real
	// time data was requested.
	ProfileInfo *RealtimeDataProfileInfo `json:"profileInfo,omitempty"`

	// Query: Real time data request query parameters.
	Query *RealtimeDataQuery `json:"query,omitempty"`

	// Rows: Real time data rows, where each row contains a list of
	// dimension values followed by the metric values. The order of
	// dimensions and metrics is same as specified in the request.
	Rows [][]string `json:"rows,omitempty"`

	// SelfLink: Link to this page.
	SelfLink string `json:"selfLink,omitempty"`

	// TotalResults: The total number of rows for the query, regardless of
	// the number of rows in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// TotalsForAllResults: Total values for the requested metrics over all
	// the results, not just the results returned in this response. The
	// order of the metric totals is same as the metric order specified in
	// the request.
	TotalsForAllResults map[string]string `json:"totalsForAllResults,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ColumnHeaders") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RealtimeData) MarshalJSON() ([]byte, error) {
	type noMethod RealtimeData
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type RealtimeDataColumnHeaders struct {
	// ColumnType: Column Type. Either DIMENSION or METRIC.
	ColumnType string `json:"columnType,omitempty"`

	// DataType: Data type. Dimension column headers have only STRING as the
	// data type. Metric column headers have data types for metric values
	// such as INTEGER, DOUBLE, CURRENCY etc.
	DataType string `json:"dataType,omitempty"`

	// Name: Column name.
	Name string `json:"name,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ColumnType") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RealtimeDataColumnHeaders) MarshalJSON() ([]byte, error) {
	type noMethod RealtimeDataColumnHeaders
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RealtimeDataProfileInfo: Information for the view (profile), for
// which the real time data was requested.
type RealtimeDataProfileInfo struct {
	// AccountId: Account ID to which this view (profile) belongs.
	AccountId string `json:"accountId,omitempty"`

	// InternalWebPropertyId: Internal ID for the web property to which this
	// view (profile) belongs.
	InternalWebPropertyId string `json:"internalWebPropertyId,omitempty"`

	// ProfileId: View (Profile) ID.
	ProfileId string `json:"profileId,omitempty"`

	// ProfileName: View (Profile) name.
	ProfileName string `json:"profileName,omitempty"`

	// TableId: Table ID for view (profile).
	TableId string `json:"tableId,omitempty"`

	// WebPropertyId: Web Property ID to which this view (profile) belongs.
	WebPropertyId string `json:"webPropertyId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RealtimeDataProfileInfo) MarshalJSON() ([]byte, error) {
	type noMethod RealtimeDataProfileInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RealtimeDataQuery: Real time data request query parameters.
type RealtimeDataQuery struct {
	// Dimensions: List of real time dimensions.
	Dimensions string `json:"dimensions,omitempty"`

	// Filters: Comma-separated list of dimension or metric filters.
	Filters string `json:"filters,omitempty"`

	// Ids: Unique table ID.
	Ids string `json:"ids,omitempty"`

	// MaxResults: Maximum results per page.
	MaxResults int64 `json:"max-results,omitempty"`

	// Metrics: List of real time metrics.
	Metrics []string `json:"metrics,omitempty"`

	// Sort: List of dimensions or metrics based on which real time data is
	// sorted.
	Sort []string `json:"sort,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Dimensions") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RealtimeDataQuery) MarshalJSON() ([]byte, error) {
	type noMethod RealtimeDataQuery
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Segment: JSON template for an Analytics segment.
type Segment struct {
	// Created: Time the segment was created.
	Created string `json:"created,omitempty"`

	// Definition: Segment definition.
	Definition string `json:"definition,omitempty"`

	// Id: Segment ID.
	Id string `json:"id,omitempty"`

	// Kind: Resource type for Analytics segment.
	Kind string `json:"kind,omitempty"`

	// Name: Segment name.
	Name string `json:"name,omitempty"`

	// SegmentId: Segment ID. Can be used with the 'segment' parameter in
	// Core Reporting API.
	SegmentId string `json:"segmentId,omitempty"`

	// SelfLink: Link for this segment.
	SelfLink string `json:"selfLink,omitempty"`

	// Type: Type for a segment. Possible values are "BUILT_IN" or "CUSTOM".
	Type string `json:"type,omitempty"`

	// Updated: Time the segment was last modified.
	Updated string `json:"updated,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Created") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Segment) MarshalJSON() ([]byte, error) {
	type noMethod Segment
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Segments: An segment collection lists Analytics segments that the
// user has access to. Each resource in the collection corresponds to a
// single Analytics segment.
type Segments struct {
	// Items: A list of segments.
	Items []*Segment `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of resources the response can
	// contain, regardless of the actual number of resources returned. Its
	// value ranges from 1 to 1000 with a value of 1000 by default, or
	// otherwise specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type for segments.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this segment collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this segment collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the resources, which is 1 by
	// default or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of results in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// Username: Email ID of the authenticated user
	Username string `json:"username,omitempty"`

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

func (s *Segments) MarshalJSON() ([]byte, error) {
	type noMethod Segments
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// UnsampledReport: JSON template for Analytics unsampled report
// resource.
type UnsampledReport struct {
	// AccountId: Account ID to which this unsampled report belongs.
	AccountId string `json:"accountId,omitempty"`

	// CloudStorageDownloadDetails: Download details for a file stored in
	// Google Cloud Storage.
	CloudStorageDownloadDetails *UnsampledReportCloudStorageDownloadDetails `json:"cloudStorageDownloadDetails,omitempty"`

	// Created: Time this unsampled report was created.
	Created string `json:"created,omitempty"`

	// Dimensions: The dimensions for the unsampled report.
	Dimensions string `json:"dimensions,omitempty"`

	// DownloadType: The type of download you need to use for the report
	// data file.
	DownloadType string `json:"downloadType,omitempty"`

	// DriveDownloadDetails: Download details for a file stored in Google
	// Drive.
	DriveDownloadDetails *UnsampledReportDriveDownloadDetails `json:"driveDownloadDetails,omitempty"`

	// EndDate: The end date for the unsampled report.
	EndDate string `json:"end-date,omitempty"`

	// Filters: The filters for the unsampled report.
	Filters string `json:"filters,omitempty"`

	// Id: Unsampled report ID.
	Id string `json:"id,omitempty"`

	// Kind: Resource type for an Analytics unsampled report.
	Kind string `json:"kind,omitempty"`

	// Metrics: The metrics for the unsampled report.
	Metrics string `json:"metrics,omitempty"`

	// ProfileId: View (Profile) ID to which this unsampled report belongs.
	ProfileId string `json:"profileId,omitempty"`

	// Segment: The segment for the unsampled report.
	Segment string `json:"segment,omitempty"`

	// SelfLink: Link for this unsampled report.
	SelfLink string `json:"selfLink,omitempty"`

	// StartDate: The start date for the unsampled report.
	StartDate string `json:"start-date,omitempty"`

	// Status: Status of this unsampled report. Possible values are PENDING,
	// COMPLETED, or FAILED.
	Status string `json:"status,omitempty"`

	// Title: Title of the unsampled report.
	Title string `json:"title,omitempty"`

	// Updated: Time this unsampled report was last modified.
	Updated string `json:"updated,omitempty"`

	// WebPropertyId: Web property ID to which this unsampled report
	// belongs. The web property ID is of the form UA-XXXXX-YY.
	WebPropertyId string `json:"webPropertyId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *UnsampledReport) MarshalJSON() ([]byte, error) {
	type noMethod UnsampledReport
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// UnsampledReportCloudStorageDownloadDetails: Download details for a
// file stored in Google Cloud Storage.
type UnsampledReportCloudStorageDownloadDetails struct {
	// BucketId: Id of the bucket the file object is stored in.
	BucketId string `json:"bucketId,omitempty"`

	// ObjectId: Id of the file object containing the report data.
	ObjectId string `json:"objectId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "BucketId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *UnsampledReportCloudStorageDownloadDetails) MarshalJSON() ([]byte, error) {
	type noMethod UnsampledReportCloudStorageDownloadDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// UnsampledReportDriveDownloadDetails: Download details for a file
// stored in Google Drive.
type UnsampledReportDriveDownloadDetails struct {
	// DocumentId: Id of the document/file containing the report data.
	DocumentId string `json:"documentId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DocumentId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *UnsampledReportDriveDownloadDetails) MarshalJSON() ([]byte, error) {
	type noMethod UnsampledReportDriveDownloadDetails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// UnsampledReports: An unsampled report collection lists Analytics
// unsampled reports to which the user has access. Each view (profile)
// can have a set of unsampled reports. Each resource in the unsampled
// report collection corresponds to a single Analytics unsampled report.
type UnsampledReports struct {
	// Items: A list of unsampled reports.
	Items []*UnsampledReport `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of resources the response can
	// contain, regardless of the actual number of resources returned. Its
	// value ranges from 1 to 1000 with a value of 1000 by default, or
	// otherwise specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this unsampled report collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this unsampled report
	// collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the resources, which is 1 by
	// default or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of resources in the result.
	TotalResults int64 `json:"totalResults,omitempty"`

	// Username: Email ID of the authenticated user
	Username string `json:"username,omitempty"`

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

func (s *UnsampledReports) MarshalJSON() ([]byte, error) {
	type noMethod UnsampledReports
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Upload: Metadata returned for an upload operation.
type Upload struct {
	// AccountId: Account Id to which this upload belongs.
	AccountId int64 `json:"accountId,omitempty,string"`

	// CustomDataSourceId: Custom data source Id to which this data import
	// belongs.
	CustomDataSourceId string `json:"customDataSourceId,omitempty"`

	// Errors: Data import errors collection.
	Errors []string `json:"errors,omitempty"`

	// Id: A unique ID for this upload.
	Id string `json:"id,omitempty"`

	// Kind: Resource type for Analytics upload.
	Kind string `json:"kind,omitempty"`

	// Status: Upload status. Possible values: PENDING, COMPLETED, FAILED,
	// DELETING, DELETED.
	Status string `json:"status,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Upload) MarshalJSON() ([]byte, error) {
	type noMethod Upload
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Uploads: Upload collection lists Analytics uploads to which the user
// has access. Each custom data source can have a set of uploads. Each
// resource in the upload collection corresponds to a single Analytics
// data upload.
type Uploads struct {
	// Items: A list of uploads.
	Items []*Upload `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of resources the response can
	// contain, regardless of the actual number of resources returned. Its
	// value ranges from 1 to 1000 with a value of 1000 by default, or
	// otherwise specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this upload collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this upload collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the resources, which is 1 by
	// default or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of resources in the result.
	TotalResults int64 `json:"totalResults,omitempty"`

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

func (s *Uploads) MarshalJSON() ([]byte, error) {
	type noMethod Uploads
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// UserRef: JSON template for a user reference.
type UserRef struct {
	// Email: Email ID of this user.
	Email string `json:"email,omitempty"`

	// Id: User ID.
	Id string `json:"id,omitempty"`

	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Email") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *UserRef) MarshalJSON() ([]byte, error) {
	type noMethod UserRef
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// WebPropertyRef: JSON template for a web property reference.
type WebPropertyRef struct {
	// AccountId: Account ID to which this web property belongs.
	AccountId string `json:"accountId,omitempty"`

	// Href: Link for this web property.
	Href string `json:"href,omitempty"`

	// Id: Web property ID of the form UA-XXXXX-YY.
	Id string `json:"id,omitempty"`

	// InternalWebPropertyId: Internal ID for this web property.
	InternalWebPropertyId string `json:"internalWebPropertyId,omitempty"`

	// Kind: Analytics web property reference.
	Kind string `json:"kind,omitempty"`

	// Name: Name of this web property.
	Name string `json:"name,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *WebPropertyRef) MarshalJSON() ([]byte, error) {
	type noMethod WebPropertyRef
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// WebPropertySummary: JSON template for an Analytics
// WebPropertySummary. WebPropertySummary returns basic information
// (i.e., summary) for a web property.
type WebPropertySummary struct {
	// Id: Web property ID of the form UA-XXXXX-YY.
	Id string `json:"id,omitempty"`

	// InternalWebPropertyId: Internal ID for this web property.
	InternalWebPropertyId string `json:"internalWebPropertyId,omitempty"`

	// Kind: Resource type for Analytics WebPropertySummary.
	Kind string `json:"kind,omitempty"`

	// Level: Level for this web property. Possible values are STANDARD or
	// PREMIUM.
	Level string `json:"level,omitempty"`

	// Name: Web property name.
	Name string `json:"name,omitempty"`

	// Profiles: List of profiles under this web property.
	Profiles []*ProfileSummary `json:"profiles,omitempty"`

	// WebsiteUrl: Website url for this web property.
	WebsiteUrl string `json:"websiteUrl,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *WebPropertySummary) MarshalJSON() ([]byte, error) {
	type noMethod WebPropertySummary
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Webproperties: A web property collection lists Analytics web
// properties to which the user has access. Each resource in the
// collection corresponds to a single Analytics web property.
type Webproperties struct {
	// Items: A list of web properties.
	Items []*Webproperty `json:"items,omitempty"`

	// ItemsPerPage: The maximum number of resources the response can
	// contain, regardless of the actual number of resources returned. Its
	// value ranges from 1 to 1000 with a value of 1000 by default, or
	// otherwise specified by the max-results query parameter.
	ItemsPerPage int64 `json:"itemsPerPage,omitempty"`

	// Kind: Collection type.
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to next page for this web property collection.
	NextLink string `json:"nextLink,omitempty"`

	// PreviousLink: Link to previous page for this web property collection.
	PreviousLink string `json:"previousLink,omitempty"`

	// StartIndex: The starting index of the resources, which is 1 by
	// default or otherwise specified by the start-index query parameter.
	StartIndex int64 `json:"startIndex,omitempty"`

	// TotalResults: The total number of results for the query, regardless
	// of the number of results in the response.
	TotalResults int64 `json:"totalResults,omitempty"`

	// Username: Email ID of the authenticated user
	Username string `json:"username,omitempty"`

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

func (s *Webproperties) MarshalJSON() ([]byte, error) {
	type noMethod Webproperties
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Webproperty: JSON template for an Analytics web property.
type Webproperty struct {
	// AccountId: Account ID to which this web property belongs.
	AccountId string `json:"accountId,omitempty"`

	// ChildLink: Child link for this web property. Points to the list of
	// views (profiles) for this web property.
	ChildLink *WebpropertyChildLink `json:"childLink,omitempty"`

	// Created: Time this web property was created.
	Created string `json:"created,omitempty"`

	// DefaultProfileId: Default view (profile) ID.
	DefaultProfileId int64 `json:"defaultProfileId,omitempty,string"`

	// Id: Web property ID of the form UA-XXXXX-YY.
	Id string `json:"id,omitempty"`

	// IndustryVertical: The industry vertical/category selected for this
	// web property.
	IndustryVertical string `json:"industryVertical,omitempty"`

	// InternalWebPropertyId: Internal ID for this web property.
	InternalWebPropertyId string `json:"internalWebPropertyId,omitempty"`

	// Kind: Resource type for Analytics WebProperty.
	Kind string `json:"kind,omitempty"`

	// Level: Level for this web property. Possible values are STANDARD or
	// PREMIUM.
	Level string `json:"level,omitempty"`

	// Name: Name of this web property.
	Name string `json:"name,omitempty"`

	// ParentLink: Parent link for this web property. Points to the account
	// to which this web property belongs.
	ParentLink *WebpropertyParentLink `json:"parentLink,omitempty"`

	// Permissions: Permissions the user has for this web property.
	Permissions *WebpropertyPermissions `json:"permissions,omitempty"`

	// ProfileCount: View (Profile) count for this web property.
	ProfileCount int64 `json:"profileCount,omitempty"`

	// SelfLink: Link for this web property.
	SelfLink string `json:"selfLink,omitempty"`

	// Updated: Time this web property was last modified.
	Updated string `json:"updated,omitempty"`

	// WebsiteUrl: Website url for this web property.
	WebsiteUrl string `json:"websiteUrl,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AccountId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Webproperty) MarshalJSON() ([]byte, error) {
	type noMethod Webproperty
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// WebpropertyChildLink: Child link for this web property. Points to the
// list of views (profiles) for this web property.
type WebpropertyChildLink struct {
	// Href: Link to the list of views (profiles) for this web property.
	Href string `json:"href,omitempty"`

	// Type: Type of the parent link. Its value is "analytics#profiles".
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Href") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *WebpropertyChildLink) MarshalJSON() ([]byte, error) {
	type noMethod WebpropertyChildLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// WebpropertyParentLink: Parent link for this web property. Points to
// the account to which this web property belongs.
type WebpropertyParentLink struct {
	// Href: Link to the account for this web property.
	Href string `json:"href,omitempty"`

	// Type: Type of the parent link. Its value is "analytics#account".
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Href") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *WebpropertyParentLink) MarshalJSON() ([]byte, error) {
	type noMethod WebpropertyParentLink
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// WebpropertyPermissions: Permissions the user has for this web
// property.
type WebpropertyPermissions struct {
	// Effective: All the permissions that the user has for this web
	// property. These include any implied permissions (e.g., EDIT implies
	// VIEW) or inherited permissions from the parent account.
	Effective []string `json:"effective,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Effective") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *WebpropertyPermissions) MarshalJSON() ([]byte, error) {
	type noMethod WebpropertyPermissions
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "analytics.data.ga.get":

type DataGaGetCall struct {
	s         *Service
	ids       string
	startDate string
	endDate   string
	metrics   string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Returns Analytics data for a view (profile).
func (r *DataGaService) Get(ids string, startDate string, endDate string, metrics string) *DataGaGetCall {
	c := &DataGaGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.ids = ids
	c.startDate = startDate
	c.endDate = endDate
	c.metrics = metrics
	return c
}

// Dimensions sets the optional parameter "dimensions": A
// comma-separated list of Analytics dimensions. E.g.,
// 'ga:browser,ga:city'.
func (c *DataGaGetCall) Dimensions(dimensions string) *DataGaGetCall {
	c.opt_["dimensions"] = dimensions
	return c
}

// Filters sets the optional parameter "filters": A comma-separated list
// of dimension or metric filters to be applied to Analytics data.
func (c *DataGaGetCall) Filters(filters string) *DataGaGetCall {
	c.opt_["filters"] = filters
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of entries to include in this feed.
func (c *DataGaGetCall) MaxResults(maxResults int64) *DataGaGetCall {
	c.opt_["max-results"] = maxResults
	return c
}

// Output sets the optional parameter "output": The selected format for
// the response. Default format is JSON.
//
// Possible values:
//   "dataTable" - Returns the response in Google Charts Data Table
// format. This is useful in creating visualization using Google Charts.
//   "json" - Returns the response in standard JSON format.
func (c *DataGaGetCall) Output(output string) *DataGaGetCall {
	c.opt_["output"] = output
	return c
}

// SamplingLevel sets the optional parameter "samplingLevel": The
// desired sampling level.
//
// Possible values:
//   "DEFAULT" - Returns response with a sample size that balances speed
// and accuracy.
//   "FASTER" - Returns a fast response with a smaller sample size.
//   "HIGHER_PRECISION" - Returns a more accurate response using a large
// sample size, but this may result in the response being slower.
func (c *DataGaGetCall) SamplingLevel(samplingLevel string) *DataGaGetCall {
	c.opt_["samplingLevel"] = samplingLevel
	return c
}

// Segment sets the optional parameter "segment": An Analytics segment
// to be applied to data.
func (c *DataGaGetCall) Segment(segment string) *DataGaGetCall {
	c.opt_["segment"] = segment
	return c
}

// Sort sets the optional parameter "sort": A comma-separated list of
// dimensions or metrics that determine the sort order for Analytics
// data.
func (c *DataGaGetCall) Sort(sort string) *DataGaGetCall {
	c.opt_["sort"] = sort
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first entity to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
func (c *DataGaGetCall) StartIndex(startIndex int64) *DataGaGetCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *DataGaGetCall) Fields(s ...googleapi.Field) *DataGaGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *DataGaGetCall) IfNoneMatch(entityTag string) *DataGaGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *DataGaGetCall) Context(ctx context.Context) *DataGaGetCall {
	c.ctx_ = ctx
	return c
}

func (c *DataGaGetCall) doRequest(alt string) (*http.Response, error) {
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
	if v, ok := c.opt_["output"]; ok {
		params.Set("output", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["samplingLevel"]; ok {
		params.Set("samplingLevel", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "data/ga")
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

// Do executes the "analytics.data.ga.get" call.
// Exactly one of *GaData or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *GaData.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *DataGaGetCall) Do() (*GaData, error) {
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
	ret := &GaData{
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
	//   "description": "Returns Analytics data for a view (profile).",
	//   "httpMethod": "GET",
	//   "id": "analytics.data.ga.get",
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
	//       "description": "End date for fetching Analytics data. Request can should specify an end date formatted as YYYY-MM-DD, or as a relative date (e.g., today, yesterday, or 7daysAgo). The default value is yesterday.",
	//       "location": "query",
	//       "pattern": "[0-9]{4}-[0-9]{2}-[0-9]{2}|today|yesterday|[0-9]+(daysAgo)",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "filters": {
	//       "description": "A comma-separated list of dimension or metric filters to be applied to Analytics data.",
	//       "location": "query",
	//       "pattern": "ga:.+",
	//       "type": "string"
	//     },
	//     "ids": {
	//       "description": "Unique table ID for retrieving Analytics data. Table ID is of the form ga:XXXX, where XXXX is the Analytics view (profile) ID.",
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
	//       "description": "A comma-separated list of Analytics metrics. E.g., 'ga:sessions,ga:pageviews'. At least one metric must be specified.",
	//       "location": "query",
	//       "pattern": "ga:.+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "output": {
	//       "description": "The selected format for the response. Default format is JSON.",
	//       "enum": [
	//         "dataTable",
	//         "json"
	//       ],
	//       "enumDescriptions": [
	//         "Returns the response in Google Charts Data Table format. This is useful in creating visualization using Google Charts.",
	//         "Returns the response in standard JSON format."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "samplingLevel": {
	//       "description": "The desired sampling level.",
	//       "enum": [
	//         "DEFAULT",
	//         "FASTER",
	//         "HIGHER_PRECISION"
	//       ],
	//       "enumDescriptions": [
	//         "Returns response with a sample size that balances speed and accuracy.",
	//         "Returns a fast response with a smaller sample size.",
	//         "Returns a more accurate response using a large sample size, but this may result in the response being slower."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "segment": {
	//       "description": "An Analytics segment to be applied to data.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "sort": {
	//       "description": "A comma-separated list of dimensions or metrics that determine the sort order for Analytics data.",
	//       "location": "query",
	//       "pattern": "(-)?ga:.+",
	//       "type": "string"
	//     },
	//     "start-date": {
	//       "description": "Start date for fetching Analytics data. Requests can specify a start date formatted as YYYY-MM-DD, or as a relative date (e.g., today, yesterday, or 7daysAgo). The default value is 7daysAgo.",
	//       "location": "query",
	//       "pattern": "[0-9]{4}-[0-9]{2}-[0-9]{2}|today|yesterday|[0-9]+(daysAgo)",
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
	//   "path": "data/ga",
	//   "response": {
	//     "$ref": "GaData"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.data.mcf.get":

type DataMcfGetCall struct {
	s         *Service
	ids       string
	startDate string
	endDate   string
	metrics   string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Returns Analytics Multi-Channel Funnels data for a view
// (profile).
func (r *DataMcfService) Get(ids string, startDate string, endDate string, metrics string) *DataMcfGetCall {
	c := &DataMcfGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.ids = ids
	c.startDate = startDate
	c.endDate = endDate
	c.metrics = metrics
	return c
}

// Dimensions sets the optional parameter "dimensions": A
// comma-separated list of Multi-Channel Funnels dimensions. E.g.,
// 'mcf:source,mcf:medium'.
func (c *DataMcfGetCall) Dimensions(dimensions string) *DataMcfGetCall {
	c.opt_["dimensions"] = dimensions
	return c
}

// Filters sets the optional parameter "filters": A comma-separated list
// of dimension or metric filters to be applied to the Analytics data.
func (c *DataMcfGetCall) Filters(filters string) *DataMcfGetCall {
	c.opt_["filters"] = filters
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of entries to include in this feed.
func (c *DataMcfGetCall) MaxResults(maxResults int64) *DataMcfGetCall {
	c.opt_["max-results"] = maxResults
	return c
}

// SamplingLevel sets the optional parameter "samplingLevel": The
// desired sampling level.
//
// Possible values:
//   "DEFAULT" - Returns response with a sample size that balances speed
// and accuracy.
//   "FASTER" - Returns a fast response with a smaller sample size.
//   "HIGHER_PRECISION" - Returns a more accurate response using a large
// sample size, but this may result in the response being slower.
func (c *DataMcfGetCall) SamplingLevel(samplingLevel string) *DataMcfGetCall {
	c.opt_["samplingLevel"] = samplingLevel
	return c
}

// Sort sets the optional parameter "sort": A comma-separated list of
// dimensions or metrics that determine the sort order for the Analytics
// data.
func (c *DataMcfGetCall) Sort(sort string) *DataMcfGetCall {
	c.opt_["sort"] = sort
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first entity to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
func (c *DataMcfGetCall) StartIndex(startIndex int64) *DataMcfGetCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *DataMcfGetCall) Fields(s ...googleapi.Field) *DataMcfGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *DataMcfGetCall) IfNoneMatch(entityTag string) *DataMcfGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *DataMcfGetCall) Context(ctx context.Context) *DataMcfGetCall {
	c.ctx_ = ctx
	return c
}

func (c *DataMcfGetCall) doRequest(alt string) (*http.Response, error) {
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
	if v, ok := c.opt_["samplingLevel"]; ok {
		params.Set("samplingLevel", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "data/mcf")
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

// Do executes the "analytics.data.mcf.get" call.
// Exactly one of *McfData or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *McfData.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *DataMcfGetCall) Do() (*McfData, error) {
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
	ret := &McfData{
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
	//   "description": "Returns Analytics Multi-Channel Funnels data for a view (profile).",
	//   "httpMethod": "GET",
	//   "id": "analytics.data.mcf.get",
	//   "parameterOrder": [
	//     "ids",
	//     "start-date",
	//     "end-date",
	//     "metrics"
	//   ],
	//   "parameters": {
	//     "dimensions": {
	//       "description": "A comma-separated list of Multi-Channel Funnels dimensions. E.g., 'mcf:source,mcf:medium'.",
	//       "location": "query",
	//       "pattern": "(mcf:.+)?",
	//       "type": "string"
	//     },
	//     "end-date": {
	//       "description": "End date for fetching Analytics data. Requests can specify a start date formatted as YYYY-MM-DD, or as a relative date (e.g., today, yesterday, or 7daysAgo). The default value is 7daysAgo.",
	//       "location": "query",
	//       "pattern": "[0-9]{4}-[0-9]{2}-[0-9]{2}|today|yesterday|[0-9]+(daysAgo)",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "filters": {
	//       "description": "A comma-separated list of dimension or metric filters to be applied to the Analytics data.",
	//       "location": "query",
	//       "pattern": "mcf:.+",
	//       "type": "string"
	//     },
	//     "ids": {
	//       "description": "Unique table ID for retrieving Analytics data. Table ID is of the form ga:XXXX, where XXXX is the Analytics view (profile) ID.",
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
	//       "description": "A comma-separated list of Multi-Channel Funnels metrics. E.g., 'mcf:totalConversions,mcf:totalConversionValue'. At least one metric must be specified.",
	//       "location": "query",
	//       "pattern": "mcf:.+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "samplingLevel": {
	//       "description": "The desired sampling level.",
	//       "enum": [
	//         "DEFAULT",
	//         "FASTER",
	//         "HIGHER_PRECISION"
	//       ],
	//       "enumDescriptions": [
	//         "Returns response with a sample size that balances speed and accuracy.",
	//         "Returns a fast response with a smaller sample size.",
	//         "Returns a more accurate response using a large sample size, but this may result in the response being slower."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "sort": {
	//       "description": "A comma-separated list of dimensions or metrics that determine the sort order for the Analytics data.",
	//       "location": "query",
	//       "pattern": "(-)?mcf:.+",
	//       "type": "string"
	//     },
	//     "start-date": {
	//       "description": "Start date for fetching Analytics data. Requests can specify a start date formatted as YYYY-MM-DD, or as a relative date (e.g., today, yesterday, or 7daysAgo). The default value is 7daysAgo.",
	//       "location": "query",
	//       "pattern": "[0-9]{4}-[0-9]{2}-[0-9]{2}|today|yesterday|[0-9]+(daysAgo)",
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
	//   "path": "data/mcf",
	//   "response": {
	//     "$ref": "McfData"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.data.realtime.get":

type DataRealtimeGetCall struct {
	s       *Service
	ids     string
	metrics string
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Get: Returns real time data for a view (profile).
func (r *DataRealtimeService) Get(ids string, metrics string) *DataRealtimeGetCall {
	c := &DataRealtimeGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.ids = ids
	c.metrics = metrics
	return c
}

// Dimensions sets the optional parameter "dimensions": A
// comma-separated list of real time dimensions. E.g.,
// 'rt:medium,rt:city'.
func (c *DataRealtimeGetCall) Dimensions(dimensions string) *DataRealtimeGetCall {
	c.opt_["dimensions"] = dimensions
	return c
}

// Filters sets the optional parameter "filters": A comma-separated list
// of dimension or metric filters to be applied to real time data.
func (c *DataRealtimeGetCall) Filters(filters string) *DataRealtimeGetCall {
	c.opt_["filters"] = filters
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of entries to include in this feed.
func (c *DataRealtimeGetCall) MaxResults(maxResults int64) *DataRealtimeGetCall {
	c.opt_["max-results"] = maxResults
	return c
}

// Sort sets the optional parameter "sort": A comma-separated list of
// dimensions or metrics that determine the sort order for real time
// data.
func (c *DataRealtimeGetCall) Sort(sort string) *DataRealtimeGetCall {
	c.opt_["sort"] = sort
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *DataRealtimeGetCall) Fields(s ...googleapi.Field) *DataRealtimeGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *DataRealtimeGetCall) IfNoneMatch(entityTag string) *DataRealtimeGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *DataRealtimeGetCall) Context(ctx context.Context) *DataRealtimeGetCall {
	c.ctx_ = ctx
	return c
}

func (c *DataRealtimeGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	params.Set("ids", fmt.Sprintf("%v", c.ids))
	params.Set("metrics", fmt.Sprintf("%v", c.metrics))
	if v, ok := c.opt_["dimensions"]; ok {
		params.Set("dimensions", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["filters"]; ok {
		params.Set("filters", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["max-results"]; ok {
		params.Set("max-results", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["sort"]; ok {
		params.Set("sort", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "data/realtime")
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

// Do executes the "analytics.data.realtime.get" call.
// Exactly one of *RealtimeData or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *RealtimeData.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *DataRealtimeGetCall) Do() (*RealtimeData, error) {
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
	ret := &RealtimeData{
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
	//   "description": "Returns real time data for a view (profile).",
	//   "httpMethod": "GET",
	//   "id": "analytics.data.realtime.get",
	//   "parameterOrder": [
	//     "ids",
	//     "metrics"
	//   ],
	//   "parameters": {
	//     "dimensions": {
	//       "description": "A comma-separated list of real time dimensions. E.g., 'rt:medium,rt:city'.",
	//       "location": "query",
	//       "pattern": "(ga:.+)|(rt:.+)",
	//       "type": "string"
	//     },
	//     "filters": {
	//       "description": "A comma-separated list of dimension or metric filters to be applied to real time data.",
	//       "location": "query",
	//       "pattern": "(ga:.+)|(rt:.+)",
	//       "type": "string"
	//     },
	//     "ids": {
	//       "description": "Unique table ID for retrieving real time data. Table ID is of the form ga:XXXX, where XXXX is the Analytics view (profile) ID.",
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
	//       "description": "A comma-separated list of real time metrics. E.g., 'rt:activeUsers'. At least one metric must be specified.",
	//       "location": "query",
	//       "pattern": "(ga:.+)|(rt:.+)",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "sort": {
	//       "description": "A comma-separated list of dimensions or metrics that determine the sort order for real time data.",
	//       "location": "query",
	//       "pattern": "(-)?((ga:.+)|(rt:.+))",
	//       "type": "string"
	//     }
	//   },
	//   "path": "data/realtime",
	//   "response": {
	//     "$ref": "RealtimeData"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.accountSummaries.list":

type ManagementAccountSummariesListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Lists account summaries (lightweight tree comprised of
// accounts/properties/profiles) to which the user has access.
func (r *ManagementAccountSummariesService) List() *ManagementAccountSummariesListCall {
	c := &ManagementAccountSummariesListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of account summaries to include in this response, where the
// largest acceptable value is 1000.
func (c *ManagementAccountSummariesListCall) MaxResults(maxResults int64) *ManagementAccountSummariesListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first entity to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
func (c *ManagementAccountSummariesListCall) StartIndex(startIndex int64) *ManagementAccountSummariesListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementAccountSummariesListCall) Fields(s ...googleapi.Field) *ManagementAccountSummariesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementAccountSummariesListCall) IfNoneMatch(entityTag string) *ManagementAccountSummariesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementAccountSummariesListCall) Context(ctx context.Context) *ManagementAccountSummariesListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementAccountSummariesListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accountSummaries")
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

// Do executes the "analytics.management.accountSummaries.list" call.
// Exactly one of *AccountSummaries or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *AccountSummaries.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementAccountSummariesListCall) Do() (*AccountSummaries, error) {
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
	ret := &AccountSummaries{
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
	//   "description": "Lists account summaries (lightweight tree comprised of accounts/properties/profiles) to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.accountSummaries.list",
	//   "parameters": {
	//     "max-results": {
	//       "description": "The maximum number of account summaries to include in this response, where the largest acceptable value is 1000.",
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
	//   "path": "management/accountSummaries",
	//   "response": {
	//     "$ref": "AccountSummaries"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.accountUserLinks.delete":

type ManagementAccountUserLinksDeleteCall struct {
	s         *Service
	accountId string
	linkId    string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Delete: Removes a user from the given account.
func (r *ManagementAccountUserLinksService) Delete(accountId string, linkId string) *ManagementAccountUserLinksDeleteCall {
	c := &ManagementAccountUserLinksDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.linkId = linkId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementAccountUserLinksDeleteCall) Fields(s ...googleapi.Field) *ManagementAccountUserLinksDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementAccountUserLinksDeleteCall) Context(ctx context.Context) *ManagementAccountUserLinksDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementAccountUserLinksDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/entityUserLinks/{linkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId": c.accountId,
		"linkId":    c.linkId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.accountUserLinks.delete" call.
func (c *ManagementAccountUserLinksDeleteCall) Do() error {
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
	//   "description": "Removes a user from the given account.",
	//   "httpMethod": "DELETE",
	//   "id": "analytics.management.accountUserLinks.delete",
	//   "parameterOrder": [
	//     "accountId",
	//     "linkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to delete the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "linkId": {
	//       "description": "Link ID to delete the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/entityUserLinks/{linkId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.manage.users"
	//   ]
	// }

}

// method id "analytics.management.accountUserLinks.insert":

type ManagementAccountUserLinksInsertCall struct {
	s              *Service
	accountId      string
	entityuserlink *EntityUserLink
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Insert: Adds a new user to the given account.
func (r *ManagementAccountUserLinksService) Insert(accountId string, entityuserlink *EntityUserLink) *ManagementAccountUserLinksInsertCall {
	c := &ManagementAccountUserLinksInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.entityuserlink = entityuserlink
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementAccountUserLinksInsertCall) Fields(s ...googleapi.Field) *ManagementAccountUserLinksInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementAccountUserLinksInsertCall) Context(ctx context.Context) *ManagementAccountUserLinksInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementAccountUserLinksInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.entityuserlink)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/entityUserLinks")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId": c.accountId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.accountUserLinks.insert" call.
// Exactly one of *EntityUserLink or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *EntityUserLink.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementAccountUserLinksInsertCall) Do() (*EntityUserLink, error) {
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
	ret := &EntityUserLink{
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
	//   "description": "Adds a new user to the given account.",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.accountUserLinks.insert",
	//   "parameterOrder": [
	//     "accountId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to create the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/entityUserLinks",
	//   "request": {
	//     "$ref": "EntityUserLink"
	//   },
	//   "response": {
	//     "$ref": "EntityUserLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.manage.users"
	//   ]
	// }

}

// method id "analytics.management.accountUserLinks.list":

type ManagementAccountUserLinksListCall struct {
	s         *Service
	accountId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// List: Lists account-user links for a given account.
func (r *ManagementAccountUserLinksService) List(accountId string) *ManagementAccountUserLinksListCall {
	c := &ManagementAccountUserLinksListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of account-user links to include in this response.
func (c *ManagementAccountUserLinksListCall) MaxResults(maxResults int64) *ManagementAccountUserLinksListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first account-user link to retrieve. Use this parameter as a
// pagination mechanism along with the max-results parameter.
func (c *ManagementAccountUserLinksListCall) StartIndex(startIndex int64) *ManagementAccountUserLinksListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementAccountUserLinksListCall) Fields(s ...googleapi.Field) *ManagementAccountUserLinksListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementAccountUserLinksListCall) IfNoneMatch(entityTag string) *ManagementAccountUserLinksListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementAccountUserLinksListCall) Context(ctx context.Context) *ManagementAccountUserLinksListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementAccountUserLinksListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/entityUserLinks")
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

// Do executes the "analytics.management.accountUserLinks.list" call.
// Exactly one of *EntityUserLinks or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *EntityUserLinks.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementAccountUserLinksListCall) Do() (*EntityUserLinks, error) {
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
	ret := &EntityUserLinks{
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
	//   "description": "Lists account-user links for a given account.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.accountUserLinks.list",
	//   "parameterOrder": [
	//     "accountId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve the user links for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of account-user links to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "start-index": {
	//       "description": "An index of the first account-user link to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/entityUserLinks",
	//   "response": {
	//     "$ref": "EntityUserLinks"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.manage.users",
	//     "https://www.googleapis.com/auth/analytics.manage.users.readonly"
	//   ]
	// }

}

// method id "analytics.management.accountUserLinks.update":

type ManagementAccountUserLinksUpdateCall struct {
	s              *Service
	accountId      string
	linkId         string
	entityuserlink *EntityUserLink
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Update: Updates permissions for an existing user on the given
// account.
func (r *ManagementAccountUserLinksService) Update(accountId string, linkId string, entityuserlink *EntityUserLink) *ManagementAccountUserLinksUpdateCall {
	c := &ManagementAccountUserLinksUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.linkId = linkId
	c.entityuserlink = entityuserlink
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementAccountUserLinksUpdateCall) Fields(s ...googleapi.Field) *ManagementAccountUserLinksUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementAccountUserLinksUpdateCall) Context(ctx context.Context) *ManagementAccountUserLinksUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementAccountUserLinksUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.entityuserlink)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/entityUserLinks/{linkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId": c.accountId,
		"linkId":    c.linkId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.accountUserLinks.update" call.
// Exactly one of *EntityUserLink or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *EntityUserLink.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementAccountUserLinksUpdateCall) Do() (*EntityUserLink, error) {
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
	ret := &EntityUserLink{
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
	//   "description": "Updates permissions for an existing user on the given account.",
	//   "httpMethod": "PUT",
	//   "id": "analytics.management.accountUserLinks.update",
	//   "parameterOrder": [
	//     "accountId",
	//     "linkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to update the account-user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "linkId": {
	//       "description": "Link ID to update the account-user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/entityUserLinks/{linkId}",
	//   "request": {
	//     "$ref": "EntityUserLink"
	//   },
	//   "response": {
	//     "$ref": "EntityUserLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.manage.users"
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
// Exactly one of *Accounts or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Accounts.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementAccountsListCall) Do() (*Accounts, error) {
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
	ret := &Accounts{
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
	//   "response": {
	//     "$ref": "Accounts"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.customDataSources.list":

type ManagementCustomDataSourcesListCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: List custom data sources to which the user has access.
func (r *ManagementCustomDataSourcesService) List(accountId string, webPropertyId string) *ManagementCustomDataSourcesListCall {
	c := &ManagementCustomDataSourcesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of custom data sources to include in this response.
func (c *ManagementCustomDataSourcesListCall) MaxResults(maxResults int64) *ManagementCustomDataSourcesListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": A 1-based index
// of the first custom data source to retrieve. Use this parameter as a
// pagination mechanism along with the max-results parameter.
func (c *ManagementCustomDataSourcesListCall) StartIndex(startIndex int64) *ManagementCustomDataSourcesListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementCustomDataSourcesListCall) Fields(s ...googleapi.Field) *ManagementCustomDataSourcesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementCustomDataSourcesListCall) IfNoneMatch(entityTag string) *ManagementCustomDataSourcesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementCustomDataSourcesListCall) Context(ctx context.Context) *ManagementCustomDataSourcesListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementCustomDataSourcesListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources")
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

// Do executes the "analytics.management.customDataSources.list" call.
// Exactly one of *CustomDataSources or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *CustomDataSources.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementCustomDataSourcesListCall) Do() (*CustomDataSources, error) {
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
	ret := &CustomDataSources{
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
	//   "description": "List custom data sources to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.customDataSources.list",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account Id for the custom data sources to retrieve.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of custom data sources to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "start-index": {
	//       "description": "A 1-based index of the first custom data source to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property Id for the custom data sources to retrieve.",
	//       "location": "path",
	//       "pattern": "UA-(\\d+)-(\\d+)",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources",
	//   "response": {
	//     "$ref": "CustomDataSources"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.customDimensions.get":

type ManagementCustomDimensionsGetCall struct {
	s                 *Service
	accountId         string
	webPropertyId     string
	customDimensionId string
	opt_              map[string]interface{}
	ctx_              context.Context
}

// Get: Get a custom dimension to which the user has access.
func (r *ManagementCustomDimensionsService) Get(accountId string, webPropertyId string, customDimensionId string) *ManagementCustomDimensionsGetCall {
	c := &ManagementCustomDimensionsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.customDimensionId = customDimensionId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementCustomDimensionsGetCall) Fields(s ...googleapi.Field) *ManagementCustomDimensionsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementCustomDimensionsGetCall) IfNoneMatch(entityTag string) *ManagementCustomDimensionsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementCustomDimensionsGetCall) Context(ctx context.Context) *ManagementCustomDimensionsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementCustomDimensionsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions/{customDimensionId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":         c.accountId,
		"webPropertyId":     c.webPropertyId,
		"customDimensionId": c.customDimensionId,
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

// Do executes the "analytics.management.customDimensions.get" call.
// Exactly one of *CustomDimension or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CustomDimension.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementCustomDimensionsGetCall) Do() (*CustomDimension, error) {
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
	ret := &CustomDimension{
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
	//   "description": "Get a custom dimension to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.customDimensions.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "customDimensionId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID for the custom dimension to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "customDimensionId": {
	//       "description": "The ID of the custom dimension to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID for the custom dimension to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions/{customDimensionId}",
	//   "response": {
	//     "$ref": "CustomDimension"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.customDimensions.insert":

type ManagementCustomDimensionsInsertCall struct {
	s               *Service
	accountId       string
	webPropertyId   string
	customdimension *CustomDimension
	opt_            map[string]interface{}
	ctx_            context.Context
}

// Insert: Create a new custom dimension.
func (r *ManagementCustomDimensionsService) Insert(accountId string, webPropertyId string, customdimension *CustomDimension) *ManagementCustomDimensionsInsertCall {
	c := &ManagementCustomDimensionsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.customdimension = customdimension
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementCustomDimensionsInsertCall) Fields(s ...googleapi.Field) *ManagementCustomDimensionsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementCustomDimensionsInsertCall) Context(ctx context.Context) *ManagementCustomDimensionsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementCustomDimensionsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.customdimension)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.customDimensions.insert" call.
// Exactly one of *CustomDimension or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CustomDimension.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementCustomDimensionsInsertCall) Do() (*CustomDimension, error) {
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
	ret := &CustomDimension{
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
	//   "description": "Create a new custom dimension.",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.customDimensions.insert",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID for the custom dimension to create.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID for the custom dimension to create.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions",
	//   "request": {
	//     "$ref": "CustomDimension"
	//   },
	//   "response": {
	//     "$ref": "CustomDimension"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.customDimensions.list":

type ManagementCustomDimensionsListCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: Lists custom dimensions to which the user has access.
func (r *ManagementCustomDimensionsService) List(accountId string, webPropertyId string) *ManagementCustomDimensionsListCall {
	c := &ManagementCustomDimensionsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of custom dimensions to include in this response.
func (c *ManagementCustomDimensionsListCall) MaxResults(maxResults int64) *ManagementCustomDimensionsListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first entity to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
func (c *ManagementCustomDimensionsListCall) StartIndex(startIndex int64) *ManagementCustomDimensionsListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementCustomDimensionsListCall) Fields(s ...googleapi.Field) *ManagementCustomDimensionsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementCustomDimensionsListCall) IfNoneMatch(entityTag string) *ManagementCustomDimensionsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementCustomDimensionsListCall) Context(ctx context.Context) *ManagementCustomDimensionsListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementCustomDimensionsListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions")
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

// Do executes the "analytics.management.customDimensions.list" call.
// Exactly one of *CustomDimensions or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *CustomDimensions.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementCustomDimensionsListCall) Do() (*CustomDimensions, error) {
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
	ret := &CustomDimensions{
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
	//   "description": "Lists custom dimensions to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.customDimensions.list",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID for the custom dimensions to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of custom dimensions to include in this response.",
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
	//       "description": "Web property ID for the custom dimensions to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions",
	//   "response": {
	//     "$ref": "CustomDimensions"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.customDimensions.patch":

type ManagementCustomDimensionsPatchCall struct {
	s                 *Service
	accountId         string
	webPropertyId     string
	customDimensionId string
	customdimension   *CustomDimension
	opt_              map[string]interface{}
	ctx_              context.Context
}

// Patch: Updates an existing custom dimension. This method supports
// patch semantics.
func (r *ManagementCustomDimensionsService) Patch(accountId string, webPropertyId string, customDimensionId string, customdimension *CustomDimension) *ManagementCustomDimensionsPatchCall {
	c := &ManagementCustomDimensionsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.customDimensionId = customDimensionId
	c.customdimension = customdimension
	return c
}

// IgnoreCustomDataSourceLinks sets the optional parameter
// "ignoreCustomDataSourceLinks": Force the update and ignore any
// warnings related to the custom dimension being linked to a custom
// data source / data set.
func (c *ManagementCustomDimensionsPatchCall) IgnoreCustomDataSourceLinks(ignoreCustomDataSourceLinks bool) *ManagementCustomDimensionsPatchCall {
	c.opt_["ignoreCustomDataSourceLinks"] = ignoreCustomDataSourceLinks
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementCustomDimensionsPatchCall) Fields(s ...googleapi.Field) *ManagementCustomDimensionsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementCustomDimensionsPatchCall) Context(ctx context.Context) *ManagementCustomDimensionsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementCustomDimensionsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.customdimension)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["ignoreCustomDataSourceLinks"]; ok {
		params.Set("ignoreCustomDataSourceLinks", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions/{customDimensionId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":         c.accountId,
		"webPropertyId":     c.webPropertyId,
		"customDimensionId": c.customDimensionId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.customDimensions.patch" call.
// Exactly one of *CustomDimension or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CustomDimension.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementCustomDimensionsPatchCall) Do() (*CustomDimension, error) {
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
	ret := &CustomDimension{
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
	//   "description": "Updates an existing custom dimension. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "analytics.management.customDimensions.patch",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "customDimensionId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID for the custom dimension to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "customDimensionId": {
	//       "description": "Custom dimension ID for the custom dimension to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "ignoreCustomDataSourceLinks": {
	//       "default": "false",
	//       "description": "Force the update and ignore any warnings related to the custom dimension being linked to a custom data source / data set.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID for the custom dimension to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions/{customDimensionId}",
	//   "request": {
	//     "$ref": "CustomDimension"
	//   },
	//   "response": {
	//     "$ref": "CustomDimension"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.customDimensions.update":

type ManagementCustomDimensionsUpdateCall struct {
	s                 *Service
	accountId         string
	webPropertyId     string
	customDimensionId string
	customdimension   *CustomDimension
	opt_              map[string]interface{}
	ctx_              context.Context
}

// Update: Updates an existing custom dimension.
func (r *ManagementCustomDimensionsService) Update(accountId string, webPropertyId string, customDimensionId string, customdimension *CustomDimension) *ManagementCustomDimensionsUpdateCall {
	c := &ManagementCustomDimensionsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.customDimensionId = customDimensionId
	c.customdimension = customdimension
	return c
}

// IgnoreCustomDataSourceLinks sets the optional parameter
// "ignoreCustomDataSourceLinks": Force the update and ignore any
// warnings related to the custom dimension being linked to a custom
// data source / data set.
func (c *ManagementCustomDimensionsUpdateCall) IgnoreCustomDataSourceLinks(ignoreCustomDataSourceLinks bool) *ManagementCustomDimensionsUpdateCall {
	c.opt_["ignoreCustomDataSourceLinks"] = ignoreCustomDataSourceLinks
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementCustomDimensionsUpdateCall) Fields(s ...googleapi.Field) *ManagementCustomDimensionsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementCustomDimensionsUpdateCall) Context(ctx context.Context) *ManagementCustomDimensionsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementCustomDimensionsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.customdimension)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["ignoreCustomDataSourceLinks"]; ok {
		params.Set("ignoreCustomDataSourceLinks", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions/{customDimensionId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":         c.accountId,
		"webPropertyId":     c.webPropertyId,
		"customDimensionId": c.customDimensionId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.customDimensions.update" call.
// Exactly one of *CustomDimension or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CustomDimension.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementCustomDimensionsUpdateCall) Do() (*CustomDimension, error) {
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
	ret := &CustomDimension{
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
	//   "description": "Updates an existing custom dimension.",
	//   "httpMethod": "PUT",
	//   "id": "analytics.management.customDimensions.update",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "customDimensionId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID for the custom dimension to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "customDimensionId": {
	//       "description": "Custom dimension ID for the custom dimension to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "ignoreCustomDataSourceLinks": {
	//       "default": "false",
	//       "description": "Force the update and ignore any warnings related to the custom dimension being linked to a custom data source / data set.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID for the custom dimension to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions/{customDimensionId}",
	//   "request": {
	//     "$ref": "CustomDimension"
	//   },
	//   "response": {
	//     "$ref": "CustomDimension"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.customMetrics.get":

type ManagementCustomMetricsGetCall struct {
	s              *Service
	accountId      string
	webPropertyId  string
	customMetricId string
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Get: Get a custom metric to which the user has access.
func (r *ManagementCustomMetricsService) Get(accountId string, webPropertyId string, customMetricId string) *ManagementCustomMetricsGetCall {
	c := &ManagementCustomMetricsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.customMetricId = customMetricId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementCustomMetricsGetCall) Fields(s ...googleapi.Field) *ManagementCustomMetricsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementCustomMetricsGetCall) IfNoneMatch(entityTag string) *ManagementCustomMetricsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementCustomMetricsGetCall) Context(ctx context.Context) *ManagementCustomMetricsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementCustomMetricsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics/{customMetricId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":      c.accountId,
		"webPropertyId":  c.webPropertyId,
		"customMetricId": c.customMetricId,
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

// Do executes the "analytics.management.customMetrics.get" call.
// Exactly one of *CustomMetric or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CustomMetric.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementCustomMetricsGetCall) Do() (*CustomMetric, error) {
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
	ret := &CustomMetric{
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
	//   "description": "Get a custom metric to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.customMetrics.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "customMetricId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID for the custom metric to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "customMetricId": {
	//       "description": "The ID of the custom metric to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID for the custom metric to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics/{customMetricId}",
	//   "response": {
	//     "$ref": "CustomMetric"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.customMetrics.insert":

type ManagementCustomMetricsInsertCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	custommetric  *CustomMetric
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Insert: Create a new custom metric.
func (r *ManagementCustomMetricsService) Insert(accountId string, webPropertyId string, custommetric *CustomMetric) *ManagementCustomMetricsInsertCall {
	c := &ManagementCustomMetricsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.custommetric = custommetric
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementCustomMetricsInsertCall) Fields(s ...googleapi.Field) *ManagementCustomMetricsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementCustomMetricsInsertCall) Context(ctx context.Context) *ManagementCustomMetricsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementCustomMetricsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.custommetric)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.customMetrics.insert" call.
// Exactly one of *CustomMetric or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CustomMetric.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementCustomMetricsInsertCall) Do() (*CustomMetric, error) {
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
	ret := &CustomMetric{
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
	//   "description": "Create a new custom metric.",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.customMetrics.insert",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID for the custom metric to create.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID for the custom dimension to create.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics",
	//   "request": {
	//     "$ref": "CustomMetric"
	//   },
	//   "response": {
	//     "$ref": "CustomMetric"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.customMetrics.list":

type ManagementCustomMetricsListCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: Lists custom metrics to which the user has access.
func (r *ManagementCustomMetricsService) List(accountId string, webPropertyId string) *ManagementCustomMetricsListCall {
	c := &ManagementCustomMetricsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of custom metrics to include in this response.
func (c *ManagementCustomMetricsListCall) MaxResults(maxResults int64) *ManagementCustomMetricsListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first entity to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
func (c *ManagementCustomMetricsListCall) StartIndex(startIndex int64) *ManagementCustomMetricsListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementCustomMetricsListCall) Fields(s ...googleapi.Field) *ManagementCustomMetricsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementCustomMetricsListCall) IfNoneMatch(entityTag string) *ManagementCustomMetricsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementCustomMetricsListCall) Context(ctx context.Context) *ManagementCustomMetricsListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementCustomMetricsListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics")
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

// Do executes the "analytics.management.customMetrics.list" call.
// Exactly one of *CustomMetrics or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CustomMetrics.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementCustomMetricsListCall) Do() (*CustomMetrics, error) {
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
	ret := &CustomMetrics{
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
	//   "description": "Lists custom metrics to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.customMetrics.list",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID for the custom metrics to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of custom metrics to include in this response.",
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
	//       "description": "Web property ID for the custom metrics to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics",
	//   "response": {
	//     "$ref": "CustomMetrics"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.customMetrics.patch":

type ManagementCustomMetricsPatchCall struct {
	s              *Service
	accountId      string
	webPropertyId  string
	customMetricId string
	custommetric   *CustomMetric
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Patch: Updates an existing custom metric. This method supports patch
// semantics.
func (r *ManagementCustomMetricsService) Patch(accountId string, webPropertyId string, customMetricId string, custommetric *CustomMetric) *ManagementCustomMetricsPatchCall {
	c := &ManagementCustomMetricsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.customMetricId = customMetricId
	c.custommetric = custommetric
	return c
}

// IgnoreCustomDataSourceLinks sets the optional parameter
// "ignoreCustomDataSourceLinks": Force the update and ignore any
// warnings related to the custom metric being linked to a custom data
// source / data set.
func (c *ManagementCustomMetricsPatchCall) IgnoreCustomDataSourceLinks(ignoreCustomDataSourceLinks bool) *ManagementCustomMetricsPatchCall {
	c.opt_["ignoreCustomDataSourceLinks"] = ignoreCustomDataSourceLinks
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementCustomMetricsPatchCall) Fields(s ...googleapi.Field) *ManagementCustomMetricsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementCustomMetricsPatchCall) Context(ctx context.Context) *ManagementCustomMetricsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementCustomMetricsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.custommetric)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["ignoreCustomDataSourceLinks"]; ok {
		params.Set("ignoreCustomDataSourceLinks", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics/{customMetricId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":      c.accountId,
		"webPropertyId":  c.webPropertyId,
		"customMetricId": c.customMetricId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.customMetrics.patch" call.
// Exactly one of *CustomMetric or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CustomMetric.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementCustomMetricsPatchCall) Do() (*CustomMetric, error) {
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
	ret := &CustomMetric{
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
	//   "description": "Updates an existing custom metric. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "analytics.management.customMetrics.patch",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "customMetricId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID for the custom metric to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "customMetricId": {
	//       "description": "Custom metric ID for the custom metric to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "ignoreCustomDataSourceLinks": {
	//       "default": "false",
	//       "description": "Force the update and ignore any warnings related to the custom metric being linked to a custom data source / data set.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID for the custom metric to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics/{customMetricId}",
	//   "request": {
	//     "$ref": "CustomMetric"
	//   },
	//   "response": {
	//     "$ref": "CustomMetric"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.customMetrics.update":

type ManagementCustomMetricsUpdateCall struct {
	s              *Service
	accountId      string
	webPropertyId  string
	customMetricId string
	custommetric   *CustomMetric
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Update: Updates an existing custom metric.
func (r *ManagementCustomMetricsService) Update(accountId string, webPropertyId string, customMetricId string, custommetric *CustomMetric) *ManagementCustomMetricsUpdateCall {
	c := &ManagementCustomMetricsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.customMetricId = customMetricId
	c.custommetric = custommetric
	return c
}

// IgnoreCustomDataSourceLinks sets the optional parameter
// "ignoreCustomDataSourceLinks": Force the update and ignore any
// warnings related to the custom metric being linked to a custom data
// source / data set.
func (c *ManagementCustomMetricsUpdateCall) IgnoreCustomDataSourceLinks(ignoreCustomDataSourceLinks bool) *ManagementCustomMetricsUpdateCall {
	c.opt_["ignoreCustomDataSourceLinks"] = ignoreCustomDataSourceLinks
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementCustomMetricsUpdateCall) Fields(s ...googleapi.Field) *ManagementCustomMetricsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementCustomMetricsUpdateCall) Context(ctx context.Context) *ManagementCustomMetricsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementCustomMetricsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.custommetric)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["ignoreCustomDataSourceLinks"]; ok {
		params.Set("ignoreCustomDataSourceLinks", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics/{customMetricId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":      c.accountId,
		"webPropertyId":  c.webPropertyId,
		"customMetricId": c.customMetricId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.customMetrics.update" call.
// Exactly one of *CustomMetric or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CustomMetric.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementCustomMetricsUpdateCall) Do() (*CustomMetric, error) {
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
	ret := &CustomMetric{
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
	//   "description": "Updates an existing custom metric.",
	//   "httpMethod": "PUT",
	//   "id": "analytics.management.customMetrics.update",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "customMetricId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID for the custom metric to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "customMetricId": {
	//       "description": "Custom metric ID for the custom metric to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "ignoreCustomDataSourceLinks": {
	//       "default": "false",
	//       "description": "Force the update and ignore any warnings related to the custom metric being linked to a custom data source / data set.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID for the custom metric to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics/{customMetricId}",
	//   "request": {
	//     "$ref": "CustomMetric"
	//   },
	//   "response": {
	//     "$ref": "CustomMetric"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.experiments.delete":

type ManagementExperimentsDeleteCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	experimentId  string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Delete: Delete an experiment.
func (r *ManagementExperimentsService) Delete(accountId string, webPropertyId string, profileId string, experimentId string) *ManagementExperimentsDeleteCall {
	c := &ManagementExperimentsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.experimentId = experimentId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementExperimentsDeleteCall) Fields(s ...googleapi.Field) *ManagementExperimentsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementExperimentsDeleteCall) Context(ctx context.Context) *ManagementExperimentsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementExperimentsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments/{experimentId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
		"experimentId":  c.experimentId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.experiments.delete" call.
func (c *ManagementExperimentsDeleteCall) Do() error {
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
	//   "description": "Delete an experiment.",
	//   "httpMethod": "DELETE",
	//   "id": "analytics.management.experiments.delete",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "experimentId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to which the experiment belongs",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "experimentId": {
	//       "description": "ID of the experiment to delete",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to which the experiment belongs",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to which the experiment belongs",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments/{experimentId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.experiments.get":

type ManagementExperimentsGetCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	experimentId  string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Get: Returns an experiment to which the user has access.
func (r *ManagementExperimentsService) Get(accountId string, webPropertyId string, profileId string, experimentId string) *ManagementExperimentsGetCall {
	c := &ManagementExperimentsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.experimentId = experimentId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementExperimentsGetCall) Fields(s ...googleapi.Field) *ManagementExperimentsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementExperimentsGetCall) IfNoneMatch(entityTag string) *ManagementExperimentsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementExperimentsGetCall) Context(ctx context.Context) *ManagementExperimentsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementExperimentsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments/{experimentId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
		"experimentId":  c.experimentId,
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

// Do executes the "analytics.management.experiments.get" call.
// Exactly one of *Experiment or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Experiment.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementExperimentsGetCall) Do() (*Experiment, error) {
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
	ret := &Experiment{
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
	//   "description": "Returns an experiment to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.experiments.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "experimentId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve the experiment for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "experimentId": {
	//       "description": "Experiment ID to retrieve the experiment for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to retrieve the experiment for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to retrieve the experiment for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments/{experimentId}",
	//   "response": {
	//     "$ref": "Experiment"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.experiments.insert":

type ManagementExperimentsInsertCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	experiment    *Experiment
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Insert: Create a new experiment.
func (r *ManagementExperimentsService) Insert(accountId string, webPropertyId string, profileId string, experiment *Experiment) *ManagementExperimentsInsertCall {
	c := &ManagementExperimentsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.experiment = experiment
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementExperimentsInsertCall) Fields(s ...googleapi.Field) *ManagementExperimentsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementExperimentsInsertCall) Context(ctx context.Context) *ManagementExperimentsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementExperimentsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.experiment)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.experiments.insert" call.
// Exactly one of *Experiment or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Experiment.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementExperimentsInsertCall) Do() (*Experiment, error) {
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
	ret := &Experiment{
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
	//   "description": "Create a new experiment.",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.experiments.insert",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to create the experiment for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to create the experiment for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to create the experiment for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments",
	//   "request": {
	//     "$ref": "Experiment"
	//   },
	//   "response": {
	//     "$ref": "Experiment"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.experiments.list":

type ManagementExperimentsListCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: Lists experiments to which the user has access.
func (r *ManagementExperimentsService) List(accountId string, webPropertyId string, profileId string) *ManagementExperimentsListCall {
	c := &ManagementExperimentsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of experiments to include in this response.
func (c *ManagementExperimentsListCall) MaxResults(maxResults int64) *ManagementExperimentsListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first experiment to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
func (c *ManagementExperimentsListCall) StartIndex(startIndex int64) *ManagementExperimentsListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementExperimentsListCall) Fields(s ...googleapi.Field) *ManagementExperimentsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementExperimentsListCall) IfNoneMatch(entityTag string) *ManagementExperimentsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementExperimentsListCall) Context(ctx context.Context) *ManagementExperimentsListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementExperimentsListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments")
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

// Do executes the "analytics.management.experiments.list" call.
// Exactly one of *Experiments or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Experiments.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementExperimentsListCall) Do() (*Experiments, error) {
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
	ret := &Experiments{
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
	//   "description": "Lists experiments to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.experiments.list",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve experiments for.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of experiments to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to retrieve experiments for.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "start-index": {
	//       "description": "An index of the first experiment to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to retrieve experiments for.",
	//       "location": "path",
	//       "pattern": "UA-(\\d+)-(\\d+)",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments",
	//   "response": {
	//     "$ref": "Experiments"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.experiments.patch":

type ManagementExperimentsPatchCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	experimentId  string
	experiment    *Experiment
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Patch: Update an existing experiment. This method supports patch
// semantics.
func (r *ManagementExperimentsService) Patch(accountId string, webPropertyId string, profileId string, experimentId string, experiment *Experiment) *ManagementExperimentsPatchCall {
	c := &ManagementExperimentsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.experimentId = experimentId
	c.experiment = experiment
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementExperimentsPatchCall) Fields(s ...googleapi.Field) *ManagementExperimentsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementExperimentsPatchCall) Context(ctx context.Context) *ManagementExperimentsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementExperimentsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.experiment)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments/{experimentId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
		"experimentId":  c.experimentId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.experiments.patch" call.
// Exactly one of *Experiment or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Experiment.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementExperimentsPatchCall) Do() (*Experiment, error) {
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
	ret := &Experiment{
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
	//   "description": "Update an existing experiment. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "analytics.management.experiments.patch",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "experimentId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID of the experiment to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "experimentId": {
	//       "description": "Experiment ID of the experiment to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID of the experiment to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID of the experiment to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments/{experimentId}",
	//   "request": {
	//     "$ref": "Experiment"
	//   },
	//   "response": {
	//     "$ref": "Experiment"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.experiments.update":

type ManagementExperimentsUpdateCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	experimentId  string
	experiment    *Experiment
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Update: Update an existing experiment.
func (r *ManagementExperimentsService) Update(accountId string, webPropertyId string, profileId string, experimentId string, experiment *Experiment) *ManagementExperimentsUpdateCall {
	c := &ManagementExperimentsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.experimentId = experimentId
	c.experiment = experiment
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementExperimentsUpdateCall) Fields(s ...googleapi.Field) *ManagementExperimentsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementExperimentsUpdateCall) Context(ctx context.Context) *ManagementExperimentsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementExperimentsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.experiment)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments/{experimentId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
		"experimentId":  c.experimentId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.experiments.update" call.
// Exactly one of *Experiment or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Experiment.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementExperimentsUpdateCall) Do() (*Experiment, error) {
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
	ret := &Experiment{
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
	//   "description": "Update an existing experiment.",
	//   "httpMethod": "PUT",
	//   "id": "analytics.management.experiments.update",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "experimentId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID of the experiment to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "experimentId": {
	//       "description": "Experiment ID of the experiment to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID of the experiment to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID of the experiment to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments/{experimentId}",
	//   "request": {
	//     "$ref": "Experiment"
	//   },
	//   "response": {
	//     "$ref": "Experiment"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.filters.delete":

type ManagementFiltersDeleteCall struct {
	s         *Service
	accountId string
	filterId  string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Delete: Delete a filter.
func (r *ManagementFiltersService) Delete(accountId string, filterId string) *ManagementFiltersDeleteCall {
	c := &ManagementFiltersDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.filterId = filterId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementFiltersDeleteCall) Fields(s ...googleapi.Field) *ManagementFiltersDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementFiltersDeleteCall) Context(ctx context.Context) *ManagementFiltersDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementFiltersDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/filters/{filterId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId": c.accountId,
		"filterId":  c.filterId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.filters.delete" call.
// Exactly one of *Filter or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Filter.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementFiltersDeleteCall) Do() (*Filter, error) {
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
	ret := &Filter{
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
	//   "description": "Delete a filter.",
	//   "httpMethod": "DELETE",
	//   "id": "analytics.management.filters.delete",
	//   "parameterOrder": [
	//     "accountId",
	//     "filterId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to delete the filter for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "filterId": {
	//       "description": "ID of the filter to be deleted.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/filters/{filterId}",
	//   "response": {
	//     "$ref": "Filter"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.filters.get":

type ManagementFiltersGetCall struct {
	s         *Service
	accountId string
	filterId  string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Returns a filters to which the user has access.
func (r *ManagementFiltersService) Get(accountId string, filterId string) *ManagementFiltersGetCall {
	c := &ManagementFiltersGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.filterId = filterId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementFiltersGetCall) Fields(s ...googleapi.Field) *ManagementFiltersGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementFiltersGetCall) IfNoneMatch(entityTag string) *ManagementFiltersGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementFiltersGetCall) Context(ctx context.Context) *ManagementFiltersGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementFiltersGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/filters/{filterId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId": c.accountId,
		"filterId":  c.filterId,
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

// Do executes the "analytics.management.filters.get" call.
// Exactly one of *Filter or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Filter.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementFiltersGetCall) Do() (*Filter, error) {
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
	ret := &Filter{
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
	//   "description": "Returns a filters to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.filters.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "filterId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve filters for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "filterId": {
	//       "description": "Filter ID to retrieve filters for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/filters/{filterId}",
	//   "response": {
	//     "$ref": "Filter"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.filters.insert":

type ManagementFiltersInsertCall struct {
	s         *Service
	accountId string
	filter    *Filter
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Insert: Create a new filter.
func (r *ManagementFiltersService) Insert(accountId string, filter *Filter) *ManagementFiltersInsertCall {
	c := &ManagementFiltersInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.filter = filter
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementFiltersInsertCall) Fields(s ...googleapi.Field) *ManagementFiltersInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementFiltersInsertCall) Context(ctx context.Context) *ManagementFiltersInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementFiltersInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.filter)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/filters")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId": c.accountId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.filters.insert" call.
// Exactly one of *Filter or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Filter.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementFiltersInsertCall) Do() (*Filter, error) {
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
	ret := &Filter{
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
	//   "description": "Create a new filter.",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.filters.insert",
	//   "parameterOrder": [
	//     "accountId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to create filter for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/filters",
	//   "request": {
	//     "$ref": "Filter"
	//   },
	//   "response": {
	//     "$ref": "Filter"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.filters.list":

type ManagementFiltersListCall struct {
	s         *Service
	accountId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// List: Lists all filters for an account
func (r *ManagementFiltersService) List(accountId string) *ManagementFiltersListCall {
	c := &ManagementFiltersListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of filters to include in this response.
func (c *ManagementFiltersListCall) MaxResults(maxResults int64) *ManagementFiltersListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first entity to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
func (c *ManagementFiltersListCall) StartIndex(startIndex int64) *ManagementFiltersListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementFiltersListCall) Fields(s ...googleapi.Field) *ManagementFiltersListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementFiltersListCall) IfNoneMatch(entityTag string) *ManagementFiltersListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementFiltersListCall) Context(ctx context.Context) *ManagementFiltersListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementFiltersListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/filters")
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

// Do executes the "analytics.management.filters.list" call.
// Exactly one of *Filters or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Filters.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementFiltersListCall) Do() (*Filters, error) {
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
	ret := &Filters{
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
	//   "description": "Lists all filters for an account",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.filters.list",
	//   "parameterOrder": [
	//     "accountId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve filters for.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of filters to include in this response.",
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
	//   "path": "management/accounts/{accountId}/filters",
	//   "response": {
	//     "$ref": "Filters"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.filters.patch":

type ManagementFiltersPatchCall struct {
	s         *Service
	accountId string
	filterId  string
	filter    *Filter
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Patch: Updates an existing filter. This method supports patch
// semantics.
func (r *ManagementFiltersService) Patch(accountId string, filterId string, filter *Filter) *ManagementFiltersPatchCall {
	c := &ManagementFiltersPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.filterId = filterId
	c.filter = filter
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementFiltersPatchCall) Fields(s ...googleapi.Field) *ManagementFiltersPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementFiltersPatchCall) Context(ctx context.Context) *ManagementFiltersPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementFiltersPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.filter)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/filters/{filterId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId": c.accountId,
		"filterId":  c.filterId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.filters.patch" call.
// Exactly one of *Filter or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Filter.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementFiltersPatchCall) Do() (*Filter, error) {
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
	ret := &Filter{
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
	//   "description": "Updates an existing filter. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "analytics.management.filters.patch",
	//   "parameterOrder": [
	//     "accountId",
	//     "filterId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to which the filter belongs.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "filterId": {
	//       "description": "ID of the filter to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/filters/{filterId}",
	//   "request": {
	//     "$ref": "Filter"
	//   },
	//   "response": {
	//     "$ref": "Filter"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.filters.update":

type ManagementFiltersUpdateCall struct {
	s         *Service
	accountId string
	filterId  string
	filter    *Filter
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Update: Updates an existing filter.
func (r *ManagementFiltersService) Update(accountId string, filterId string, filter *Filter) *ManagementFiltersUpdateCall {
	c := &ManagementFiltersUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.filterId = filterId
	c.filter = filter
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementFiltersUpdateCall) Fields(s ...googleapi.Field) *ManagementFiltersUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementFiltersUpdateCall) Context(ctx context.Context) *ManagementFiltersUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementFiltersUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.filter)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/filters/{filterId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId": c.accountId,
		"filterId":  c.filterId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.filters.update" call.
// Exactly one of *Filter or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Filter.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementFiltersUpdateCall) Do() (*Filter, error) {
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
	ret := &Filter{
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
	//   "description": "Updates an existing filter.",
	//   "httpMethod": "PUT",
	//   "id": "analytics.management.filters.update",
	//   "parameterOrder": [
	//     "accountId",
	//     "filterId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to which the filter belongs.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "filterId": {
	//       "description": "ID of the filter to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/filters/{filterId}",
	//   "request": {
	//     "$ref": "Filter"
	//   },
	//   "response": {
	//     "$ref": "Filter"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.goals.get":

type ManagementGoalsGetCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	goalId        string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Get: Gets a goal to which the user has access.
func (r *ManagementGoalsService) Get(accountId string, webPropertyId string, profileId string, goalId string) *ManagementGoalsGetCall {
	c := &ManagementGoalsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.goalId = goalId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementGoalsGetCall) Fields(s ...googleapi.Field) *ManagementGoalsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementGoalsGetCall) IfNoneMatch(entityTag string) *ManagementGoalsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementGoalsGetCall) Context(ctx context.Context) *ManagementGoalsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementGoalsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals/{goalId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
		"goalId":        c.goalId,
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

// Do executes the "analytics.management.goals.get" call.
// Exactly one of *Goal or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Goal.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *ManagementGoalsGetCall) Do() (*Goal, error) {
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
	ret := &Goal{
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
	//   "description": "Gets a goal to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.goals.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "goalId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve the goal for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "goalId": {
	//       "description": "Goal ID to retrieve the goal for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to retrieve the goal for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to retrieve the goal for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals/{goalId}",
	//   "response": {
	//     "$ref": "Goal"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.goals.insert":

type ManagementGoalsInsertCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	goal          *Goal
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Insert: Create a new goal.
func (r *ManagementGoalsService) Insert(accountId string, webPropertyId string, profileId string, goal *Goal) *ManagementGoalsInsertCall {
	c := &ManagementGoalsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.goal = goal
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementGoalsInsertCall) Fields(s ...googleapi.Field) *ManagementGoalsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementGoalsInsertCall) Context(ctx context.Context) *ManagementGoalsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementGoalsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.goal)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.goals.insert" call.
// Exactly one of *Goal or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Goal.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *ManagementGoalsInsertCall) Do() (*Goal, error) {
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
	ret := &Goal{
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
	//   "description": "Create a new goal.",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.goals.insert",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to create the goal for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to create the goal for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to create the goal for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals",
	//   "request": {
	//     "$ref": "Goal"
	//   },
	//   "response": {
	//     "$ref": "Goal"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
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
// Exactly one of *Goals or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Goals.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementGoalsListCall) Do() (*Goals, error) {
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
	ret := &Goals{
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
	//   "response": {
	//     "$ref": "Goals"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.goals.patch":

type ManagementGoalsPatchCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	goalId        string
	goal          *Goal
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Patch: Updates an existing view (profile). This method supports patch
// semantics.
func (r *ManagementGoalsService) Patch(accountId string, webPropertyId string, profileId string, goalId string, goal *Goal) *ManagementGoalsPatchCall {
	c := &ManagementGoalsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.goalId = goalId
	c.goal = goal
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementGoalsPatchCall) Fields(s ...googleapi.Field) *ManagementGoalsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementGoalsPatchCall) Context(ctx context.Context) *ManagementGoalsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementGoalsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.goal)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals/{goalId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
		"goalId":        c.goalId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.goals.patch" call.
// Exactly one of *Goal or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Goal.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *ManagementGoalsPatchCall) Do() (*Goal, error) {
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
	ret := &Goal{
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
	//   "description": "Updates an existing view (profile). This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "analytics.management.goals.patch",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "goalId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to update the goal.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "goalId": {
	//       "description": "Index of the goal to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to update the goal.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to update the goal.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals/{goalId}",
	//   "request": {
	//     "$ref": "Goal"
	//   },
	//   "response": {
	//     "$ref": "Goal"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.goals.update":

type ManagementGoalsUpdateCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	goalId        string
	goal          *Goal
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Update: Updates an existing view (profile).
func (r *ManagementGoalsService) Update(accountId string, webPropertyId string, profileId string, goalId string, goal *Goal) *ManagementGoalsUpdateCall {
	c := &ManagementGoalsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.goalId = goalId
	c.goal = goal
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementGoalsUpdateCall) Fields(s ...googleapi.Field) *ManagementGoalsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementGoalsUpdateCall) Context(ctx context.Context) *ManagementGoalsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementGoalsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.goal)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals/{goalId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
		"goalId":        c.goalId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.goals.update" call.
// Exactly one of *Goal or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Goal.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *ManagementGoalsUpdateCall) Do() (*Goal, error) {
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
	ret := &Goal{
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
	//   "description": "Updates an existing view (profile).",
	//   "httpMethod": "PUT",
	//   "id": "analytics.management.goals.update",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "goalId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to update the goal.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "goalId": {
	//       "description": "Index of the goal to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to update the goal.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to update the goal.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals/{goalId}",
	//   "request": {
	//     "$ref": "Goal"
	//   },
	//   "response": {
	//     "$ref": "Goal"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.profileFilterLinks.delete":

type ManagementProfileFilterLinksDeleteCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	linkId        string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Delete: Delete a profile filter link.
func (r *ManagementProfileFilterLinksService) Delete(accountId string, webPropertyId string, profileId string, linkId string) *ManagementProfileFilterLinksDeleteCall {
	c := &ManagementProfileFilterLinksDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.linkId = linkId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfileFilterLinksDeleteCall) Fields(s ...googleapi.Field) *ManagementProfileFilterLinksDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfileFilterLinksDeleteCall) Context(ctx context.Context) *ManagementProfileFilterLinksDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfileFilterLinksDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks/{linkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
		"linkId":        c.linkId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.profileFilterLinks.delete" call.
func (c *ManagementProfileFilterLinksDeleteCall) Do() error {
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
	//   "description": "Delete a profile filter link.",
	//   "httpMethod": "DELETE",
	//   "id": "analytics.management.profileFilterLinks.delete",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "linkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to which the profile filter link belongs.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "linkId": {
	//       "description": "ID of the profile filter link to delete.",
	//       "location": "path",
	//       "pattern": "\\d+:\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "Profile ID to which the filter link belongs.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property Id to which the profile filter link belongs.",
	//       "location": "path",
	//       "pattern": "UA-(\\d+)-(\\d+)",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks/{linkId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.profileFilterLinks.get":

type ManagementProfileFilterLinksGetCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	linkId        string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Get: Returns a single profile filter link.
func (r *ManagementProfileFilterLinksService) Get(accountId string, webPropertyId string, profileId string, linkId string) *ManagementProfileFilterLinksGetCall {
	c := &ManagementProfileFilterLinksGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.linkId = linkId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfileFilterLinksGetCall) Fields(s ...googleapi.Field) *ManagementProfileFilterLinksGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementProfileFilterLinksGetCall) IfNoneMatch(entityTag string) *ManagementProfileFilterLinksGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfileFilterLinksGetCall) Context(ctx context.Context) *ManagementProfileFilterLinksGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfileFilterLinksGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks/{linkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
		"linkId":        c.linkId,
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

// Do executes the "analytics.management.profileFilterLinks.get" call.
// Exactly one of *ProfileFilterLink or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ProfileFilterLink.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementProfileFilterLinksGetCall) Do() (*ProfileFilterLink, error) {
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
	ret := &ProfileFilterLink{
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
	//   "description": "Returns a single profile filter link.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.profileFilterLinks.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "linkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve profile filter link for.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "linkId": {
	//       "description": "ID of the profile filter link.",
	//       "location": "path",
	//       "pattern": "\\d+:\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "Profile ID to retrieve filter link for.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property Id to retrieve profile filter link for.",
	//       "location": "path",
	//       "pattern": "UA-(\\d+)-(\\d+)",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks/{linkId}",
	//   "response": {
	//     "$ref": "ProfileFilterLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.profileFilterLinks.insert":

type ManagementProfileFilterLinksInsertCall struct {
	s                 *Service
	accountId         string
	webPropertyId     string
	profileId         string
	profilefilterlink *ProfileFilterLink
	opt_              map[string]interface{}
	ctx_              context.Context
}

// Insert: Create a new profile filter link.
func (r *ManagementProfileFilterLinksService) Insert(accountId string, webPropertyId string, profileId string, profilefilterlink *ProfileFilterLink) *ManagementProfileFilterLinksInsertCall {
	c := &ManagementProfileFilterLinksInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.profilefilterlink = profilefilterlink
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfileFilterLinksInsertCall) Fields(s ...googleapi.Field) *ManagementProfileFilterLinksInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfileFilterLinksInsertCall) Context(ctx context.Context) *ManagementProfileFilterLinksInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfileFilterLinksInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.profilefilterlink)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.profileFilterLinks.insert" call.
// Exactly one of *ProfileFilterLink or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ProfileFilterLink.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementProfileFilterLinksInsertCall) Do() (*ProfileFilterLink, error) {
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
	ret := &ProfileFilterLink{
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
	//   "description": "Create a new profile filter link.",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.profileFilterLinks.insert",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to create profile filter link for.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "Profile ID to create filter link for.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property Id to create profile filter link for.",
	//       "location": "path",
	//       "pattern": "UA-(\\d+)-(\\d+)",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks",
	//   "request": {
	//     "$ref": "ProfileFilterLink"
	//   },
	//   "response": {
	//     "$ref": "ProfileFilterLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.profileFilterLinks.list":

type ManagementProfileFilterLinksListCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: Lists all profile filter links for a profile.
func (r *ManagementProfileFilterLinksService) List(accountId string, webPropertyId string, profileId string) *ManagementProfileFilterLinksListCall {
	c := &ManagementProfileFilterLinksListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of profile filter links to include in this response.
func (c *ManagementProfileFilterLinksListCall) MaxResults(maxResults int64) *ManagementProfileFilterLinksListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first entity to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
func (c *ManagementProfileFilterLinksListCall) StartIndex(startIndex int64) *ManagementProfileFilterLinksListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfileFilterLinksListCall) Fields(s ...googleapi.Field) *ManagementProfileFilterLinksListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementProfileFilterLinksListCall) IfNoneMatch(entityTag string) *ManagementProfileFilterLinksListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfileFilterLinksListCall) Context(ctx context.Context) *ManagementProfileFilterLinksListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfileFilterLinksListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks")
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

// Do executes the "analytics.management.profileFilterLinks.list" call.
// Exactly one of *ProfileFilterLinks or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ProfileFilterLinks.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementProfileFilterLinksListCall) Do() (*ProfileFilterLinks, error) {
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
	ret := &ProfileFilterLinks{
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
	//   "description": "Lists all profile filter links for a profile.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.profileFilterLinks.list",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve profile filter links for.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of profile filter links to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "profileId": {
	//       "description": "Profile ID to retrieve filter links for. Can either be a specific profile ID or '~all', which refers to all the profiles that user has access to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "start-index": {
	//       "description": "An index of the first entity to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property Id for profile filter links for. Can either be a specific web property ID or '~all', which refers to all the web properties that user has access to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks",
	//   "response": {
	//     "$ref": "ProfileFilterLinks"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.profileFilterLinks.patch":

type ManagementProfileFilterLinksPatchCall struct {
	s                 *Service
	accountId         string
	webPropertyId     string
	profileId         string
	linkId            string
	profilefilterlink *ProfileFilterLink
	opt_              map[string]interface{}
	ctx_              context.Context
}

// Patch: Update an existing profile filter link. This method supports
// patch semantics.
func (r *ManagementProfileFilterLinksService) Patch(accountId string, webPropertyId string, profileId string, linkId string, profilefilterlink *ProfileFilterLink) *ManagementProfileFilterLinksPatchCall {
	c := &ManagementProfileFilterLinksPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.linkId = linkId
	c.profilefilterlink = profilefilterlink
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfileFilterLinksPatchCall) Fields(s ...googleapi.Field) *ManagementProfileFilterLinksPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfileFilterLinksPatchCall) Context(ctx context.Context) *ManagementProfileFilterLinksPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfileFilterLinksPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.profilefilterlink)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks/{linkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
		"linkId":        c.linkId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.profileFilterLinks.patch" call.
// Exactly one of *ProfileFilterLink or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ProfileFilterLink.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementProfileFilterLinksPatchCall) Do() (*ProfileFilterLink, error) {
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
	ret := &ProfileFilterLink{
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
	//   "description": "Update an existing profile filter link. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "analytics.management.profileFilterLinks.patch",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "linkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to which profile filter link belongs.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "linkId": {
	//       "description": "ID of the profile filter link to be updated.",
	//       "location": "path",
	//       "pattern": "\\d+:\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "Profile ID to which filter link belongs",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property Id to which profile filter link belongs",
	//       "location": "path",
	//       "pattern": "UA-(\\d+)-(\\d+)",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks/{linkId}",
	//   "request": {
	//     "$ref": "ProfileFilterLink"
	//   },
	//   "response": {
	//     "$ref": "ProfileFilterLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.profileFilterLinks.update":

type ManagementProfileFilterLinksUpdateCall struct {
	s                 *Service
	accountId         string
	webPropertyId     string
	profileId         string
	linkId            string
	profilefilterlink *ProfileFilterLink
	opt_              map[string]interface{}
	ctx_              context.Context
}

// Update: Update an existing profile filter link.
func (r *ManagementProfileFilterLinksService) Update(accountId string, webPropertyId string, profileId string, linkId string, profilefilterlink *ProfileFilterLink) *ManagementProfileFilterLinksUpdateCall {
	c := &ManagementProfileFilterLinksUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.linkId = linkId
	c.profilefilterlink = profilefilterlink
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfileFilterLinksUpdateCall) Fields(s ...googleapi.Field) *ManagementProfileFilterLinksUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfileFilterLinksUpdateCall) Context(ctx context.Context) *ManagementProfileFilterLinksUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfileFilterLinksUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.profilefilterlink)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks/{linkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
		"linkId":        c.linkId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.profileFilterLinks.update" call.
// Exactly one of *ProfileFilterLink or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ProfileFilterLink.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementProfileFilterLinksUpdateCall) Do() (*ProfileFilterLink, error) {
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
	ret := &ProfileFilterLink{
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
	//   "description": "Update an existing profile filter link.",
	//   "httpMethod": "PUT",
	//   "id": "analytics.management.profileFilterLinks.update",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "linkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to which profile filter link belongs.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "linkId": {
	//       "description": "ID of the profile filter link to be updated.",
	//       "location": "path",
	//       "pattern": "\\d+:\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "Profile ID to which filter link belongs",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property Id to which profile filter link belongs",
	//       "location": "path",
	//       "pattern": "UA-(\\d+)-(\\d+)",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks/{linkId}",
	//   "request": {
	//     "$ref": "ProfileFilterLink"
	//   },
	//   "response": {
	//     "$ref": "ProfileFilterLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.profileUserLinks.delete":

type ManagementProfileUserLinksDeleteCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	linkId        string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Delete: Removes a user from the given view (profile).
func (r *ManagementProfileUserLinksService) Delete(accountId string, webPropertyId string, profileId string, linkId string) *ManagementProfileUserLinksDeleteCall {
	c := &ManagementProfileUserLinksDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.linkId = linkId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfileUserLinksDeleteCall) Fields(s ...googleapi.Field) *ManagementProfileUserLinksDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfileUserLinksDeleteCall) Context(ctx context.Context) *ManagementProfileUserLinksDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfileUserLinksDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/entityUserLinks/{linkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
		"linkId":        c.linkId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.profileUserLinks.delete" call.
func (c *ManagementProfileUserLinksDeleteCall) Do() error {
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
	//   "description": "Removes a user from the given view (profile).",
	//   "httpMethod": "DELETE",
	//   "id": "analytics.management.profileUserLinks.delete",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "linkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to delete the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "linkId": {
	//       "description": "Link ID to delete the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to delete the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web Property ID to delete the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/entityUserLinks/{linkId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.manage.users"
	//   ]
	// }

}

// method id "analytics.management.profileUserLinks.insert":

type ManagementProfileUserLinksInsertCall struct {
	s              *Service
	accountId      string
	webPropertyId  string
	profileId      string
	entityuserlink *EntityUserLink
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Insert: Adds a new user to the given view (profile).
func (r *ManagementProfileUserLinksService) Insert(accountId string, webPropertyId string, profileId string, entityuserlink *EntityUserLink) *ManagementProfileUserLinksInsertCall {
	c := &ManagementProfileUserLinksInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.entityuserlink = entityuserlink
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfileUserLinksInsertCall) Fields(s ...googleapi.Field) *ManagementProfileUserLinksInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfileUserLinksInsertCall) Context(ctx context.Context) *ManagementProfileUserLinksInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfileUserLinksInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.entityuserlink)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/entityUserLinks")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.profileUserLinks.insert" call.
// Exactly one of *EntityUserLink or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *EntityUserLink.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementProfileUserLinksInsertCall) Do() (*EntityUserLink, error) {
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
	ret := &EntityUserLink{
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
	//   "description": "Adds a new user to the given view (profile).",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.profileUserLinks.insert",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to create the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to create the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web Property ID to create the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/entityUserLinks",
	//   "request": {
	//     "$ref": "EntityUserLink"
	//   },
	//   "response": {
	//     "$ref": "EntityUserLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.manage.users"
	//   ]
	// }

}

// method id "analytics.management.profileUserLinks.list":

type ManagementProfileUserLinksListCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: Lists profile-user links for a given view (profile).
func (r *ManagementProfileUserLinksService) List(accountId string, webPropertyId string, profileId string) *ManagementProfileUserLinksListCall {
	c := &ManagementProfileUserLinksListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of profile-user links to include in this response.
func (c *ManagementProfileUserLinksListCall) MaxResults(maxResults int64) *ManagementProfileUserLinksListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first profile-user link to retrieve. Use this parameter as a
// pagination mechanism along with the max-results parameter.
func (c *ManagementProfileUserLinksListCall) StartIndex(startIndex int64) *ManagementProfileUserLinksListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfileUserLinksListCall) Fields(s ...googleapi.Field) *ManagementProfileUserLinksListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementProfileUserLinksListCall) IfNoneMatch(entityTag string) *ManagementProfileUserLinksListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfileUserLinksListCall) Context(ctx context.Context) *ManagementProfileUserLinksListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfileUserLinksListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/entityUserLinks")
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

// Do executes the "analytics.management.profileUserLinks.list" call.
// Exactly one of *EntityUserLinks or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *EntityUserLinks.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementProfileUserLinksListCall) Do() (*EntityUserLinks, error) {
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
	ret := &EntityUserLinks{
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
	//   "description": "Lists profile-user links for a given view (profile).",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.profileUserLinks.list",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID which the given view (profile) belongs to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of profile-user links to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to retrieve the profile-user links for. Can either be a specific profile ID or '~all', which refers to all the profiles that user has access to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "start-index": {
	//       "description": "An index of the first profile-user link to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "webPropertyId": {
	//       "description": "Web Property ID which the given view (profile) belongs to. Can either be a specific web property ID or '~all', which refers to all the web properties that user has access to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/entityUserLinks",
	//   "response": {
	//     "$ref": "EntityUserLinks"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.manage.users",
	//     "https://www.googleapis.com/auth/analytics.manage.users.readonly"
	//   ]
	// }

}

// method id "analytics.management.profileUserLinks.update":

type ManagementProfileUserLinksUpdateCall struct {
	s              *Service
	accountId      string
	webPropertyId  string
	profileId      string
	linkId         string
	entityuserlink *EntityUserLink
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Update: Updates permissions for an existing user on the given view
// (profile).
func (r *ManagementProfileUserLinksService) Update(accountId string, webPropertyId string, profileId string, linkId string, entityuserlink *EntityUserLink) *ManagementProfileUserLinksUpdateCall {
	c := &ManagementProfileUserLinksUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.linkId = linkId
	c.entityuserlink = entityuserlink
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfileUserLinksUpdateCall) Fields(s ...googleapi.Field) *ManagementProfileUserLinksUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfileUserLinksUpdateCall) Context(ctx context.Context) *ManagementProfileUserLinksUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfileUserLinksUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.entityuserlink)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/entityUserLinks/{linkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
		"linkId":        c.linkId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.profileUserLinks.update" call.
// Exactly one of *EntityUserLink or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *EntityUserLink.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementProfileUserLinksUpdateCall) Do() (*EntityUserLink, error) {
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
	ret := &EntityUserLink{
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
	//   "description": "Updates permissions for an existing user on the given view (profile).",
	//   "httpMethod": "PUT",
	//   "id": "analytics.management.profileUserLinks.update",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "linkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to update the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "linkId": {
	//       "description": "Link ID to update the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile ID) to update the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web Property ID to update the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/entityUserLinks/{linkId}",
	//   "request": {
	//     "$ref": "EntityUserLink"
	//   },
	//   "response": {
	//     "$ref": "EntityUserLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.manage.users"
	//   ]
	// }

}

// method id "analytics.management.profiles.delete":

type ManagementProfilesDeleteCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Delete: Deletes a view (profile).
func (r *ManagementProfilesService) Delete(accountId string, webPropertyId string, profileId string) *ManagementProfilesDeleteCall {
	c := &ManagementProfilesDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfilesDeleteCall) Fields(s ...googleapi.Field) *ManagementProfilesDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfilesDeleteCall) Context(ctx context.Context) *ManagementProfilesDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfilesDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.profiles.delete" call.
func (c *ManagementProfilesDeleteCall) Do() error {
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
	//   "description": "Deletes a view (profile).",
	//   "httpMethod": "DELETE",
	//   "id": "analytics.management.profiles.delete",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to delete the view (profile) for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "ID of the view (profile) to be deleted.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to delete the view (profile) for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.profiles.get":

type ManagementProfilesGetCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Get: Gets a view (profile) to which the user has access.
func (r *ManagementProfilesService) Get(accountId string, webPropertyId string, profileId string) *ManagementProfilesGetCall {
	c := &ManagementProfilesGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfilesGetCall) Fields(s ...googleapi.Field) *ManagementProfilesGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementProfilesGetCall) IfNoneMatch(entityTag string) *ManagementProfilesGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfilesGetCall) Context(ctx context.Context) *ManagementProfilesGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfilesGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}")
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

// Do executes the "analytics.management.profiles.get" call.
// Exactly one of *Profile or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Profile.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementProfilesGetCall) Do() (*Profile, error) {
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
	ret := &Profile{
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
	//   "description": "Gets a view (profile) to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.profiles.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve the goal for.",
	//       "location": "path",
	//       "pattern": "[0-9]+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to retrieve the goal for.",
	//       "location": "path",
	//       "pattern": "[0-9]+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to retrieve the goal for.",
	//       "location": "path",
	//       "pattern": "UA-[0-9]+-[0-9]+",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}",
	//   "response": {
	//     "$ref": "Profile"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.profiles.insert":

type ManagementProfilesInsertCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profile       *Profile
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Insert: Create a new view (profile).
func (r *ManagementProfilesService) Insert(accountId string, webPropertyId string, profile *Profile) *ManagementProfilesInsertCall {
	c := &ManagementProfilesInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profile = profile
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfilesInsertCall) Fields(s ...googleapi.Field) *ManagementProfilesInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfilesInsertCall) Context(ctx context.Context) *ManagementProfilesInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfilesInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.profile)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.profiles.insert" call.
// Exactly one of *Profile or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Profile.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementProfilesInsertCall) Do() (*Profile, error) {
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
	ret := &Profile{
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
	//   "description": "Create a new view (profile).",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.profiles.insert",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to create the view (profile) for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to create the view (profile) for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles",
	//   "request": {
	//     "$ref": "Profile"
	//   },
	//   "response": {
	//     "$ref": "Profile"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
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
// Exactly one of *Profiles or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Profiles.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementProfilesListCall) Do() (*Profiles, error) {
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
	ret := &Profiles{
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
	//   "description": "Lists views (profiles) to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.profiles.list",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID for the view (profiles) to retrieve. Can either be a specific account ID or '~all', which refers to all the accounts to which the user has access.",
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
	//   "response": {
	//     "$ref": "Profiles"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.profiles.patch":

type ManagementProfilesPatchCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	profile       *Profile
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Patch: Updates an existing view (profile). This method supports patch
// semantics.
func (r *ManagementProfilesService) Patch(accountId string, webPropertyId string, profileId string, profile *Profile) *ManagementProfilesPatchCall {
	c := &ManagementProfilesPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.profile = profile
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfilesPatchCall) Fields(s ...googleapi.Field) *ManagementProfilesPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfilesPatchCall) Context(ctx context.Context) *ManagementProfilesPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfilesPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.profile)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.profiles.patch" call.
// Exactly one of *Profile or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Profile.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementProfilesPatchCall) Do() (*Profile, error) {
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
	ret := &Profile{
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
	//   "description": "Updates an existing view (profile). This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "analytics.management.profiles.patch",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to which the view (profile) belongs",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "ID of the view (profile) to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to which the view (profile) belongs",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}",
	//   "request": {
	//     "$ref": "Profile"
	//   },
	//   "response": {
	//     "$ref": "Profile"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.profiles.update":

type ManagementProfilesUpdateCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	profile       *Profile
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Update: Updates an existing view (profile).
func (r *ManagementProfilesService) Update(accountId string, webPropertyId string, profileId string, profile *Profile) *ManagementProfilesUpdateCall {
	c := &ManagementProfilesUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.profile = profile
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementProfilesUpdateCall) Fields(s ...googleapi.Field) *ManagementProfilesUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementProfilesUpdateCall) Context(ctx context.Context) *ManagementProfilesUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementProfilesUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.profile)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.profiles.update" call.
// Exactly one of *Profile or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Profile.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementProfilesUpdateCall) Do() (*Profile, error) {
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
	ret := &Profile{
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
	//   "description": "Updates an existing view (profile).",
	//   "httpMethod": "PUT",
	//   "id": "analytics.management.profiles.update",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to which the view (profile) belongs",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "ID of the view (profile) to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to which the view (profile) belongs",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}",
	//   "request": {
	//     "$ref": "Profile"
	//   },
	//   "response": {
	//     "$ref": "Profile"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.segments.list":

type ManagementSegmentsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Lists segments to which the user has access.
func (r *ManagementSegmentsService) List() *ManagementSegmentsListCall {
	c := &ManagementSegmentsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of segments to include in this response.
func (c *ManagementSegmentsListCall) MaxResults(maxResults int64) *ManagementSegmentsListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first segment to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
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
// Exactly one of *Segments or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Segments.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementSegmentsListCall) Do() (*Segments, error) {
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
	ret := &Segments{
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
	//   "description": "Lists segments to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.segments.list",
	//   "parameters": {
	//     "max-results": {
	//       "description": "The maximum number of segments to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "start-index": {
	//       "description": "An index of the first segment to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     }
	//   },
	//   "path": "management/segments",
	//   "response": {
	//     "$ref": "Segments"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.unsampledReports.get":

type ManagementUnsampledReportsGetCall struct {
	s                 *Service
	accountId         string
	webPropertyId     string
	profileId         string
	unsampledReportId string
	opt_              map[string]interface{}
	ctx_              context.Context
}

// Get: Returns a single unsampled report.
func (r *ManagementUnsampledReportsService) Get(accountId string, webPropertyId string, profileId string, unsampledReportId string) *ManagementUnsampledReportsGetCall {
	c := &ManagementUnsampledReportsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.unsampledReportId = unsampledReportId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementUnsampledReportsGetCall) Fields(s ...googleapi.Field) *ManagementUnsampledReportsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementUnsampledReportsGetCall) IfNoneMatch(entityTag string) *ManagementUnsampledReportsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementUnsampledReportsGetCall) Context(ctx context.Context) *ManagementUnsampledReportsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementUnsampledReportsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/unsampledReports/{unsampledReportId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":         c.accountId,
		"webPropertyId":     c.webPropertyId,
		"profileId":         c.profileId,
		"unsampledReportId": c.unsampledReportId,
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

// Do executes the "analytics.management.unsampledReports.get" call.
// Exactly one of *UnsampledReport or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *UnsampledReport.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementUnsampledReportsGetCall) Do() (*UnsampledReport, error) {
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
	ret := &UnsampledReport{
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
	//   "description": "Returns a single unsampled report.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.unsampledReports.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId",
	//     "unsampledReportId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve unsampled report for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to retrieve unsampled report for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "unsampledReportId": {
	//       "description": "ID of the unsampled report to retrieve.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to retrieve unsampled reports for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/unsampledReports/{unsampledReportId}",
	//   "response": {
	//     "$ref": "UnsampledReport"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.unsampledReports.insert":

type ManagementUnsampledReportsInsertCall struct {
	s               *Service
	accountId       string
	webPropertyId   string
	profileId       string
	unsampledreport *UnsampledReport
	opt_            map[string]interface{}
	ctx_            context.Context
}

// Insert: Create a new unsampled report.
func (r *ManagementUnsampledReportsService) Insert(accountId string, webPropertyId string, profileId string, unsampledreport *UnsampledReport) *ManagementUnsampledReportsInsertCall {
	c := &ManagementUnsampledReportsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	c.unsampledreport = unsampledreport
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementUnsampledReportsInsertCall) Fields(s ...googleapi.Field) *ManagementUnsampledReportsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementUnsampledReportsInsertCall) Context(ctx context.Context) *ManagementUnsampledReportsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementUnsampledReportsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.unsampledreport)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/unsampledReports")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"profileId":     c.profileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.unsampledReports.insert" call.
// Exactly one of *UnsampledReport or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *UnsampledReport.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementUnsampledReportsInsertCall) Do() (*UnsampledReport, error) {
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
	ret := &UnsampledReport{
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
	//   "description": "Create a new unsampled report.",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.unsampledReports.insert",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to create the unsampled report for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to create the unsampled report for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to create the unsampled report for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/unsampledReports",
	//   "request": {
	//     "$ref": "UnsampledReport"
	//   },
	//   "response": {
	//     "$ref": "UnsampledReport"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.unsampledReports.list":

type ManagementUnsampledReportsListCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	profileId     string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: Lists unsampled reports to which the user has access.
func (r *ManagementUnsampledReportsService) List(accountId string, webPropertyId string, profileId string) *ManagementUnsampledReportsListCall {
	c := &ManagementUnsampledReportsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.profileId = profileId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of unsampled reports to include in this response.
func (c *ManagementUnsampledReportsListCall) MaxResults(maxResults int64) *ManagementUnsampledReportsListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first unsampled report to retrieve. Use this parameter as a
// pagination mechanism along with the max-results parameter.
func (c *ManagementUnsampledReportsListCall) StartIndex(startIndex int64) *ManagementUnsampledReportsListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementUnsampledReportsListCall) Fields(s ...googleapi.Field) *ManagementUnsampledReportsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementUnsampledReportsListCall) IfNoneMatch(entityTag string) *ManagementUnsampledReportsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementUnsampledReportsListCall) Context(ctx context.Context) *ManagementUnsampledReportsListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementUnsampledReportsListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/unsampledReports")
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

// Do executes the "analytics.management.unsampledReports.list" call.
// Exactly one of *UnsampledReports or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *UnsampledReports.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementUnsampledReportsListCall) Do() (*UnsampledReports, error) {
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
	ret := &UnsampledReports{
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
	//   "description": "Lists unsampled reports to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.unsampledReports.list",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "profileId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve unsampled reports for. Must be a specific account ID, ~all is not supported.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of unsampled reports to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "profileId": {
	//       "description": "View (Profile) ID to retrieve unsampled reports for. Must be a specific view (profile) ID, ~all is not supported.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "start-index": {
	//       "description": "An index of the first unsampled report to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to retrieve unsampled reports for. Must be a specific web property ID, ~all is not supported.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/unsampledReports",
	//   "response": {
	//     "$ref": "UnsampledReports"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.uploads.deleteUploadData":

type ManagementUploadsDeleteUploadDataCall struct {
	s                                          *Service
	accountId                                  string
	webPropertyId                              string
	customDataSourceId                         string
	analyticsdataimportdeleteuploaddatarequest *AnalyticsDataimportDeleteUploadDataRequest
	opt_                                       map[string]interface{}
	ctx_                                       context.Context
}

// DeleteUploadData: Delete data associated with a previous upload.
func (r *ManagementUploadsService) DeleteUploadData(accountId string, webPropertyId string, customDataSourceId string, analyticsdataimportdeleteuploaddatarequest *AnalyticsDataimportDeleteUploadDataRequest) *ManagementUploadsDeleteUploadDataCall {
	c := &ManagementUploadsDeleteUploadDataCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.customDataSourceId = customDataSourceId
	c.analyticsdataimportdeleteuploaddatarequest = analyticsdataimportdeleteuploaddatarequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementUploadsDeleteUploadDataCall) Fields(s ...googleapi.Field) *ManagementUploadsDeleteUploadDataCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementUploadsDeleteUploadDataCall) Context(ctx context.Context) *ManagementUploadsDeleteUploadDataCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementUploadsDeleteUploadDataCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.analyticsdataimportdeleteuploaddatarequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/deleteUploadData")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":          c.accountId,
		"webPropertyId":      c.webPropertyId,
		"customDataSourceId": c.customDataSourceId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.uploads.deleteUploadData" call.
func (c *ManagementUploadsDeleteUploadDataCall) Do() error {
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
	//   "description": "Delete data associated with a previous upload.",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.uploads.deleteUploadData",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "customDataSourceId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account Id for the uploads to be deleted.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "customDataSourceId": {
	//       "description": "Custom data source Id for the uploads to be deleted.",
	//       "location": "path",
	//       "pattern": ".{22}",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property Id for the uploads to be deleted.",
	//       "location": "path",
	//       "pattern": "UA-(\\d+)-(\\d+)",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/deleteUploadData",
	//   "request": {
	//     "$ref": "AnalyticsDataimportDeleteUploadDataRequest"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.uploads.get":

type ManagementUploadsGetCall struct {
	s                  *Service
	accountId          string
	webPropertyId      string
	customDataSourceId string
	uploadId           string
	opt_               map[string]interface{}
	ctx_               context.Context
}

// Get: List uploads to which the user has access.
func (r *ManagementUploadsService) Get(accountId string, webPropertyId string, customDataSourceId string, uploadId string) *ManagementUploadsGetCall {
	c := &ManagementUploadsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.customDataSourceId = customDataSourceId
	c.uploadId = uploadId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementUploadsGetCall) Fields(s ...googleapi.Field) *ManagementUploadsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementUploadsGetCall) IfNoneMatch(entityTag string) *ManagementUploadsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementUploadsGetCall) Context(ctx context.Context) *ManagementUploadsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementUploadsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/uploads/{uploadId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":          c.accountId,
		"webPropertyId":      c.webPropertyId,
		"customDataSourceId": c.customDataSourceId,
		"uploadId":           c.uploadId,
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

// Do executes the "analytics.management.uploads.get" call.
// Exactly one of *Upload or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Upload.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementUploadsGetCall) Do() (*Upload, error) {
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
	ret := &Upload{
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
	//   "description": "List uploads to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.uploads.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "customDataSourceId",
	//     "uploadId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account Id for the upload to retrieve.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "customDataSourceId": {
	//       "description": "Custom data source Id for upload to retrieve.",
	//       "location": "path",
	//       "pattern": ".{22}",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "uploadId": {
	//       "description": "Upload Id to retrieve.",
	//       "location": "path",
	//       "pattern": ".{22}",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property Id for the upload to retrieve.",
	//       "location": "path",
	//       "pattern": "UA-(\\d+)-(\\d+)",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/uploads/{uploadId}",
	//   "response": {
	//     "$ref": "Upload"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.uploads.list":

type ManagementUploadsListCall struct {
	s                  *Service
	accountId          string
	webPropertyId      string
	customDataSourceId string
	opt_               map[string]interface{}
	ctx_               context.Context
}

// List: List uploads to which the user has access.
func (r *ManagementUploadsService) List(accountId string, webPropertyId string, customDataSourceId string) *ManagementUploadsListCall {
	c := &ManagementUploadsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.customDataSourceId = customDataSourceId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of uploads to include in this response.
func (c *ManagementUploadsListCall) MaxResults(maxResults int64) *ManagementUploadsListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": A 1-based index
// of the first upload to retrieve. Use this parameter as a pagination
// mechanism along with the max-results parameter.
func (c *ManagementUploadsListCall) StartIndex(startIndex int64) *ManagementUploadsListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementUploadsListCall) Fields(s ...googleapi.Field) *ManagementUploadsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementUploadsListCall) IfNoneMatch(entityTag string) *ManagementUploadsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementUploadsListCall) Context(ctx context.Context) *ManagementUploadsListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementUploadsListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/uploads")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":          c.accountId,
		"webPropertyId":      c.webPropertyId,
		"customDataSourceId": c.customDataSourceId,
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

// Do executes the "analytics.management.uploads.list" call.
// Exactly one of *Uploads or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Uploads.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementUploadsListCall) Do() (*Uploads, error) {
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
	ret := &Uploads{
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
	//   "description": "List uploads to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.uploads.list",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "customDataSourceId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account Id for the uploads to retrieve.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "customDataSourceId": {
	//       "description": "Custom data source Id for uploads to retrieve.",
	//       "location": "path",
	//       "pattern": ".{22}",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of uploads to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "start-index": {
	//       "description": "A 1-based index of the first upload to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property Id for the uploads to retrieve.",
	//       "location": "path",
	//       "pattern": "UA-(\\d+)-(\\d+)",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/uploads",
	//   "response": {
	//     "$ref": "Uploads"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.uploads.uploadData":

type ManagementUploadsUploadDataCall struct {
	s                  *Service
	accountId          string
	webPropertyId      string
	customDataSourceId string
	opt_               map[string]interface{}
	media_             io.Reader
	resumable_         googleapi.SizeReaderAt
	mediaType_         string
	protocol_          string
	ctx_               context.Context
}

// UploadData: Upload data for a custom data source.
func (r *ManagementUploadsService) UploadData(accountId string, webPropertyId string, customDataSourceId string) *ManagementUploadsUploadDataCall {
	c := &ManagementUploadsUploadDataCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.customDataSourceId = customDataSourceId
	return c
}

// Media specifies the media to upload in a single chunk.
// At most one of Media and ResumableMedia may be set.
func (c *ManagementUploadsUploadDataCall) Media(r io.Reader) *ManagementUploadsUploadDataCall {
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
func (c *ManagementUploadsUploadDataCall) ResumableMedia(ctx context.Context, r io.ReaderAt, size int64, mediaType string) *ManagementUploadsUploadDataCall {
	c.ctx_ = ctx
	c.resumable_ = io.NewSectionReader(r, 0, size)
	c.mediaType_ = mediaType
	c.protocol_ = "resumable"
	return c
}

// ProgressUpdater provides a callback function that will be called after every chunk.
// It should be a low-latency function in order to not slow down the upload operation.
// This should only be called when using ResumableMedia (as opposed to Media).
func (c *ManagementUploadsUploadDataCall) ProgressUpdater(pu googleapi.ProgressUpdater) *ManagementUploadsUploadDataCall {
	c.opt_["progressUpdater"] = pu
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementUploadsUploadDataCall) Fields(s ...googleapi.Field) *ManagementUploadsUploadDataCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
// This context will supersede any context previously provided to
// the ResumableMedia method.
func (c *ManagementUploadsUploadDataCall) Context(ctx context.Context) *ManagementUploadsUploadDataCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementUploadsUploadDataCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/uploads")
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
		"accountId":          c.accountId,
		"webPropertyId":      c.webPropertyId,
		"customDataSourceId": c.customDataSourceId,
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

// Do executes the "analytics.management.uploads.uploadData" call.
// Exactly one of *Upload or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Upload.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ManagementUploadsUploadDataCall) Do() (*Upload, error) {
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
	ret := &Upload{
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
	//   "description": "Upload data for a custom data source.",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.uploads.uploadData",
	//   "mediaUpload": {
	//     "accept": [
	//       "application/octet-stream"
	//     ],
	//     "maxSize": "1GB",
	//     "protocols": {
	//       "resumable": {
	//         "multipart": true,
	//         "path": "/resumable/upload/analytics/v3/management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/uploads"
	//       },
	//       "simple": {
	//         "multipart": true,
	//         "path": "/upload/analytics/v3/management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/uploads"
	//       }
	//     }
	//   },
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "customDataSourceId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account Id associated with the upload.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "customDataSourceId": {
	//       "description": "Custom data source Id to which the data being uploaded belongs.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property UA-string associated with the upload.",
	//       "location": "path",
	//       "pattern": "UA-\\d+-\\d+",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/uploads",
	//   "response": {
	//     "$ref": "Upload"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ],
	//   "supportsMediaUpload": true
	// }

}

// method id "analytics.management.webPropertyAdWordsLinks.delete":

type ManagementWebPropertyAdWordsLinksDeleteCall struct {
	s                        *Service
	accountId                string
	webPropertyId            string
	webPropertyAdWordsLinkId string
	opt_                     map[string]interface{}
	ctx_                     context.Context
}

// Delete: Deletes a web property-AdWords link.
func (r *ManagementWebPropertyAdWordsLinksService) Delete(accountId string, webPropertyId string, webPropertyAdWordsLinkId string) *ManagementWebPropertyAdWordsLinksDeleteCall {
	c := &ManagementWebPropertyAdWordsLinksDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.webPropertyAdWordsLinkId = webPropertyAdWordsLinkId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebPropertyAdWordsLinksDeleteCall) Fields(s ...googleapi.Field) *ManagementWebPropertyAdWordsLinksDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebPropertyAdWordsLinksDeleteCall) Context(ctx context.Context) *ManagementWebPropertyAdWordsLinksDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebPropertyAdWordsLinksDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks/{webPropertyAdWordsLinkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":                c.accountId,
		"webPropertyId":            c.webPropertyId,
		"webPropertyAdWordsLinkId": c.webPropertyAdWordsLinkId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.webPropertyAdWordsLinks.delete" call.
func (c *ManagementWebPropertyAdWordsLinksDeleteCall) Do() error {
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
	//   "description": "Deletes a web property-AdWords link.",
	//   "httpMethod": "DELETE",
	//   "id": "analytics.management.webPropertyAdWordsLinks.delete",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "webPropertyAdWordsLinkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "ID of the account which the given web property belongs to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyAdWordsLinkId": {
	//       "description": "Web property AdWords link ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to delete the AdWords link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks/{webPropertyAdWordsLinkId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.webPropertyAdWordsLinks.get":

type ManagementWebPropertyAdWordsLinksGetCall struct {
	s                        *Service
	accountId                string
	webPropertyId            string
	webPropertyAdWordsLinkId string
	opt_                     map[string]interface{}
	ctx_                     context.Context
}

// Get: Returns a web property-AdWords link to which the user has
// access.
func (r *ManagementWebPropertyAdWordsLinksService) Get(accountId string, webPropertyId string, webPropertyAdWordsLinkId string) *ManagementWebPropertyAdWordsLinksGetCall {
	c := &ManagementWebPropertyAdWordsLinksGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.webPropertyAdWordsLinkId = webPropertyAdWordsLinkId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebPropertyAdWordsLinksGetCall) Fields(s ...googleapi.Field) *ManagementWebPropertyAdWordsLinksGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementWebPropertyAdWordsLinksGetCall) IfNoneMatch(entityTag string) *ManagementWebPropertyAdWordsLinksGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebPropertyAdWordsLinksGetCall) Context(ctx context.Context) *ManagementWebPropertyAdWordsLinksGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebPropertyAdWordsLinksGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks/{webPropertyAdWordsLinkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":                c.accountId,
		"webPropertyId":            c.webPropertyId,
		"webPropertyAdWordsLinkId": c.webPropertyAdWordsLinkId,
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

// Do executes the "analytics.management.webPropertyAdWordsLinks.get" call.
// Exactly one of *EntityAdWordsLink or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *EntityAdWordsLink.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementWebPropertyAdWordsLinksGetCall) Do() (*EntityAdWordsLink, error) {
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
	ret := &EntityAdWordsLink{
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
	//   "description": "Returns a web property-AdWords link to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.webPropertyAdWordsLinks.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "webPropertyAdWordsLinkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "ID of the account which the given web property belongs to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyAdWordsLinkId": {
	//       "description": "Web property-AdWords link ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to retrieve the AdWords link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks/{webPropertyAdWordsLinkId}",
	//   "response": {
	//     "$ref": "EntityAdWordsLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.webPropertyAdWordsLinks.insert":

type ManagementWebPropertyAdWordsLinksInsertCall struct {
	s                 *Service
	accountId         string
	webPropertyId     string
	entityadwordslink *EntityAdWordsLink
	opt_              map[string]interface{}
	ctx_              context.Context
}

// Insert: Creates a webProperty-AdWords link.
func (r *ManagementWebPropertyAdWordsLinksService) Insert(accountId string, webPropertyId string, entityadwordslink *EntityAdWordsLink) *ManagementWebPropertyAdWordsLinksInsertCall {
	c := &ManagementWebPropertyAdWordsLinksInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.entityadwordslink = entityadwordslink
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebPropertyAdWordsLinksInsertCall) Fields(s ...googleapi.Field) *ManagementWebPropertyAdWordsLinksInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebPropertyAdWordsLinksInsertCall) Context(ctx context.Context) *ManagementWebPropertyAdWordsLinksInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebPropertyAdWordsLinksInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.entityadwordslink)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.webPropertyAdWordsLinks.insert" call.
// Exactly one of *EntityAdWordsLink or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *EntityAdWordsLink.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementWebPropertyAdWordsLinksInsertCall) Do() (*EntityAdWordsLink, error) {
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
	ret := &EntityAdWordsLink{
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
	//   "description": "Creates a webProperty-AdWords link.",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.webPropertyAdWordsLinks.insert",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "ID of the Google Analytics account to create the link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to create the link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks",
	//   "request": {
	//     "$ref": "EntityAdWordsLink"
	//   },
	//   "response": {
	//     "$ref": "EntityAdWordsLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.webPropertyAdWordsLinks.list":

type ManagementWebPropertyAdWordsLinksListCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: Lists webProperty-AdWords links for a given web property.
func (r *ManagementWebPropertyAdWordsLinksService) List(accountId string, webPropertyId string) *ManagementWebPropertyAdWordsLinksListCall {
	c := &ManagementWebPropertyAdWordsLinksListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of webProperty-AdWords links to include in this response.
func (c *ManagementWebPropertyAdWordsLinksListCall) MaxResults(maxResults int64) *ManagementWebPropertyAdWordsLinksListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first webProperty-AdWords link to retrieve. Use this parameter as a
// pagination mechanism along with the max-results parameter.
func (c *ManagementWebPropertyAdWordsLinksListCall) StartIndex(startIndex int64) *ManagementWebPropertyAdWordsLinksListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebPropertyAdWordsLinksListCall) Fields(s ...googleapi.Field) *ManagementWebPropertyAdWordsLinksListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementWebPropertyAdWordsLinksListCall) IfNoneMatch(entityTag string) *ManagementWebPropertyAdWordsLinksListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebPropertyAdWordsLinksListCall) Context(ctx context.Context) *ManagementWebPropertyAdWordsLinksListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebPropertyAdWordsLinksListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks")
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

// Do executes the "analytics.management.webPropertyAdWordsLinks.list" call.
// Exactly one of *EntityAdWordsLinks or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *EntityAdWordsLinks.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementWebPropertyAdWordsLinksListCall) Do() (*EntityAdWordsLinks, error) {
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
	ret := &EntityAdWordsLinks{
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
	//   "description": "Lists webProperty-AdWords links for a given web property.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.webPropertyAdWordsLinks.list",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "ID of the account which the given web property belongs to.",
	//       "location": "path",
	//       "pattern": "\\d+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of webProperty-AdWords links to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "start-index": {
	//       "description": "An index of the first webProperty-AdWords link to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to retrieve the AdWords links for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks",
	//   "response": {
	//     "$ref": "EntityAdWordsLinks"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.webPropertyAdWordsLinks.patch":

type ManagementWebPropertyAdWordsLinksPatchCall struct {
	s                        *Service
	accountId                string
	webPropertyId            string
	webPropertyAdWordsLinkId string
	entityadwordslink        *EntityAdWordsLink
	opt_                     map[string]interface{}
	ctx_                     context.Context
}

// Patch: Updates an existing webProperty-AdWords link. This method
// supports patch semantics.
func (r *ManagementWebPropertyAdWordsLinksService) Patch(accountId string, webPropertyId string, webPropertyAdWordsLinkId string, entityadwordslink *EntityAdWordsLink) *ManagementWebPropertyAdWordsLinksPatchCall {
	c := &ManagementWebPropertyAdWordsLinksPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.webPropertyAdWordsLinkId = webPropertyAdWordsLinkId
	c.entityadwordslink = entityadwordslink
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebPropertyAdWordsLinksPatchCall) Fields(s ...googleapi.Field) *ManagementWebPropertyAdWordsLinksPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebPropertyAdWordsLinksPatchCall) Context(ctx context.Context) *ManagementWebPropertyAdWordsLinksPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebPropertyAdWordsLinksPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.entityadwordslink)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks/{webPropertyAdWordsLinkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":                c.accountId,
		"webPropertyId":            c.webPropertyId,
		"webPropertyAdWordsLinkId": c.webPropertyAdWordsLinkId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.webPropertyAdWordsLinks.patch" call.
// Exactly one of *EntityAdWordsLink or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *EntityAdWordsLink.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementWebPropertyAdWordsLinksPatchCall) Do() (*EntityAdWordsLink, error) {
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
	ret := &EntityAdWordsLink{
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
	//   "description": "Updates an existing webProperty-AdWords link. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "analytics.management.webPropertyAdWordsLinks.patch",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "webPropertyAdWordsLinkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "ID of the account which the given web property belongs to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyAdWordsLinkId": {
	//       "description": "Web property-AdWords link ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to retrieve the AdWords link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks/{webPropertyAdWordsLinkId}",
	//   "request": {
	//     "$ref": "EntityAdWordsLink"
	//   },
	//   "response": {
	//     "$ref": "EntityAdWordsLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.webPropertyAdWordsLinks.update":

type ManagementWebPropertyAdWordsLinksUpdateCall struct {
	s                        *Service
	accountId                string
	webPropertyId            string
	webPropertyAdWordsLinkId string
	entityadwordslink        *EntityAdWordsLink
	opt_                     map[string]interface{}
	ctx_                     context.Context
}

// Update: Updates an existing webProperty-AdWords link.
func (r *ManagementWebPropertyAdWordsLinksService) Update(accountId string, webPropertyId string, webPropertyAdWordsLinkId string, entityadwordslink *EntityAdWordsLink) *ManagementWebPropertyAdWordsLinksUpdateCall {
	c := &ManagementWebPropertyAdWordsLinksUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.webPropertyAdWordsLinkId = webPropertyAdWordsLinkId
	c.entityadwordslink = entityadwordslink
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebPropertyAdWordsLinksUpdateCall) Fields(s ...googleapi.Field) *ManagementWebPropertyAdWordsLinksUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebPropertyAdWordsLinksUpdateCall) Context(ctx context.Context) *ManagementWebPropertyAdWordsLinksUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebPropertyAdWordsLinksUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.entityadwordslink)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks/{webPropertyAdWordsLinkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":                c.accountId,
		"webPropertyId":            c.webPropertyId,
		"webPropertyAdWordsLinkId": c.webPropertyAdWordsLinkId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.webPropertyAdWordsLinks.update" call.
// Exactly one of *EntityAdWordsLink or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *EntityAdWordsLink.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementWebPropertyAdWordsLinksUpdateCall) Do() (*EntityAdWordsLink, error) {
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
	ret := &EntityAdWordsLink{
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
	//   "description": "Updates an existing webProperty-AdWords link.",
	//   "httpMethod": "PUT",
	//   "id": "analytics.management.webPropertyAdWordsLinks.update",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "webPropertyAdWordsLinkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "ID of the account which the given web property belongs to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyAdWordsLinkId": {
	//       "description": "Web property-AdWords link ID.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to retrieve the AdWords link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks/{webPropertyAdWordsLinkId}",
	//   "request": {
	//     "$ref": "EntityAdWordsLink"
	//   },
	//   "response": {
	//     "$ref": "EntityAdWordsLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.webproperties.get":

type ManagementWebpropertiesGetCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Get: Gets a web property to which the user has access.
func (r *ManagementWebpropertiesService) Get(accountId string, webPropertyId string) *ManagementWebpropertiesGetCall {
	c := &ManagementWebpropertiesGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebpropertiesGetCall) Fields(s ...googleapi.Field) *ManagementWebpropertiesGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementWebpropertiesGetCall) IfNoneMatch(entityTag string) *ManagementWebpropertiesGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebpropertiesGetCall) Context(ctx context.Context) *ManagementWebpropertiesGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebpropertiesGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}")
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

// Do executes the "analytics.management.webproperties.get" call.
// Exactly one of *Webproperty or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Webproperty.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementWebpropertiesGetCall) Do() (*Webproperty, error) {
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
	ret := &Webproperty{
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
	//   "description": "Gets a web property to which the user has access.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.webproperties.get",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to retrieve the web property for.",
	//       "location": "path",
	//       "pattern": "[0-9]+",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "ID to retrieve the web property for.",
	//       "location": "path",
	//       "pattern": "UA-[0-9]+-[0-9]+",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}",
	//   "response": {
	//     "$ref": "Webproperty"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.webproperties.insert":

type ManagementWebpropertiesInsertCall struct {
	s           *Service
	accountId   string
	webproperty *Webproperty
	opt_        map[string]interface{}
	ctx_        context.Context
}

// Insert: Create a new property if the account has fewer than 20
// properties. Web properties are visible in the Google Analytics
// interface only if they have at least one profile.
func (r *ManagementWebpropertiesService) Insert(accountId string, webproperty *Webproperty) *ManagementWebpropertiesInsertCall {
	c := &ManagementWebpropertiesInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webproperty = webproperty
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebpropertiesInsertCall) Fields(s ...googleapi.Field) *ManagementWebpropertiesInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebpropertiesInsertCall) Context(ctx context.Context) *ManagementWebpropertiesInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebpropertiesInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.webproperty)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId": c.accountId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.webproperties.insert" call.
// Exactly one of *Webproperty or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Webproperty.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementWebpropertiesInsertCall) Do() (*Webproperty, error) {
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
	ret := &Webproperty{
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
	//   "description": "Create a new property if the account has fewer than 20 properties. Web properties are visible in the Google Analytics interface only if they have at least one profile.",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.webproperties.insert",
	//   "parameterOrder": [
	//     "accountId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to create the web property for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties",
	//   "request": {
	//     "$ref": "Webproperty"
	//   },
	//   "response": {
	//     "$ref": "Webproperty"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
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
// Exactly one of *Webproperties or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Webproperties.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementWebpropertiesListCall) Do() (*Webproperties, error) {
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
	ret := &Webproperties{
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
	//   "response": {
	//     "$ref": "Webproperties"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.management.webproperties.patch":

type ManagementWebpropertiesPatchCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	webproperty   *Webproperty
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Patch: Updates an existing web property. This method supports patch
// semantics.
func (r *ManagementWebpropertiesService) Patch(accountId string, webPropertyId string, webproperty *Webproperty) *ManagementWebpropertiesPatchCall {
	c := &ManagementWebpropertiesPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.webproperty = webproperty
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebpropertiesPatchCall) Fields(s ...googleapi.Field) *ManagementWebpropertiesPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebpropertiesPatchCall) Context(ctx context.Context) *ManagementWebpropertiesPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebpropertiesPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.webproperty)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.webproperties.patch" call.
// Exactly one of *Webproperty or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Webproperty.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementWebpropertiesPatchCall) Do() (*Webproperty, error) {
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
	ret := &Webproperty{
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
	//   "description": "Updates an existing web property. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "analytics.management.webproperties.patch",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to which the web property belongs",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}",
	//   "request": {
	//     "$ref": "Webproperty"
	//   },
	//   "response": {
	//     "$ref": "Webproperty"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.webproperties.update":

type ManagementWebpropertiesUpdateCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	webproperty   *Webproperty
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Update: Updates an existing web property.
func (r *ManagementWebpropertiesService) Update(accountId string, webPropertyId string, webproperty *Webproperty) *ManagementWebpropertiesUpdateCall {
	c := &ManagementWebpropertiesUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.webproperty = webproperty
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebpropertiesUpdateCall) Fields(s ...googleapi.Field) *ManagementWebpropertiesUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebpropertiesUpdateCall) Context(ctx context.Context) *ManagementWebpropertiesUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebpropertiesUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.webproperty)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.webproperties.update" call.
// Exactly one of *Webproperty or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Webproperty.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ManagementWebpropertiesUpdateCall) Do() (*Webproperty, error) {
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
	ret := &Webproperty{
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
	//   "description": "Updates an existing web property.",
	//   "httpMethod": "PUT",
	//   "id": "analytics.management.webproperties.update",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to which the web property belongs",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}",
	//   "request": {
	//     "$ref": "Webproperty"
	//   },
	//   "response": {
	//     "$ref": "Webproperty"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.edit"
	//   ]
	// }

}

// method id "analytics.management.webpropertyUserLinks.delete":

type ManagementWebpropertyUserLinksDeleteCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	linkId        string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Delete: Removes a user from the given web property.
func (r *ManagementWebpropertyUserLinksService) Delete(accountId string, webPropertyId string, linkId string) *ManagementWebpropertyUserLinksDeleteCall {
	c := &ManagementWebpropertyUserLinksDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.linkId = linkId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebpropertyUserLinksDeleteCall) Fields(s ...googleapi.Field) *ManagementWebpropertyUserLinksDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebpropertyUserLinksDeleteCall) Context(ctx context.Context) *ManagementWebpropertyUserLinksDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebpropertyUserLinksDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/entityUserLinks/{linkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"linkId":        c.linkId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.webpropertyUserLinks.delete" call.
func (c *ManagementWebpropertyUserLinksDeleteCall) Do() error {
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
	//   "description": "Removes a user from the given web property.",
	//   "httpMethod": "DELETE",
	//   "id": "analytics.management.webpropertyUserLinks.delete",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "linkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to delete the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "linkId": {
	//       "description": "Link ID to delete the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web Property ID to delete the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/entityUserLinks/{linkId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.manage.users"
	//   ]
	// }

}

// method id "analytics.management.webpropertyUserLinks.insert":

type ManagementWebpropertyUserLinksInsertCall struct {
	s              *Service
	accountId      string
	webPropertyId  string
	entityuserlink *EntityUserLink
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Insert: Adds a new user to the given web property.
func (r *ManagementWebpropertyUserLinksService) Insert(accountId string, webPropertyId string, entityuserlink *EntityUserLink) *ManagementWebpropertyUserLinksInsertCall {
	c := &ManagementWebpropertyUserLinksInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.entityuserlink = entityuserlink
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebpropertyUserLinksInsertCall) Fields(s ...googleapi.Field) *ManagementWebpropertyUserLinksInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebpropertyUserLinksInsertCall) Context(ctx context.Context) *ManagementWebpropertyUserLinksInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebpropertyUserLinksInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.entityuserlink)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/entityUserLinks")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.webpropertyUserLinks.insert" call.
// Exactly one of *EntityUserLink or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *EntityUserLink.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementWebpropertyUserLinksInsertCall) Do() (*EntityUserLink, error) {
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
	ret := &EntityUserLink{
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
	//   "description": "Adds a new user to the given web property.",
	//   "httpMethod": "POST",
	//   "id": "analytics.management.webpropertyUserLinks.insert",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to create the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web Property ID to create the user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/entityUserLinks",
	//   "request": {
	//     "$ref": "EntityUserLink"
	//   },
	//   "response": {
	//     "$ref": "EntityUserLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.manage.users"
	//   ]
	// }

}

// method id "analytics.management.webpropertyUserLinks.list":

type ManagementWebpropertyUserLinksListCall struct {
	s             *Service
	accountId     string
	webPropertyId string
	opt_          map[string]interface{}
	ctx_          context.Context
}

// List: Lists webProperty-user links for a given web property.
func (r *ManagementWebpropertyUserLinksService) List(accountId string, webPropertyId string) *ManagementWebpropertyUserLinksListCall {
	c := &ManagementWebpropertyUserLinksListCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	return c
}

// MaxResults sets the optional parameter "max-results": The maximum
// number of webProperty-user Links to include in this response.
func (c *ManagementWebpropertyUserLinksListCall) MaxResults(maxResults int64) *ManagementWebpropertyUserLinksListCall {
	c.opt_["max-results"] = maxResults
	return c
}

// StartIndex sets the optional parameter "start-index": An index of the
// first webProperty-user link to retrieve. Use this parameter as a
// pagination mechanism along with the max-results parameter.
func (c *ManagementWebpropertyUserLinksListCall) StartIndex(startIndex int64) *ManagementWebpropertyUserLinksListCall {
	c.opt_["start-index"] = startIndex
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebpropertyUserLinksListCall) Fields(s ...googleapi.Field) *ManagementWebpropertyUserLinksListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ManagementWebpropertyUserLinksListCall) IfNoneMatch(entityTag string) *ManagementWebpropertyUserLinksListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebpropertyUserLinksListCall) Context(ctx context.Context) *ManagementWebpropertyUserLinksListCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebpropertyUserLinksListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/entityUserLinks")
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

// Do executes the "analytics.management.webpropertyUserLinks.list" call.
// Exactly one of *EntityUserLinks or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *EntityUserLinks.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementWebpropertyUserLinksListCall) Do() (*EntityUserLinks, error) {
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
	ret := &EntityUserLinks{
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
	//   "description": "Lists webProperty-user links for a given web property.",
	//   "httpMethod": "GET",
	//   "id": "analytics.management.webpropertyUserLinks.list",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID which the given web property belongs to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "max-results": {
	//       "description": "The maximum number of webProperty-user Links to include in this response.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "start-index": {
	//       "description": "An index of the first webProperty-user link to retrieve. Use this parameter as a pagination mechanism along with the max-results parameter.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "webPropertyId": {
	//       "description": "Web Property ID for the webProperty-user links to retrieve. Can either be a specific web property ID or '~all', which refers to all the web properties that user has access to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/entityUserLinks",
	//   "response": {
	//     "$ref": "EntityUserLinks"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.manage.users",
	//     "https://www.googleapis.com/auth/analytics.manage.users.readonly"
	//   ]
	// }

}

// method id "analytics.management.webpropertyUserLinks.update":

type ManagementWebpropertyUserLinksUpdateCall struct {
	s              *Service
	accountId      string
	webPropertyId  string
	linkId         string
	entityuserlink *EntityUserLink
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Update: Updates permissions for an existing user on the given web
// property.
func (r *ManagementWebpropertyUserLinksService) Update(accountId string, webPropertyId string, linkId string, entityuserlink *EntityUserLink) *ManagementWebpropertyUserLinksUpdateCall {
	c := &ManagementWebpropertyUserLinksUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountId = accountId
	c.webPropertyId = webPropertyId
	c.linkId = linkId
	c.entityuserlink = entityuserlink
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ManagementWebpropertyUserLinksUpdateCall) Fields(s ...googleapi.Field) *ManagementWebpropertyUserLinksUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ManagementWebpropertyUserLinksUpdateCall) Context(ctx context.Context) *ManagementWebpropertyUserLinksUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ManagementWebpropertyUserLinksUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.entityuserlink)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "management/accounts/{accountId}/webproperties/{webPropertyId}/entityUserLinks/{linkId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"accountId":     c.accountId,
		"webPropertyId": c.webPropertyId,
		"linkId":        c.linkId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "analytics.management.webpropertyUserLinks.update" call.
// Exactly one of *EntityUserLink or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *EntityUserLink.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ManagementWebpropertyUserLinksUpdateCall) Do() (*EntityUserLink, error) {
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
	ret := &EntityUserLink{
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
	//   "description": "Updates permissions for an existing user on the given web property.",
	//   "httpMethod": "PUT",
	//   "id": "analytics.management.webpropertyUserLinks.update",
	//   "parameterOrder": [
	//     "accountId",
	//     "webPropertyId",
	//     "linkId"
	//   ],
	//   "parameters": {
	//     "accountId": {
	//       "description": "Account ID to update the account-user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "linkId": {
	//       "description": "Link ID to update the account-user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "webPropertyId": {
	//       "description": "Web property ID to update the account-user link for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "management/accounts/{accountId}/webproperties/{webPropertyId}/entityUserLinks/{linkId}",
	//   "request": {
	//     "$ref": "EntityUserLink"
	//   },
	//   "response": {
	//     "$ref": "EntityUserLink"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.manage.users"
	//   ]
	// }

}

// method id "analytics.metadata.columns.list":

type MetadataColumnsListCall struct {
	s          *Service
	reportType string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// List: Lists all columns for a report type
func (r *MetadataColumnsService) List(reportType string) *MetadataColumnsListCall {
	c := &MetadataColumnsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.reportType = reportType
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *MetadataColumnsListCall) Fields(s ...googleapi.Field) *MetadataColumnsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *MetadataColumnsListCall) IfNoneMatch(entityTag string) *MetadataColumnsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *MetadataColumnsListCall) Context(ctx context.Context) *MetadataColumnsListCall {
	c.ctx_ = ctx
	return c
}

func (c *MetadataColumnsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "metadata/{reportType}/columns")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"reportType": c.reportType,
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

// Do executes the "analytics.metadata.columns.list" call.
// Exactly one of *Columns or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Columns.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *MetadataColumnsListCall) Do() (*Columns, error) {
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
	ret := &Columns{
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
	//   "description": "Lists all columns for a report type",
	//   "httpMethod": "GET",
	//   "id": "analytics.metadata.columns.list",
	//   "parameterOrder": [
	//     "reportType"
	//   ],
	//   "parameters": {
	//     "reportType": {
	//       "description": "Report type. Allowed Values: 'ga'. Where 'ga' corresponds to the Core Reporting API",
	//       "location": "path",
	//       "pattern": "ga",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "metadata/{reportType}/columns",
	//   "response": {
	//     "$ref": "Columns"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics",
	//     "https://www.googleapis.com/auth/analytics.edit",
	//     "https://www.googleapis.com/auth/analytics.readonly"
	//   ]
	// }

}

// method id "analytics.provisioning.createAccountTicket":

type ProvisioningCreateAccountTicketCall struct {
	s             *Service
	accountticket *AccountTicket
	opt_          map[string]interface{}
	ctx_          context.Context
}

// CreateAccountTicket: Creates an account ticket.
func (r *ProvisioningService) CreateAccountTicket(accountticket *AccountTicket) *ProvisioningCreateAccountTicketCall {
	c := &ProvisioningCreateAccountTicketCall{s: r.s, opt_: make(map[string]interface{})}
	c.accountticket = accountticket
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProvisioningCreateAccountTicketCall) Fields(s ...googleapi.Field) *ProvisioningCreateAccountTicketCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ProvisioningCreateAccountTicketCall) Context(ctx context.Context) *ProvisioningCreateAccountTicketCall {
	c.ctx_ = ctx
	return c
}

func (c *ProvisioningCreateAccountTicketCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.accountticket)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "provisioning/createAccountTicket")
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

// Do executes the "analytics.provisioning.createAccountTicket" call.
// Exactly one of *AccountTicket or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *AccountTicket.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ProvisioningCreateAccountTicketCall) Do() (*AccountTicket, error) {
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
	ret := &AccountTicket{
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
	//   "description": "Creates an account ticket.",
	//   "httpMethod": "POST",
	//   "id": "analytics.provisioning.createAccountTicket",
	//   "path": "provisioning/createAccountTicket",
	//   "request": {
	//     "$ref": "AccountTicket"
	//   },
	//   "response": {
	//     "$ref": "AccountTicket"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/analytics.provision"
	//   ]
	// }

}
