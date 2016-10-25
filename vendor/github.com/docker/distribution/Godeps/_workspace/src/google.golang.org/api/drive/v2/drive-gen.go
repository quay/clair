// Package drive provides access to the Drive API.
//
// See https://developers.google.com/drive/
//
// Usage example:
//
//   import "google.golang.org/api/drive/v2"
//   ...
//   driveService, err := drive.New(oauthHttpClient)
package drive // import "google.golang.org/api/drive/v2"

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

const apiId = "drive:v2"
const apiName = "drive"
const apiVersion = "v2"
const basePath = "https://www.googleapis.com/drive/v2/"

// OAuth2 scopes used by this API.
const (
	// View and manage the files in your Google Drive
	DriveScope = "https://www.googleapis.com/auth/drive"

	// View and manage its own configuration data in your Google Drive
	DriveAppdataScope = "https://www.googleapis.com/auth/drive.appdata"

	// View your Google Drive apps
	DriveAppsReadonlyScope = "https://www.googleapis.com/auth/drive.apps.readonly"

	// View and manage Google Drive files and folders that you have opened
	// or created with this app
	DriveFileScope = "https://www.googleapis.com/auth/drive.file"

	// View and manage metadata of files in your Google Drive
	DriveMetadataScope = "https://www.googleapis.com/auth/drive.metadata"

	// View metadata for files in your Google Drive
	DriveMetadataReadonlyScope = "https://www.googleapis.com/auth/drive.metadata.readonly"

	// View the photos, videos and albums in your Google Photos
	DrivePhotosReadonlyScope = "https://www.googleapis.com/auth/drive.photos.readonly"

	// View the files in your Google Drive
	DriveReadonlyScope = "https://www.googleapis.com/auth/drive.readonly"

	// Modify your Google Apps Script scripts' behavior
	DriveScriptsScope = "https://www.googleapis.com/auth/drive.scripts"
)

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.About = NewAboutService(s)
	s.Apps = NewAppsService(s)
	s.Changes = NewChangesService(s)
	s.Channels = NewChannelsService(s)
	s.Children = NewChildrenService(s)
	s.Comments = NewCommentsService(s)
	s.Files = NewFilesService(s)
	s.Parents = NewParentsService(s)
	s.Permissions = NewPermissionsService(s)
	s.Properties = NewPropertiesService(s)
	s.Realtime = NewRealtimeService(s)
	s.Replies = NewRepliesService(s)
	s.Revisions = NewRevisionsService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	About *AboutService

	Apps *AppsService

	Changes *ChangesService

	Channels *ChannelsService

	Children *ChildrenService

	Comments *CommentsService

	Files *FilesService

	Parents *ParentsService

	Permissions *PermissionsService

	Properties *PropertiesService

	Realtime *RealtimeService

	Replies *RepliesService

	Revisions *RevisionsService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewAboutService(s *Service) *AboutService {
	rs := &AboutService{s: s}
	return rs
}

type AboutService struct {
	s *Service
}

func NewAppsService(s *Service) *AppsService {
	rs := &AppsService{s: s}
	return rs
}

type AppsService struct {
	s *Service
}

func NewChangesService(s *Service) *ChangesService {
	rs := &ChangesService{s: s}
	return rs
}

type ChangesService struct {
	s *Service
}

func NewChannelsService(s *Service) *ChannelsService {
	rs := &ChannelsService{s: s}
	return rs
}

type ChannelsService struct {
	s *Service
}

func NewChildrenService(s *Service) *ChildrenService {
	rs := &ChildrenService{s: s}
	return rs
}

type ChildrenService struct {
	s *Service
}

func NewCommentsService(s *Service) *CommentsService {
	rs := &CommentsService{s: s}
	return rs
}

type CommentsService struct {
	s *Service
}

func NewFilesService(s *Service) *FilesService {
	rs := &FilesService{s: s}
	return rs
}

type FilesService struct {
	s *Service
}

func NewParentsService(s *Service) *ParentsService {
	rs := &ParentsService{s: s}
	return rs
}

type ParentsService struct {
	s *Service
}

func NewPermissionsService(s *Service) *PermissionsService {
	rs := &PermissionsService{s: s}
	return rs
}

type PermissionsService struct {
	s *Service
}

func NewPropertiesService(s *Service) *PropertiesService {
	rs := &PropertiesService{s: s}
	return rs
}

type PropertiesService struct {
	s *Service
}

func NewRealtimeService(s *Service) *RealtimeService {
	rs := &RealtimeService{s: s}
	return rs
}

type RealtimeService struct {
	s *Service
}

func NewRepliesService(s *Service) *RepliesService {
	rs := &RepliesService{s: s}
	return rs
}

type RepliesService struct {
	s *Service
}

func NewRevisionsService(s *Service) *RevisionsService {
	rs := &RevisionsService{s: s}
	return rs
}

type RevisionsService struct {
	s *Service
}

// About: An item with user information and settings.
type About struct {
	// AdditionalRoleInfo: Information about supported additional roles per
	// file type. The most specific type takes precedence.
	AdditionalRoleInfo []*AboutAdditionalRoleInfo `json:"additionalRoleInfo,omitempty"`

	// DomainSharingPolicy: The domain sharing policy for the current user.
	// Possible values are:
	// - allowed
	// - allowedWithWarning
	// - incomingOnly
	// - disallowed
	DomainSharingPolicy string `json:"domainSharingPolicy,omitempty"`

	// Etag: The ETag of the item.
	Etag string `json:"etag,omitempty"`

	// ExportFormats: The allowable export formats.
	ExportFormats []*AboutExportFormats `json:"exportFormats,omitempty"`

	// Features: List of additional features enabled on this account.
	Features []*AboutFeatures `json:"features,omitempty"`

	// FolderColorPalette: The palette of allowable folder colors as RGB hex
	// strings.
	FolderColorPalette []string `json:"folderColorPalette,omitempty"`

	// ImportFormats: The allowable import formats.
	ImportFormats []*AboutImportFormats `json:"importFormats,omitempty"`

	// IsCurrentAppInstalled: A boolean indicating whether the authenticated
	// app is installed by the authenticated user.
	IsCurrentAppInstalled bool `json:"isCurrentAppInstalled,omitempty"`

	// Kind: This is always drive#about.
	Kind string `json:"kind,omitempty"`

	// LanguageCode: The user's language or locale code, as defined by BCP
	// 47, with some extensions from Unicode's LDML format
	// (http://www.unicode.org/reports/tr35/).
	LanguageCode string `json:"languageCode,omitempty"`

	// LargestChangeId: The largest change id.
	LargestChangeId int64 `json:"largestChangeId,omitempty,string"`

	// MaxUploadSizes: List of max upload sizes for each file type. The most
	// specific type takes precedence.
	MaxUploadSizes []*AboutMaxUploadSizes `json:"maxUploadSizes,omitempty"`

	// Name: The name of the current user.
	Name string `json:"name,omitempty"`

	// PermissionId: The current user's ID as visible in the permissions
	// collection.
	PermissionId string `json:"permissionId,omitempty"`

	// QuotaBytesByService: The amount of storage quota used by different
	// Google services.
	QuotaBytesByService []*AboutQuotaBytesByService `json:"quotaBytesByService,omitempty"`

	// QuotaBytesTotal: The total number of quota bytes.
	QuotaBytesTotal int64 `json:"quotaBytesTotal,omitempty,string"`

	// QuotaBytesUsed: The number of quota bytes used by Google Drive.
	QuotaBytesUsed int64 `json:"quotaBytesUsed,omitempty,string"`

	// QuotaBytesUsedAggregate: The number of quota bytes used by all Google
	// apps (Drive, Picasa, etc.).
	QuotaBytesUsedAggregate int64 `json:"quotaBytesUsedAggregate,omitempty,string"`

	// QuotaBytesUsedInTrash: The number of quota bytes used by trashed
	// items.
	QuotaBytesUsedInTrash int64 `json:"quotaBytesUsedInTrash,omitempty,string"`

	// QuotaType: The type of the user's storage quota. Possible values are:
	//
	// - LIMITED
	// - UNLIMITED
	QuotaType string `json:"quotaType,omitempty"`

	// RemainingChangeIds: The number of remaining change ids.
	RemainingChangeIds int64 `json:"remainingChangeIds,omitempty,string"`

	// RootFolderId: The id of the root folder.
	RootFolderId string `json:"rootFolderId,omitempty"`

	// SelfLink: A link back to this item.
	SelfLink string `json:"selfLink,omitempty"`

	// User: The authenticated user.
	User *User `json:"user,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AdditionalRoleInfo")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *About) MarshalJSON() ([]byte, error) {
	type noMethod About
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type AboutAdditionalRoleInfo struct {
	// RoleSets: The supported additional roles per primary role.
	RoleSets []*AboutAdditionalRoleInfoRoleSets `json:"roleSets,omitempty"`

	// Type: The content type that this additional role info applies to.
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "RoleSets") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AboutAdditionalRoleInfo) MarshalJSON() ([]byte, error) {
	type noMethod AboutAdditionalRoleInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type AboutAdditionalRoleInfoRoleSets struct {
	// AdditionalRoles: The supported additional roles with the primary
	// role.
	AdditionalRoles []string `json:"additionalRoles,omitempty"`

	// PrimaryRole: A primary permission role.
	PrimaryRole string `json:"primaryRole,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AdditionalRoles") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AboutAdditionalRoleInfoRoleSets) MarshalJSON() ([]byte, error) {
	type noMethod AboutAdditionalRoleInfoRoleSets
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type AboutExportFormats struct {
	// Source: The content type to convert from.
	Source string `json:"source,omitempty"`

	// Targets: The possible content types to convert to.
	Targets []string `json:"targets,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Source") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AboutExportFormats) MarshalJSON() ([]byte, error) {
	type noMethod AboutExportFormats
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type AboutFeatures struct {
	// FeatureName: The name of the feature.
	FeatureName string `json:"featureName,omitempty"`

	// FeatureRate: The request limit rate for this feature, in queries per
	// second.
	FeatureRate float64 `json:"featureRate,omitempty"`

	// ForceSendFields is a list of field names (e.g. "FeatureName") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AboutFeatures) MarshalJSON() ([]byte, error) {
	type noMethod AboutFeatures
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type AboutImportFormats struct {
	// Source: The imported file's content type to convert from.
	Source string `json:"source,omitempty"`

	// Targets: The possible content types to convert to.
	Targets []string `json:"targets,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Source") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AboutImportFormats) MarshalJSON() ([]byte, error) {
	type noMethod AboutImportFormats
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type AboutMaxUploadSizes struct {
	// Size: The max upload size for this type.
	Size int64 `json:"size,omitempty,string"`

	// Type: The file type.
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Size") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AboutMaxUploadSizes) MarshalJSON() ([]byte, error) {
	type noMethod AboutMaxUploadSizes
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type AboutQuotaBytesByService struct {
	// BytesUsed: The storage quota bytes used by the service.
	BytesUsed int64 `json:"bytesUsed,omitempty,string"`

	// ServiceName: The service's name, e.g. DRIVE, GMAIL, or PHOTOS.
	ServiceName string `json:"serviceName,omitempty"`

	// ForceSendFields is a list of field names (e.g. "BytesUsed") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AboutQuotaBytesByService) MarshalJSON() ([]byte, error) {
	type noMethod AboutQuotaBytesByService
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// App: The apps resource provides a list of the apps that a user has
// installed, with information about each app's supported MIME types,
// file extensions, and other details.
type App struct {
	// Authorized: Whether the app is authorized to access data on the
	// user's Drive.
	Authorized bool `json:"authorized,omitempty"`

	// CreateInFolderTemplate: The template url to create a new file with
	// this app in a given folder. The template will contain {folderId} to
	// be replaced by the folder to create the new file in.
	CreateInFolderTemplate string `json:"createInFolderTemplate,omitempty"`

	// CreateUrl: The url to create a new file with this app.
	CreateUrl string `json:"createUrl,omitempty"`

	// HasDriveWideScope: Whether the app has drive-wide scope. An app with
	// drive-wide scope can access all files in the user's drive.
	HasDriveWideScope bool `json:"hasDriveWideScope,omitempty"`

	// Icons: The various icons for the app.
	Icons []*AppIcons `json:"icons,omitempty"`

	// Id: The ID of the app.
	Id string `json:"id,omitempty"`

	// Installed: Whether the app is installed.
	Installed bool `json:"installed,omitempty"`

	// Kind: This is always drive#app.
	Kind string `json:"kind,omitempty"`

	// LongDescription: A long description of the app.
	LongDescription string `json:"longDescription,omitempty"`

	// Name: The name of the app.
	Name string `json:"name,omitempty"`

	// ObjectType: The type of object this app creates (e.g. Chart). If
	// empty, the app name should be used instead.
	ObjectType string `json:"objectType,omitempty"`

	// OpenUrlTemplate: The template url for opening files with this app.
	// The template will contain {ids} and/or {exportIds} to be replaced by
	// the actual file ids. See  Open Files  for the full documentation.
	OpenUrlTemplate string `json:"openUrlTemplate,omitempty"`

	// PrimaryFileExtensions: The list of primary file extensions.
	PrimaryFileExtensions []string `json:"primaryFileExtensions,omitempty"`

	// PrimaryMimeTypes: The list of primary mime types.
	PrimaryMimeTypes []string `json:"primaryMimeTypes,omitempty"`

	// ProductId: The ID of the product listing for this app.
	ProductId string `json:"productId,omitempty"`

	// ProductUrl: A link to the product listing for this app.
	ProductUrl string `json:"productUrl,omitempty"`

	// SecondaryFileExtensions: The list of secondary file extensions.
	SecondaryFileExtensions []string `json:"secondaryFileExtensions,omitempty"`

	// SecondaryMimeTypes: The list of secondary mime types.
	SecondaryMimeTypes []string `json:"secondaryMimeTypes,omitempty"`

	// ShortDescription: A short description of the app.
	ShortDescription string `json:"shortDescription,omitempty"`

	// SupportsCreate: Whether this app supports creating new objects.
	SupportsCreate bool `json:"supportsCreate,omitempty"`

	// SupportsImport: Whether this app supports importing Google Docs.
	SupportsImport bool `json:"supportsImport,omitempty"`

	// SupportsMultiOpen: Whether this app supports opening more than one
	// file.
	SupportsMultiOpen bool `json:"supportsMultiOpen,omitempty"`

	// SupportsOfflineCreate: Whether this app supports creating new files
	// when offline.
	SupportsOfflineCreate bool `json:"supportsOfflineCreate,omitempty"`

	// UseByDefault: Whether the app is selected as the default handler for
	// the types it supports.
	UseByDefault bool `json:"useByDefault,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Authorized") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *App) MarshalJSON() ([]byte, error) {
	type noMethod App
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type AppIcons struct {
	// Category: Category of the icon. Allowed values are:
	// - application - icon for the application
	// - document - icon for a file associated with the app
	// - documentShared - icon for a shared file associated with the app
	Category string `json:"category,omitempty"`

	// IconUrl: URL for the icon.
	IconUrl string `json:"iconUrl,omitempty"`

	// Size: Size of the icon. Represented as the maximum of the width and
	// height.
	Size int64 `json:"size,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Category") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AppIcons) MarshalJSON() ([]byte, error) {
	type noMethod AppIcons
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AppList: A list of third-party applications which the user has
// installed or given access to Google Drive.
type AppList struct {
	// DefaultAppIds: List of app IDs that the user has specified to use by
	// default. The list is in reverse-priority order (lowest to highest).
	DefaultAppIds []string `json:"defaultAppIds,omitempty"`

	// Etag: The ETag of the list.
	Etag string `json:"etag,omitempty"`

	// Items: The actual list of apps.
	Items []*App `json:"items,omitempty"`

	// Kind: This is always drive#appList.
	Kind string `json:"kind,omitempty"`

	// SelfLink: A link back to this list.
	SelfLink string `json:"selfLink,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "DefaultAppIds") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AppList) MarshalJSON() ([]byte, error) {
	type noMethod AppList
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Change: Representation of a change to a file.
type Change struct {
	// Deleted: Whether the file has been deleted.
	Deleted bool `json:"deleted,omitempty"`

	// File: The updated state of the file. Present if the file has not been
	// deleted.
	File *File `json:"file,omitempty"`

	// FileId: The ID of the file associated with this change.
	FileId string `json:"fileId,omitempty"`

	// Id: The ID of the change.
	Id int64 `json:"id,omitempty,string"`

	// Kind: This is always drive#change.
	Kind string `json:"kind,omitempty"`

	// ModificationDate: The time of this modification.
	ModificationDate string `json:"modificationDate,omitempty"`

	// SelfLink: A link back to this change.
	SelfLink string `json:"selfLink,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Deleted") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Change) MarshalJSON() ([]byte, error) {
	type noMethod Change
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChangeList: A list of changes for a user.
type ChangeList struct {
	// Etag: The ETag of the list.
	Etag string `json:"etag,omitempty"`

	// Items: The actual list of changes.
	Items []*Change `json:"items,omitempty"`

	// Kind: This is always drive#changeList.
	Kind string `json:"kind,omitempty"`

	// LargestChangeId: The current largest change ID.
	LargestChangeId int64 `json:"largestChangeId,omitempty,string"`

	// NextLink: A link to the next page of changes.
	NextLink string `json:"nextLink,omitempty"`

	// NextPageToken: The page token for the next page of changes.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// SelfLink: A link back to this list.
	SelfLink string `json:"selfLink,omitempty"`

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

func (s *ChangeList) MarshalJSON() ([]byte, error) {
	type noMethod ChangeList
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Channel: An notification channel used to watch for resource changes.
type Channel struct {
	// Address: The address where notifications are delivered for this
	// channel.
	Address string `json:"address,omitempty"`

	// Expiration: Date and time of notification channel expiration,
	// expressed as a Unix timestamp, in milliseconds. Optional.
	Expiration int64 `json:"expiration,omitempty,string"`

	// Id: A UUID or similar unique string that identifies this channel.
	Id string `json:"id,omitempty"`

	// Kind: Identifies this as a notification channel used to watch for
	// changes to a resource. Value: the fixed string "api#channel".
	Kind string `json:"kind,omitempty"`

	// Params: Additional parameters controlling delivery channel behavior.
	// Optional.
	Params map[string]string `json:"params,omitempty"`

	// Payload: A Boolean value to indicate whether payload is wanted.
	// Optional.
	Payload bool `json:"payload,omitempty"`

	// ResourceId: An opaque ID that identifies the resource being watched
	// on this channel. Stable across different API versions.
	ResourceId string `json:"resourceId,omitempty"`

	// ResourceUri: A version-specific identifier for the watched resource.
	ResourceUri string `json:"resourceUri,omitempty"`

	// Token: An arbitrary string delivered to the target address with each
	// notification delivered over this channel. Optional.
	Token string `json:"token,omitempty"`

	// Type: The type of delivery mechanism used for this channel.
	Type string `json:"type,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Address") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Channel) MarshalJSON() ([]byte, error) {
	type noMethod Channel
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChildList: A list of children of a file.
type ChildList struct {
	// Etag: The ETag of the list.
	Etag string `json:"etag,omitempty"`

	// Items: The actual list of children.
	Items []*ChildReference `json:"items,omitempty"`

	// Kind: This is always drive#childList.
	Kind string `json:"kind,omitempty"`

	// NextLink: A link to the next page of children.
	NextLink string `json:"nextLink,omitempty"`

	// NextPageToken: The page token for the next page of children.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// SelfLink: A link back to this list.
	SelfLink string `json:"selfLink,omitempty"`

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

func (s *ChildList) MarshalJSON() ([]byte, error) {
	type noMethod ChildList
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ChildReference: A reference to a folder's child.
type ChildReference struct {
	// ChildLink: A link to the child.
	ChildLink string `json:"childLink,omitempty"`

	// Id: The ID of the child.
	Id string `json:"id,omitempty"`

	// Kind: This is always drive#childReference.
	Kind string `json:"kind,omitempty"`

	// SelfLink: A link back to this reference.
	SelfLink string `json:"selfLink,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "ChildLink") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ChildReference) MarshalJSON() ([]byte, error) {
	type noMethod ChildReference
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Comment: A JSON representation of a comment on a file in Google
// Drive.
type Comment struct {
	// Anchor: A region of the document represented as a JSON string. See
	// anchor documentation for details on how to define and interpret
	// anchor properties.
	Anchor string `json:"anchor,omitempty"`

	// Author: The user who wrote this comment.
	Author *User `json:"author,omitempty"`

	// CommentId: The ID of the comment.
	CommentId string `json:"commentId,omitempty"`

	// Content: The plain text content used to create this comment. This is
	// not HTML safe and should only be used as a starting point to make
	// edits to a comment's content.
	Content string `json:"content,omitempty"`

	// Context: The context of the file which is being commented on.
	Context *CommentContext `json:"context,omitempty"`

	// CreatedDate: The date when this comment was first created.
	CreatedDate string `json:"createdDate,omitempty"`

	// Deleted: Whether this comment has been deleted. If a comment has been
	// deleted the content will be cleared and this will only represent a
	// comment that once existed.
	Deleted bool `json:"deleted,omitempty"`

	// FileId: The file which this comment is addressing.
	FileId string `json:"fileId,omitempty"`

	// FileTitle: The title of the file which this comment is addressing.
	FileTitle string `json:"fileTitle,omitempty"`

	// HtmlContent: HTML formatted content for this comment.
	HtmlContent string `json:"htmlContent,omitempty"`

	// Kind: This is always drive#comment.
	Kind string `json:"kind,omitempty"`

	// ModifiedDate: The date when this comment or any of its replies were
	// last modified.
	ModifiedDate string `json:"modifiedDate,omitempty"`

	// Replies: Replies to this post.
	Replies []*CommentReply `json:"replies,omitempty"`

	// SelfLink: A link back to this comment.
	SelfLink string `json:"selfLink,omitempty"`

	// Status: The status of this comment. Status can be changed by posting
	// a reply to a comment with the desired status.
	// - "open" - The comment is still open.
	// - "resolved" - The comment has been resolved by one of its replies.
	Status string `json:"status,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Anchor") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Comment) MarshalJSON() ([]byte, error) {
	type noMethod Comment
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentContext: The context of the file which is being commented on.
type CommentContext struct {
	// Type: The MIME type of the context snippet.
	Type string `json:"type,omitempty"`

	// Value: Data representation of the segment of the file being commented
	// on. In the case of a text file for example, this would be the actual
	// text that the comment is about.
	Value string `json:"value,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Type") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CommentContext) MarshalJSON() ([]byte, error) {
	type noMethod CommentContext
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentList: A JSON representation of a list of comments on a file in
// Google Drive.
type CommentList struct {
	// Items: List of comments.
	Items []*Comment `json:"items,omitempty"`

	// Kind: This is always drive#commentList.
	Kind string `json:"kind,omitempty"`

	// NextLink: A link to the next page of comments.
	NextLink string `json:"nextLink,omitempty"`

	// NextPageToken: The token to use to request the next page of results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// SelfLink: A link back to this list.
	SelfLink string `json:"selfLink,omitempty"`

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

func (s *CommentList) MarshalJSON() ([]byte, error) {
	type noMethod CommentList
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentReply: A JSON representation of a reply to a comment on a file
// in Google Drive.
type CommentReply struct {
	// Author: The user who wrote this reply.
	Author *User `json:"author,omitempty"`

	// Content: The plain text content used to create this reply. This is
	// not HTML safe and should only be used as a starting point to make
	// edits to a reply's content. This field is required on inserts if no
	// verb is specified (resolve/reopen).
	Content string `json:"content,omitempty"`

	// CreatedDate: The date when this reply was first created.
	CreatedDate string `json:"createdDate,omitempty"`

	// Deleted: Whether this reply has been deleted. If a reply has been
	// deleted the content will be cleared and this will only represent a
	// reply that once existed.
	Deleted bool `json:"deleted,omitempty"`

	// HtmlContent: HTML formatted content for this reply.
	HtmlContent string `json:"htmlContent,omitempty"`

	// Kind: This is always drive#commentReply.
	Kind string `json:"kind,omitempty"`

	// ModifiedDate: The date when this reply was last modified.
	ModifiedDate string `json:"modifiedDate,omitempty"`

	// ReplyId: The ID of the reply.
	ReplyId string `json:"replyId,omitempty"`

	// Verb: The action this reply performed to the parent comment. When
	// creating a new reply this is the action to be perform to the parent
	// comment. Possible values are:
	// - "resolve" - To resolve a comment.
	// - "reopen" - To reopen (un-resolve) a comment.
	Verb string `json:"verb,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Author") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CommentReply) MarshalJSON() ([]byte, error) {
	type noMethod CommentReply
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentReplyList: A JSON representation of a list of replies to a
// comment on a file in Google Drive.
type CommentReplyList struct {
	// Items: List of reply.
	Items []*CommentReply `json:"items,omitempty"`

	// Kind: This is always drive#commentReplyList.
	Kind string `json:"kind,omitempty"`

	// NextLink: A link to the next page of replies.
	NextLink string `json:"nextLink,omitempty"`

	// NextPageToken: The token to use to request the next page of results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// SelfLink: A link back to this list.
	SelfLink string `json:"selfLink,omitempty"`

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

func (s *CommentReplyList) MarshalJSON() ([]byte, error) {
	type noMethod CommentReplyList
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// File: The metadata for a file.
type File struct {
	// AlternateLink: A link for opening the file in a relevant Google
	// editor or viewer.
	AlternateLink string `json:"alternateLink,omitempty"`

	// AppDataContents: Whether this file is in the Application Data folder.
	AppDataContents bool `json:"appDataContents,omitempty"`

	// CanComment: Whether the current user can comment on the file.
	CanComment bool `json:"canComment,omitempty"`

	// Copyable: Whether the file can be copied by the current user.
	Copyable bool `json:"copyable,omitempty"`

	// CreatedDate: Create time for this file (formatted RFC 3339
	// timestamp).
	CreatedDate string `json:"createdDate,omitempty"`

	// DefaultOpenWithLink: A link to open this file with the user's default
	// app for this file. Only populated when the drive.apps.readonly scope
	// is used.
	DefaultOpenWithLink string `json:"defaultOpenWithLink,omitempty"`

	// Description: A short description of the file.
	Description string `json:"description,omitempty"`

	DownloadUrl string `json:"downloadUrl,omitempty"`

	// Editable: Whether the file can be edited by the current user.
	Editable bool `json:"editable,omitempty"`

	// EmbedLink: A link for embedding the file.
	EmbedLink string `json:"embedLink,omitempty"`

	// Etag: ETag of the file.
	Etag string `json:"etag,omitempty"`

	// ExplicitlyTrashed: Whether this file has been explicitly trashed, as
	// opposed to recursively trashed.
	ExplicitlyTrashed bool `json:"explicitlyTrashed,omitempty"`

	// ExportLinks: Links for exporting Google Docs to specific formats.
	ExportLinks map[string]string `json:"exportLinks,omitempty"`

	// FileExtension: The final component of fullFileExtension with trailing
	// text that does not appear to be part of the extension removed. This
	// field is only populated for files with content stored in Drive; it is
	// not populated for Google Docs or shortcut files.
	FileExtension string `json:"fileExtension,omitempty"`

	// FileSize: The size of the file in bytes. This field is only populated
	// for files with content stored in Drive; it is not populated for
	// Google Docs or shortcut files.
	FileSize int64 `json:"fileSize,omitempty,string"`

	// FolderColorRgb: Folder color as an RGB hex string if the file is a
	// folder. The list of supported colors is available in the
	// folderColorPalette field of the About resource. If an unsupported
	// color is specified, it will be changed to the closest color in the
	// palette.
	FolderColorRgb string `json:"folderColorRgb,omitempty"`

	// FullFileExtension: The full file extension; extracted from the title.
	// May contain multiple concatenated extensions, such as "tar.gz".
	// Removing an extension from the title does not clear this field;
	// however, changing the extension on the title does update this field.
	// This field is only populated for files with content stored in Drive;
	// it is not populated for Google Docs or shortcut files.
	FullFileExtension string `json:"fullFileExtension,omitempty"`

	// HeadRevisionId: The ID of the file's head revision. This field is
	// only populated for files with content stored in Drive; it is not
	// populated for Google Docs or shortcut files.
	HeadRevisionId string `json:"headRevisionId,omitempty"`

	// IconLink: A link to the file's icon.
	IconLink string `json:"iconLink,omitempty"`

	// Id: The ID of the file.
	Id string `json:"id,omitempty"`

	// ImageMediaMetadata: Metadata about image media. This will only be
	// present for image types, and its contents will depend on what can be
	// parsed from the image content.
	ImageMediaMetadata *FileImageMediaMetadata `json:"imageMediaMetadata,omitempty"`

	// IndexableText: Indexable text attributes for the file (can only be
	// written)
	IndexableText *FileIndexableText `json:"indexableText,omitempty"`

	// Kind: The type of file. This is always drive#file.
	Kind string `json:"kind,omitempty"`

	// Labels: A group of labels for the file.
	Labels *FileLabels `json:"labels,omitempty"`

	// LastModifyingUser: The last user to modify this file.
	LastModifyingUser *User `json:"lastModifyingUser,omitempty"`

	// LastModifyingUserName: Name of the last user to modify this file.
	LastModifyingUserName string `json:"lastModifyingUserName,omitempty"`

	// LastViewedByMeDate: Last time this file was viewed by the user
	// (formatted RFC 3339 timestamp).
	LastViewedByMeDate string `json:"lastViewedByMeDate,omitempty"`

	// MarkedViewedByMeDate: Deprecated.
	MarkedViewedByMeDate string `json:"markedViewedByMeDate,omitempty"`

	// Md5Checksum: An MD5 checksum for the content of this file. This field
	// is only populated for files with content stored in Drive; it is not
	// populated for Google Docs or shortcut files.
	Md5Checksum string `json:"md5Checksum,omitempty"`

	// MimeType: The MIME type of the file. This is only mutable on update
	// when uploading new content. This field can be left blank, and the
	// mimetype will be determined from the uploaded content's MIME type.
	MimeType string `json:"mimeType,omitempty"`

	// ModifiedByMeDate: Last time this file was modified by the user
	// (formatted RFC 3339 timestamp). Note that setting modifiedDate will
	// also update the modifiedByMe date for the user which set the date.
	ModifiedByMeDate string `json:"modifiedByMeDate,omitempty"`

	// ModifiedDate: Last time this file was modified by anyone (formatted
	// RFC 3339 timestamp). This is only mutable on update when the
	// setModifiedDate parameter is set.
	ModifiedDate string `json:"modifiedDate,omitempty"`

	// OpenWithLinks: A map of the id of each of the user's apps to a link
	// to open this file with that app. Only populated when the
	// drive.apps.readonly scope is used.
	OpenWithLinks map[string]string `json:"openWithLinks,omitempty"`

	// OriginalFilename: The original filename if the file was uploaded
	// manually, or the original title if the file was inserted through the
	// API. Note that renames of the title will not change the original
	// filename. This field is only populated for files with content stored
	// in Drive; it is not populated for Google Docs or shortcut files.
	OriginalFilename string `json:"originalFilename,omitempty"`

	// OwnedByMe: Whether the file is owned by the current user.
	OwnedByMe bool `json:"ownedByMe,omitempty"`

	// OwnerNames: Name(s) of the owner(s) of this file.
	OwnerNames []string `json:"ownerNames,omitempty"`

	// Owners: The owner(s) of this file.
	Owners []*User `json:"owners,omitempty"`

	// Parents: Collection of parent folders which contain this
	// file.
	// Setting this field will put the file in all of the provided folders.
	// On insert, if no folders are provided, the file will be placed in the
	// default root folder.
	Parents []*ParentReference `json:"parents,omitempty"`

	// Permissions: The list of permissions for users with access to this
	// file.
	Permissions []*Permission `json:"permissions,omitempty"`

	// Properties: The list of properties.
	Properties []*Property `json:"properties,omitempty"`

	// QuotaBytesUsed: The number of quota bytes used by this file.
	QuotaBytesUsed int64 `json:"quotaBytesUsed,omitempty,string"`

	// SelfLink: A link back to this file.
	SelfLink string `json:"selfLink,omitempty"`

	// Shareable: Whether the file's sharing settings can be modified by the
	// current user.
	Shareable bool `json:"shareable,omitempty"`

	// Shared: Whether the file has been shared.
	Shared bool `json:"shared,omitempty"`

	// SharedWithMeDate: Time at which this file was shared with the user
	// (formatted RFC 3339 timestamp).
	SharedWithMeDate string `json:"sharedWithMeDate,omitempty"`

	// SharingUser: User that shared the item with the current user, if
	// available.
	SharingUser *User `json:"sharingUser,omitempty"`

	// Spaces: The list of spaces which contain the file. Supported values
	// are 'drive', 'appDataFolder' and 'photos'.
	Spaces []string `json:"spaces,omitempty"`

	// Thumbnail: Thumbnail for the file. Only accepted on upload and for
	// files that are not already thumbnailed by Google.
	Thumbnail *FileThumbnail `json:"thumbnail,omitempty"`

	// ThumbnailLink: A short-lived link to the file's thumbnail. Typically
	// lasts on the order of hours.
	ThumbnailLink string `json:"thumbnailLink,omitempty"`

	// Title: The title of this file.
	Title string `json:"title,omitempty"`

	// UserPermission: The permissions for the authenticated user on this
	// file.
	UserPermission *Permission `json:"userPermission,omitempty"`

	// Version: A monotonically increasing version number for the file. This
	// reflects every change made to the file on the server, even those not
	// visible to the requesting user.
	Version int64 `json:"version,omitempty,string"`

	// VideoMediaMetadata: Metadata about video media. This will only be
	// present for video types.
	VideoMediaMetadata *FileVideoMediaMetadata `json:"videoMediaMetadata,omitempty"`

	// WebContentLink: A link for downloading the content of the file in a
	// browser using cookie based authentication. In cases where the content
	// is shared publicly, the content can be downloaded without any
	// credentials.
	WebContentLink string `json:"webContentLink,omitempty"`

	// WebViewLink: A link only available on public folders for viewing
	// their static web assets (HTML, CSS, JS, etc) via Google Drive's
	// Website Hosting.
	WebViewLink string `json:"webViewLink,omitempty"`

	// WritersCanShare: Whether writers can share the document with other
	// users.
	WritersCanShare bool `json:"writersCanShare,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AlternateLink") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *File) MarshalJSON() ([]byte, error) {
	type noMethod File
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FileImageMediaMetadata: Metadata about image media. This will only be
// present for image types, and its contents will depend on what can be
// parsed from the image content.
type FileImageMediaMetadata struct {
	// Aperture: The aperture used to create the photo (f-number).
	Aperture float64 `json:"aperture,omitempty"`

	// CameraMake: The make of the camera used to create the photo.
	CameraMake string `json:"cameraMake,omitempty"`

	// CameraModel: The model of the camera used to create the photo.
	CameraModel string `json:"cameraModel,omitempty"`

	// ColorSpace: The color space of the photo.
	ColorSpace string `json:"colorSpace,omitempty"`

	// Date: The date and time the photo was taken (EXIF format timestamp).
	Date string `json:"date,omitempty"`

	// ExposureBias: The exposure bias of the photo (APEX value).
	ExposureBias float64 `json:"exposureBias,omitempty"`

	// ExposureMode: The exposure mode used to create the photo.
	ExposureMode string `json:"exposureMode,omitempty"`

	// ExposureTime: The length of the exposure, in seconds.
	ExposureTime float64 `json:"exposureTime,omitempty"`

	// FlashUsed: Whether a flash was used to create the photo.
	FlashUsed bool `json:"flashUsed,omitempty"`

	// FocalLength: The focal length used to create the photo, in
	// millimeters.
	FocalLength float64 `json:"focalLength,omitempty"`

	// Height: The height of the image in pixels.
	Height int64 `json:"height,omitempty"`

	// IsoSpeed: The ISO speed used to create the photo.
	IsoSpeed int64 `json:"isoSpeed,omitempty"`

	// Lens: The lens used to create the photo.
	Lens string `json:"lens,omitempty"`

	// Location: Geographic location information stored in the image.
	Location *FileImageMediaMetadataLocation `json:"location,omitempty"`

	// MaxApertureValue: The smallest f-number of the lens at the focal
	// length used to create the photo (APEX value).
	MaxApertureValue float64 `json:"maxApertureValue,omitempty"`

	// MeteringMode: The metering mode used to create the photo.
	MeteringMode string `json:"meteringMode,omitempty"`

	// Rotation: The rotation in clockwise degrees from the image's original
	// orientation.
	Rotation int64 `json:"rotation,omitempty"`

	// Sensor: The type of sensor used to create the photo.
	Sensor string `json:"sensor,omitempty"`

	// SubjectDistance: The distance to the subject of the photo, in meters.
	SubjectDistance int64 `json:"subjectDistance,omitempty"`

	// WhiteBalance: The white balance mode used to create the photo.
	WhiteBalance string `json:"whiteBalance,omitempty"`

	// Width: The width of the image in pixels.
	Width int64 `json:"width,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Aperture") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FileImageMediaMetadata) MarshalJSON() ([]byte, error) {
	type noMethod FileImageMediaMetadata
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FileImageMediaMetadataLocation: Geographic location information
// stored in the image.
type FileImageMediaMetadataLocation struct {
	// Altitude: The altitude stored in the image.
	Altitude float64 `json:"altitude,omitempty"`

	// Latitude: The latitude stored in the image.
	Latitude float64 `json:"latitude,omitempty"`

	// Longitude: The longitude stored in the image.
	Longitude float64 `json:"longitude,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Altitude") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FileImageMediaMetadataLocation) MarshalJSON() ([]byte, error) {
	type noMethod FileImageMediaMetadataLocation
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FileIndexableText: Indexable text attributes for the file (can only
// be written)
type FileIndexableText struct {
	// Text: The text to be indexed for this file.
	Text string `json:"text,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Text") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FileIndexableText) MarshalJSON() ([]byte, error) {
	type noMethod FileIndexableText
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FileLabels: A group of labels for the file.
type FileLabels struct {
	// Hidden: Deprecated.
	Hidden bool `json:"hidden,omitempty"`

	// Restricted: Whether viewers and commenters are prevented from
	// downloading, printing, and copying this file.
	Restricted bool `json:"restricted,omitempty"`

	// Starred: Whether this file is starred by the user.
	Starred bool `json:"starred,omitempty"`

	// Trashed: Whether this file has been trashed. This label applies to
	// all users accessing the file; however, only owners are allowed to see
	// and untrash files.
	Trashed bool `json:"trashed,omitempty"`

	// Viewed: Whether this file has been viewed by this user.
	Viewed bool `json:"viewed,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Hidden") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FileLabels) MarshalJSON() ([]byte, error) {
	type noMethod FileLabels
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FileThumbnail: Thumbnail for the file. Only accepted on upload and
// for files that are not already thumbnailed by Google.
type FileThumbnail struct {
	// Image: The URL-safe Base64 encoded bytes of the thumbnail image. It
	// should conform to RFC 4648 section 5.
	Image string `json:"image,omitempty"`

	// MimeType: The MIME type of the thumbnail.
	MimeType string `json:"mimeType,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Image") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FileThumbnail) MarshalJSON() ([]byte, error) {
	type noMethod FileThumbnail
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FileVideoMediaMetadata: Metadata about video media. This will only be
// present for video types.
type FileVideoMediaMetadata struct {
	// DurationMillis: The duration of the video in milliseconds.
	DurationMillis int64 `json:"durationMillis,omitempty,string"`

	// Height: The height of the video in pixels.
	Height int64 `json:"height,omitempty"`

	// Width: The width of the video in pixels.
	Width int64 `json:"width,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DurationMillis") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FileVideoMediaMetadata) MarshalJSON() ([]byte, error) {
	type noMethod FileVideoMediaMetadata
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// FileList: A list of files.
type FileList struct {
	// Etag: The ETag of the list.
	Etag string `json:"etag,omitempty"`

	// Items: The actual list of files.
	Items []*File `json:"items,omitempty"`

	// Kind: This is always drive#fileList.
	Kind string `json:"kind,omitempty"`

	// NextLink: A link to the next page of files.
	NextLink string `json:"nextLink,omitempty"`

	// NextPageToken: The page token for the next page of files.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// SelfLink: A link back to this list.
	SelfLink string `json:"selfLink,omitempty"`

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

func (s *FileList) MarshalJSON() ([]byte, error) {
	type noMethod FileList
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// GeneratedIds: A list of generated IDs which can be provided in insert
// requests
type GeneratedIds struct {
	// Ids: The IDs generated for the requesting user in the specified
	// space.
	Ids []string `json:"ids,omitempty"`

	// Kind: This is always drive#generatedIds
	Kind string `json:"kind,omitempty"`

	// Space: The type of file that can be created with these IDs.
	Space string `json:"space,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Ids") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *GeneratedIds) MarshalJSON() ([]byte, error) {
	type noMethod GeneratedIds
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ParentList: A list of a file's parents.
type ParentList struct {
	// Etag: The ETag of the list.
	Etag string `json:"etag,omitempty"`

	// Items: The actual list of parents.
	Items []*ParentReference `json:"items,omitempty"`

	// Kind: This is always drive#parentList.
	Kind string `json:"kind,omitempty"`

	// SelfLink: A link back to this list.
	SelfLink string `json:"selfLink,omitempty"`

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

func (s *ParentList) MarshalJSON() ([]byte, error) {
	type noMethod ParentList
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ParentReference: A reference to a file's parent.
type ParentReference struct {
	// Id: The ID of the parent.
	Id string `json:"id,omitempty"`

	// IsRoot: Whether or not the parent is the root folder.
	IsRoot bool `json:"isRoot,omitempty"`

	// Kind: This is always drive#parentReference.
	Kind string `json:"kind,omitempty"`

	// ParentLink: A link to the parent.
	ParentLink string `json:"parentLink,omitempty"`

	// SelfLink: A link back to this reference.
	SelfLink string `json:"selfLink,omitempty"`

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

func (s *ParentReference) MarshalJSON() ([]byte, error) {
	type noMethod ParentReference
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Permission: A permission for a file.
type Permission struct {
	// AdditionalRoles: Additional roles for this user. Only commenter is
	// currently allowed.
	AdditionalRoles []string `json:"additionalRoles,omitempty"`

	// AuthKey: The authkey parameter required for this permission.
	AuthKey string `json:"authKey,omitempty"`

	// Domain: The domain name of the entity this permission refers to. This
	// is an output-only field which is present when the permission type is
	// user, group or domain.
	Domain string `json:"domain,omitempty"`

	// EmailAddress: The email address of the user or group this permission
	// refers to. This is an output-only field which is present when the
	// permission type is user or group.
	EmailAddress string `json:"emailAddress,omitempty"`

	// Etag: The ETag of the permission.
	Etag string `json:"etag,omitempty"`

	// Id: The ID of the user this permission refers to, and identical to
	// the permissionId in the About and Files resources. When making a
	// drive.permissions.insert request, exactly one of the id or value
	// fields must be specified.
	Id string `json:"id,omitempty"`

	// Kind: This is always drive#permission.
	Kind string `json:"kind,omitempty"`

	// Name: The name for this permission.
	Name string `json:"name,omitempty"`

	// PhotoLink: A link to the profile photo, if available.
	PhotoLink string `json:"photoLink,omitempty"`

	// Role: The primary role for this user. Allowed values are:
	// - owner
	// - reader
	// - writer
	Role string `json:"role,omitempty"`

	// SelfLink: A link back to this permission.
	SelfLink string `json:"selfLink,omitempty"`

	// Type: The account type. Allowed values are:
	// - user
	// - group
	// - domain
	// - anyone
	Type string `json:"type,omitempty"`

	// Value: The email address or domain name for the entity. This is used
	// during inserts and is not populated in responses. When making a
	// drive.permissions.insert request, exactly one of the id or value
	// fields must be specified.
	Value string `json:"value,omitempty"`

	// WithLink: Whether the link is required for this permission.
	WithLink bool `json:"withLink,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AdditionalRoles") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Permission) MarshalJSON() ([]byte, error) {
	type noMethod Permission
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PermissionId: An ID for a user or group as seen in Permission items.
type PermissionId struct {
	// Id: The permission ID.
	Id string `json:"id,omitempty"`

	// Kind: This is always drive#permissionId.
	Kind string `json:"kind,omitempty"`

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

func (s *PermissionId) MarshalJSON() ([]byte, error) {
	type noMethod PermissionId
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PermissionList: A list of permissions associated with a file.
type PermissionList struct {
	// Etag: The ETag of the list.
	Etag string `json:"etag,omitempty"`

	// Items: The actual list of permissions.
	Items []*Permission `json:"items,omitempty"`

	// Kind: This is always drive#permissionList.
	Kind string `json:"kind,omitempty"`

	// SelfLink: A link back to this list.
	SelfLink string `json:"selfLink,omitempty"`

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

func (s *PermissionList) MarshalJSON() ([]byte, error) {
	type noMethod PermissionList
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Property: A key-value pair attached to a file that is either public
// or private to an application.
// The following limits apply to file properties:
// - Maximum of 100 properties total per file
// - Maximum of 30 private properties per app
// - Maximum of 30 public properties
// - Maximum of 124 bytes size limit on (key + value) string in UTF-8
// encoding for a single property.
type Property struct {
	// Etag: ETag of the property.
	Etag string `json:"etag,omitempty"`

	// Key: The key of this property.
	Key string `json:"key,omitempty"`

	// Kind: This is always drive#property.
	Kind string `json:"kind,omitempty"`

	// SelfLink: The link back to this property.
	SelfLink string `json:"selfLink,omitempty"`

	// Value: The value of this property.
	Value string `json:"value,omitempty"`

	// Visibility: The visibility of this property.
	Visibility string `json:"visibility,omitempty"`

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

func (s *Property) MarshalJSON() ([]byte, error) {
	type noMethod Property
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PropertyList: A collection of properties, key-value pairs that are
// either public or private to an application.
type PropertyList struct {
	// Etag: The ETag of the list.
	Etag string `json:"etag,omitempty"`

	// Items: The list of properties.
	Items []*Property `json:"items,omitempty"`

	// Kind: This is always drive#propertyList.
	Kind string `json:"kind,omitempty"`

	// SelfLink: The link back to this list.
	SelfLink string `json:"selfLink,omitempty"`

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

func (s *PropertyList) MarshalJSON() ([]byte, error) {
	type noMethod PropertyList
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Revision: A revision of a file.
type Revision struct {
	// DownloadUrl: Short term download URL for the file. This will only be
	// populated on files with content stored in Drive.
	DownloadUrl string `json:"downloadUrl,omitempty"`

	// Etag: The ETag of the revision.
	Etag string `json:"etag,omitempty"`

	// ExportLinks: Links for exporting Google Docs to specific formats.
	ExportLinks map[string]string `json:"exportLinks,omitempty"`

	// FileSize: The size of the revision in bytes. This will only be
	// populated on files with content stored in Drive.
	FileSize int64 `json:"fileSize,omitempty,string"`

	// Id: The ID of the revision.
	Id string `json:"id,omitempty"`

	// Kind: This is always drive#revision.
	Kind string `json:"kind,omitempty"`

	// LastModifyingUser: The last user to modify this revision.
	LastModifyingUser *User `json:"lastModifyingUser,omitempty"`

	// LastModifyingUserName: Name of the last user to modify this revision.
	LastModifyingUserName string `json:"lastModifyingUserName,omitempty"`

	// Md5Checksum: An MD5 checksum for the content of this revision. This
	// will only be populated on files with content stored in Drive.
	Md5Checksum string `json:"md5Checksum,omitempty"`

	// MimeType: The MIME type of the revision.
	MimeType string `json:"mimeType,omitempty"`

	// ModifiedDate: Last time this revision was modified (formatted RFC
	// 3339 timestamp).
	ModifiedDate string `json:"modifiedDate,omitempty"`

	// OriginalFilename: The original filename when this revision was
	// created. This will only be populated on files with content stored in
	// Drive.
	OriginalFilename string `json:"originalFilename,omitempty"`

	// Pinned: Whether this revision is pinned to prevent automatic purging.
	// This will only be populated and can only be modified on files with
	// content stored in Drive which are not Google Docs. Revisions can also
	// be pinned when they are created through the
	// drive.files.insert/update/copy by using the pinned query parameter.
	Pinned bool `json:"pinned,omitempty"`

	// PublishAuto: Whether subsequent revisions will be automatically
	// republished. This is only populated and can only be modified for
	// Google Docs.
	PublishAuto bool `json:"publishAuto,omitempty"`

	// Published: Whether this revision is published. This is only populated
	// and can only be modified for Google Docs.
	Published bool `json:"published,omitempty"`

	// PublishedLink: A link to the published revision.
	PublishedLink string `json:"publishedLink,omitempty"`

	// PublishedOutsideDomain: Whether this revision is published outside
	// the domain. This is only populated and can only be modified for
	// Google Docs.
	PublishedOutsideDomain bool `json:"publishedOutsideDomain,omitempty"`

	// SelfLink: A link back to this revision.
	SelfLink string `json:"selfLink,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "DownloadUrl") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Revision) MarshalJSON() ([]byte, error) {
	type noMethod Revision
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RevisionList: A list of revisions of a file.
type RevisionList struct {
	// Etag: The ETag of the list.
	Etag string `json:"etag,omitempty"`

	// Items: The actual list of revisions.
	Items []*Revision `json:"items,omitempty"`

	// Kind: This is always drive#revisionList.
	Kind string `json:"kind,omitempty"`

	// SelfLink: A link back to this list.
	SelfLink string `json:"selfLink,omitempty"`

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

func (s *RevisionList) MarshalJSON() ([]byte, error) {
	type noMethod RevisionList
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// User: The JSON template for a user.
type User struct {
	// DisplayName: A plain text displayable name for this user.
	DisplayName string `json:"displayName,omitempty"`

	// EmailAddress: The email address of the user.
	EmailAddress string `json:"emailAddress,omitempty"`

	// IsAuthenticatedUser: Whether this user is the same as the
	// authenticated user for whom the request was made.
	IsAuthenticatedUser bool `json:"isAuthenticatedUser,omitempty"`

	// Kind: This is always drive#user.
	Kind string `json:"kind,omitempty"`

	// PermissionId: The user's ID as visible in the permissions collection.
	PermissionId string `json:"permissionId,omitempty"`

	// Picture: The user's profile picture.
	Picture *UserPicture `json:"picture,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DisplayName") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *User) MarshalJSON() ([]byte, error) {
	type noMethod User
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// UserPicture: The user's profile picture.
type UserPicture struct {
	// Url: A URL that points to a profile picture of this user.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Url") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *UserPicture) MarshalJSON() ([]byte, error) {
	type noMethod UserPicture
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "drive.about.get":

type AboutGetCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// Get: Gets the information about the current user along with Drive API
// settings
func (r *AboutService) Get() *AboutGetCall {
	c := &AboutGetCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// IncludeSubscribed sets the optional parameter "includeSubscribed":
// When calculating the number of remaining change IDs, whether to
// include public files the user has opened and shared files. When set
// to false, this counts only change IDs for owned files and any shared
// or public files that the user has explicitly added to a folder they
// own.
func (c *AboutGetCall) IncludeSubscribed(includeSubscribed bool) *AboutGetCall {
	c.opt_["includeSubscribed"] = includeSubscribed
	return c
}

// MaxChangeIdCount sets the optional parameter "maxChangeIdCount":
// Maximum number of remaining change IDs to count
func (c *AboutGetCall) MaxChangeIdCount(maxChangeIdCount int64) *AboutGetCall {
	c.opt_["maxChangeIdCount"] = maxChangeIdCount
	return c
}

// StartChangeId sets the optional parameter "startChangeId": Change ID
// to start counting from when calculating number of remaining change
// IDs
func (c *AboutGetCall) StartChangeId(startChangeId int64) *AboutGetCall {
	c.opt_["startChangeId"] = startChangeId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AboutGetCall) Fields(s ...googleapi.Field) *AboutGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AboutGetCall) IfNoneMatch(entityTag string) *AboutGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AboutGetCall) Context(ctx context.Context) *AboutGetCall {
	c.ctx_ = ctx
	return c
}

func (c *AboutGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["includeSubscribed"]; ok {
		params.Set("includeSubscribed", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxChangeIdCount"]; ok {
		params.Set("maxChangeIdCount", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["startChangeId"]; ok {
		params.Set("startChangeId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "about")
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

// Do executes the "drive.about.get" call.
// Exactly one of *About or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *About.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *AboutGetCall) Do() (*About, error) {
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
	ret := &About{
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
	//   "description": "Gets the information about the current user along with Drive API settings",
	//   "httpMethod": "GET",
	//   "id": "drive.about.get",
	//   "parameters": {
	//     "includeSubscribed": {
	//       "default": "true",
	//       "description": "When calculating the number of remaining change IDs, whether to include public files the user has opened and shared files. When set to false, this counts only change IDs for owned files and any shared or public files that the user has explicitly added to a folder they own.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "maxChangeIdCount": {
	//       "default": "1",
	//       "description": "Maximum number of remaining change IDs to count",
	//       "format": "int64",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "startChangeId": {
	//       "description": "Change ID to start counting from when calculating number of remaining change IDs",
	//       "format": "int64",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "about",
	//   "response": {
	//     "$ref": "About"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.apps.get":

type AppsGetCall struct {
	s     *Service
	appId string
	opt_  map[string]interface{}
	ctx_  context.Context
}

// Get: Gets a specific app.
func (r *AppsService) Get(appId string) *AppsGetCall {
	c := &AppsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.appId = appId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AppsGetCall) Fields(s ...googleapi.Field) *AppsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AppsGetCall) IfNoneMatch(entityTag string) *AppsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AppsGetCall) Context(ctx context.Context) *AppsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *AppsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "apps/{appId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"appId": c.appId,
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

// Do executes the "drive.apps.get" call.
// Exactly one of *App or error will be non-nil. Any non-2xx status code
// is an error. Response headers are in either
// *App.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *AppsGetCall) Do() (*App, error) {
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
	ret := &App{
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
	//   "description": "Gets a specific app.",
	//   "httpMethod": "GET",
	//   "id": "drive.apps.get",
	//   "parameterOrder": [
	//     "appId"
	//   ],
	//   "parameters": {
	//     "appId": {
	//       "description": "The ID of the app.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "apps/{appId}",
	//   "response": {
	//     "$ref": "App"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.apps.list":

type AppsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Lists a user's installed apps.
func (r *AppsService) List() *AppsListCall {
	c := &AppsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// AppFilterExtensions sets the optional parameter
// "appFilterExtensions": A comma-separated list of file extensions for
// open with filtering. All apps within the given app query scope which
// can open any of the given file extensions will be included in the
// response. If appFilterMimeTypes are provided as well, the result is a
// union of the two resulting app lists.
func (c *AppsListCall) AppFilterExtensions(appFilterExtensions string) *AppsListCall {
	c.opt_["appFilterExtensions"] = appFilterExtensions
	return c
}

// AppFilterMimeTypes sets the optional parameter "appFilterMimeTypes":
// A comma-separated list of MIME types for open with filtering. All
// apps within the given app query scope which can open any of the given
// MIME types will be included in the response. If appFilterExtensions
// are provided as well, the result is a union of the two resulting app
// lists.
func (c *AppsListCall) AppFilterMimeTypes(appFilterMimeTypes string) *AppsListCall {
	c.opt_["appFilterMimeTypes"] = appFilterMimeTypes
	return c
}

// LanguageCode sets the optional parameter "languageCode": A language
// or locale code, as defined by BCP 47, with some extensions from
// Unicode's LDML format (http://www.unicode.org/reports/tr35/).
func (c *AppsListCall) LanguageCode(languageCode string) *AppsListCall {
	c.opt_["languageCode"] = languageCode
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AppsListCall) Fields(s ...googleapi.Field) *AppsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AppsListCall) IfNoneMatch(entityTag string) *AppsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AppsListCall) Context(ctx context.Context) *AppsListCall {
	c.ctx_ = ctx
	return c
}

func (c *AppsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["appFilterExtensions"]; ok {
		params.Set("appFilterExtensions", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["appFilterMimeTypes"]; ok {
		params.Set("appFilterMimeTypes", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["languageCode"]; ok {
		params.Set("languageCode", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "apps")
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

// Do executes the "drive.apps.list" call.
// Exactly one of *AppList or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *AppList.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *AppsListCall) Do() (*AppList, error) {
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
	ret := &AppList{
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
	//   "description": "Lists a user's installed apps.",
	//   "httpMethod": "GET",
	//   "id": "drive.apps.list",
	//   "parameters": {
	//     "appFilterExtensions": {
	//       "default": "",
	//       "description": "A comma-separated list of file extensions for open with filtering. All apps within the given app query scope which can open any of the given file extensions will be included in the response. If appFilterMimeTypes are provided as well, the result is a union of the two resulting app lists.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "appFilterMimeTypes": {
	//       "default": "",
	//       "description": "A comma-separated list of MIME types for open with filtering. All apps within the given app query scope which can open any of the given MIME types will be included in the response. If appFilterExtensions are provided as well, the result is a union of the two resulting app lists.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "languageCode": {
	//       "description": "A language or locale code, as defined by BCP 47, with some extensions from Unicode's LDML format (http://www.unicode.org/reports/tr35/).",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "apps",
	//   "response": {
	//     "$ref": "AppList"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive.apps.readonly"
	//   ]
	// }

}

// method id "drive.changes.get":

type ChangesGetCall struct {
	s        *Service
	changeId string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Get: Gets a specific change.
func (r *ChangesService) Get(changeId string) *ChangesGetCall {
	c := &ChangesGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.changeId = changeId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChangesGetCall) Fields(s ...googleapi.Field) *ChangesGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ChangesGetCall) IfNoneMatch(entityTag string) *ChangesGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChangesGetCall) Context(ctx context.Context) *ChangesGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ChangesGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "changes/{changeId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"changeId": c.changeId,
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

// Do executes the "drive.changes.get" call.
// Exactly one of *Change or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Change.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ChangesGetCall) Do() (*Change, error) {
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
	ret := &Change{
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
	//   "description": "Gets a specific change.",
	//   "httpMethod": "GET",
	//   "id": "drive.changes.get",
	//   "parameterOrder": [
	//     "changeId"
	//   ],
	//   "parameters": {
	//     "changeId": {
	//       "description": "The ID of the change.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "changes/{changeId}",
	//   "response": {
	//     "$ref": "Change"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.changes.list":

type ChangesListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Lists the changes for a user.
func (r *ChangesService) List() *ChangesListCall {
	c := &ChangesListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// IncludeDeleted sets the optional parameter "includeDeleted": Whether
// to include deleted items.
func (c *ChangesListCall) IncludeDeleted(includeDeleted bool) *ChangesListCall {
	c.opt_["includeDeleted"] = includeDeleted
	return c
}

// IncludeSubscribed sets the optional parameter "includeSubscribed":
// Whether to include public files the user has opened and shared files.
// When set to false, the list only includes owned files plus any shared
// or public files the user has explicitly added to a folder they own.
func (c *ChangesListCall) IncludeSubscribed(includeSubscribed bool) *ChangesListCall {
	c.opt_["includeSubscribed"] = includeSubscribed
	return c
}

// MaxResults sets the optional parameter "maxResults": Maximum number
// of changes to return.
func (c *ChangesListCall) MaxResults(maxResults int64) *ChangesListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": Page token for
// changes.
func (c *ChangesListCall) PageToken(pageToken string) *ChangesListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Spaces sets the optional parameter "spaces": A comma-separated list
// of spaces to query. Supported values are 'drive', 'appDataFolder' and
// 'photos'.
func (c *ChangesListCall) Spaces(spaces string) *ChangesListCall {
	c.opt_["spaces"] = spaces
	return c
}

// StartChangeId sets the optional parameter "startChangeId": Change ID
// to start listing changes from.
func (c *ChangesListCall) StartChangeId(startChangeId int64) *ChangesListCall {
	c.opt_["startChangeId"] = startChangeId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChangesListCall) Fields(s ...googleapi.Field) *ChangesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ChangesListCall) IfNoneMatch(entityTag string) *ChangesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChangesListCall) Context(ctx context.Context) *ChangesListCall {
	c.ctx_ = ctx
	return c
}

func (c *ChangesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["includeDeleted"]; ok {
		params.Set("includeDeleted", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["includeSubscribed"]; ok {
		params.Set("includeSubscribed", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["spaces"]; ok {
		params.Set("spaces", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["startChangeId"]; ok {
		params.Set("startChangeId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "changes")
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

// Do executes the "drive.changes.list" call.
// Exactly one of *ChangeList or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ChangeList.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ChangesListCall) Do() (*ChangeList, error) {
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
	ret := &ChangeList{
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
	//   "description": "Lists the changes for a user.",
	//   "httpMethod": "GET",
	//   "id": "drive.changes.list",
	//   "parameters": {
	//     "includeDeleted": {
	//       "default": "true",
	//       "description": "Whether to include deleted items.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "includeSubscribed": {
	//       "default": "true",
	//       "description": "Whether to include public files the user has opened and shared files. When set to false, the list only includes owned files plus any shared or public files the user has explicitly added to a folder they own.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "maxResults": {
	//       "default": "100",
	//       "description": "Maximum number of changes to return.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "Page token for changes.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "spaces": {
	//       "description": "A comma-separated list of spaces to query. Supported values are 'drive', 'appDataFolder' and 'photos'.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "startChangeId": {
	//       "description": "Change ID to start listing changes from.",
	//       "format": "int64",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "changes",
	//   "response": {
	//     "$ref": "ChangeList"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ],
	//   "supportsSubscription": true
	// }

}

// method id "drive.changes.watch":

type ChangesWatchCall struct {
	s       *Service
	channel *Channel
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Watch: Subscribe to changes for a user.
func (r *ChangesService) Watch(channel *Channel) *ChangesWatchCall {
	c := &ChangesWatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.channel = channel
	return c
}

// IncludeDeleted sets the optional parameter "includeDeleted": Whether
// to include deleted items.
func (c *ChangesWatchCall) IncludeDeleted(includeDeleted bool) *ChangesWatchCall {
	c.opt_["includeDeleted"] = includeDeleted
	return c
}

// IncludeSubscribed sets the optional parameter "includeSubscribed":
// Whether to include public files the user has opened and shared files.
// When set to false, the list only includes owned files plus any shared
// or public files the user has explicitly added to a folder they own.
func (c *ChangesWatchCall) IncludeSubscribed(includeSubscribed bool) *ChangesWatchCall {
	c.opt_["includeSubscribed"] = includeSubscribed
	return c
}

// MaxResults sets the optional parameter "maxResults": Maximum number
// of changes to return.
func (c *ChangesWatchCall) MaxResults(maxResults int64) *ChangesWatchCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": Page token for
// changes.
func (c *ChangesWatchCall) PageToken(pageToken string) *ChangesWatchCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Spaces sets the optional parameter "spaces": A comma-separated list
// of spaces to query. Supported values are 'drive', 'appDataFolder' and
// 'photos'.
func (c *ChangesWatchCall) Spaces(spaces string) *ChangesWatchCall {
	c.opt_["spaces"] = spaces
	return c
}

// StartChangeId sets the optional parameter "startChangeId": Change ID
// to start listing changes from.
func (c *ChangesWatchCall) StartChangeId(startChangeId int64) *ChangesWatchCall {
	c.opt_["startChangeId"] = startChangeId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChangesWatchCall) Fields(s ...googleapi.Field) *ChangesWatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChangesWatchCall) Context(ctx context.Context) *ChangesWatchCall {
	c.ctx_ = ctx
	return c
}

func (c *ChangesWatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.channel)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["includeDeleted"]; ok {
		params.Set("includeDeleted", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["includeSubscribed"]; ok {
		params.Set("includeSubscribed", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["spaces"]; ok {
		params.Set("spaces", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["startChangeId"]; ok {
		params.Set("startChangeId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "changes/watch")
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

// Do executes the "drive.changes.watch" call.
// Exactly one of *Channel or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Channel.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ChangesWatchCall) Do() (*Channel, error) {
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
	ret := &Channel{
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
	//   "description": "Subscribe to changes for a user.",
	//   "httpMethod": "POST",
	//   "id": "drive.changes.watch",
	//   "parameters": {
	//     "includeDeleted": {
	//       "default": "true",
	//       "description": "Whether to include deleted items.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "includeSubscribed": {
	//       "default": "true",
	//       "description": "Whether to include public files the user has opened and shared files. When set to false, the list only includes owned files plus any shared or public files the user has explicitly added to a folder they own.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "maxResults": {
	//       "default": "100",
	//       "description": "Maximum number of changes to return.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "Page token for changes.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "spaces": {
	//       "description": "A comma-separated list of spaces to query. Supported values are 'drive', 'appDataFolder' and 'photos'.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "startChangeId": {
	//       "description": "Change ID to start listing changes from.",
	//       "format": "int64",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "changes/watch",
	//   "request": {
	//     "$ref": "Channel",
	//     "parameterName": "resource"
	//   },
	//   "response": {
	//     "$ref": "Channel"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ],
	//   "supportsSubscription": true
	// }

}

// method id "drive.channels.stop":

type ChannelsStopCall struct {
	s       *Service
	channel *Channel
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Stop: Stop watching resources through this channel
func (r *ChannelsService) Stop(channel *Channel) *ChannelsStopCall {
	c := &ChannelsStopCall{s: r.s, opt_: make(map[string]interface{})}
	c.channel = channel
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChannelsStopCall) Fields(s ...googleapi.Field) *ChannelsStopCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChannelsStopCall) Context(ctx context.Context) *ChannelsStopCall {
	c.ctx_ = ctx
	return c
}

func (c *ChannelsStopCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.channel)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "channels/stop")
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

// Do executes the "drive.channels.stop" call.
func (c *ChannelsStopCall) Do() error {
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
	//   "description": "Stop watching resources through this channel",
	//   "httpMethod": "POST",
	//   "id": "drive.channels.stop",
	//   "path": "channels/stop",
	//   "request": {
	//     "$ref": "Channel",
	//     "parameterName": "resource"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.children.delete":

type ChildrenDeleteCall struct {
	s        *Service
	folderId string
	childId  string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Delete: Removes a child from a folder.
func (r *ChildrenService) Delete(folderId string, childId string) *ChildrenDeleteCall {
	c := &ChildrenDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.folderId = folderId
	c.childId = childId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChildrenDeleteCall) Fields(s ...googleapi.Field) *ChildrenDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChildrenDeleteCall) Context(ctx context.Context) *ChildrenDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ChildrenDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{folderId}/children/{childId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"folderId": c.folderId,
		"childId":  c.childId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.children.delete" call.
func (c *ChildrenDeleteCall) Do() error {
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
	//   "description": "Removes a child from a folder.",
	//   "httpMethod": "DELETE",
	//   "id": "drive.children.delete",
	//   "parameterOrder": [
	//     "folderId",
	//     "childId"
	//   ],
	//   "parameters": {
	//     "childId": {
	//       "description": "The ID of the child.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "folderId": {
	//       "description": "The ID of the folder.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{folderId}/children/{childId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.children.get":

type ChildrenGetCall struct {
	s        *Service
	folderId string
	childId  string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Get: Gets a specific child reference.
func (r *ChildrenService) Get(folderId string, childId string) *ChildrenGetCall {
	c := &ChildrenGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.folderId = folderId
	c.childId = childId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChildrenGetCall) Fields(s ...googleapi.Field) *ChildrenGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ChildrenGetCall) IfNoneMatch(entityTag string) *ChildrenGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChildrenGetCall) Context(ctx context.Context) *ChildrenGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ChildrenGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{folderId}/children/{childId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"folderId": c.folderId,
		"childId":  c.childId,
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

// Do executes the "drive.children.get" call.
// Exactly one of *ChildReference or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ChildReference.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ChildrenGetCall) Do() (*ChildReference, error) {
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
	ret := &ChildReference{
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
	//   "description": "Gets a specific child reference.",
	//   "httpMethod": "GET",
	//   "id": "drive.children.get",
	//   "parameterOrder": [
	//     "folderId",
	//     "childId"
	//   ],
	//   "parameters": {
	//     "childId": {
	//       "description": "The ID of the child.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "folderId": {
	//       "description": "The ID of the folder.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{folderId}/children/{childId}",
	//   "response": {
	//     "$ref": "ChildReference"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.children.insert":

type ChildrenInsertCall struct {
	s              *Service
	folderId       string
	childreference *ChildReference
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Insert: Inserts a file into a folder.
func (r *ChildrenService) Insert(folderId string, childreference *ChildReference) *ChildrenInsertCall {
	c := &ChildrenInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.folderId = folderId
	c.childreference = childreference
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChildrenInsertCall) Fields(s ...googleapi.Field) *ChildrenInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChildrenInsertCall) Context(ctx context.Context) *ChildrenInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ChildrenInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.childreference)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{folderId}/children")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"folderId": c.folderId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.children.insert" call.
// Exactly one of *ChildReference or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ChildReference.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ChildrenInsertCall) Do() (*ChildReference, error) {
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
	ret := &ChildReference{
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
	//   "description": "Inserts a file into a folder.",
	//   "httpMethod": "POST",
	//   "id": "drive.children.insert",
	//   "parameterOrder": [
	//     "folderId"
	//   ],
	//   "parameters": {
	//     "folderId": {
	//       "description": "The ID of the folder.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{folderId}/children",
	//   "request": {
	//     "$ref": "ChildReference"
	//   },
	//   "response": {
	//     "$ref": "ChildReference"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.children.list":

type ChildrenListCall struct {
	s        *Service
	folderId string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// List: Lists a folder's children.
func (r *ChildrenService) List(folderId string) *ChildrenListCall {
	c := &ChildrenListCall{s: r.s, opt_: make(map[string]interface{})}
	c.folderId = folderId
	return c
}

// MaxResults sets the optional parameter "maxResults": Maximum number
// of children to return.
func (c *ChildrenListCall) MaxResults(maxResults int64) *ChildrenListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// OrderBy sets the optional parameter "orderBy": A comma-separated list
// of sort keys. Valid keys are 'createdDate', 'folder',
// 'lastViewedByMeDate', 'modifiedByMeDate', 'modifiedDate',
// 'quotaBytesUsed', 'recency', 'sharedWithMeDate', 'starred', and
// 'title'. Each key sorts ascending by default, but may be reversed
// with the 'desc' modifier. Example usage: ?orderBy=folder,modifiedDate
// desc,title. Please note that there is a current limitation for users
// with approximately one million files in which the requested sort
// order is ignored.
func (c *ChildrenListCall) OrderBy(orderBy string) *ChildrenListCall {
	c.opt_["orderBy"] = orderBy
	return c
}

// PageToken sets the optional parameter "pageToken": Page token for
// children.
func (c *ChildrenListCall) PageToken(pageToken string) *ChildrenListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Q sets the optional parameter "q": Query string for searching
// children.
func (c *ChildrenListCall) Q(q string) *ChildrenListCall {
	c.opt_["q"] = q
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ChildrenListCall) Fields(s ...googleapi.Field) *ChildrenListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ChildrenListCall) IfNoneMatch(entityTag string) *ChildrenListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ChildrenListCall) Context(ctx context.Context) *ChildrenListCall {
	c.ctx_ = ctx
	return c
}

func (c *ChildrenListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["orderBy"]; ok {
		params.Set("orderBy", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["q"]; ok {
		params.Set("q", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{folderId}/children")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"folderId": c.folderId,
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

// Do executes the "drive.children.list" call.
// Exactly one of *ChildList or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ChildList.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ChildrenListCall) Do() (*ChildList, error) {
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
	ret := &ChildList{
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
	//   "description": "Lists a folder's children.",
	//   "httpMethod": "GET",
	//   "id": "drive.children.list",
	//   "parameterOrder": [
	//     "folderId"
	//   ],
	//   "parameters": {
	//     "folderId": {
	//       "description": "The ID of the folder.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "100",
	//       "description": "Maximum number of children to return.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "orderBy": {
	//       "description": "A comma-separated list of sort keys. Valid keys are 'createdDate', 'folder', 'lastViewedByMeDate', 'modifiedByMeDate', 'modifiedDate', 'quotaBytesUsed', 'recency', 'sharedWithMeDate', 'starred', and 'title'. Each key sorts ascending by default, but may be reversed with the 'desc' modifier. Example usage: ?orderBy=folder,modifiedDate desc,title. Please note that there is a current limitation for users with approximately one million files in which the requested sort order is ignored.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageToken": {
	//       "description": "Page token for children.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "q": {
	//       "description": "Query string for searching children.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{folderId}/children",
	//   "response": {
	//     "$ref": "ChildList"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.comments.delete":

type CommentsDeleteCall struct {
	s         *Service
	fileId    string
	commentId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Delete: Deletes a comment.
func (r *CommentsService) Delete(fileId string, commentId string) *CommentsDeleteCall {
	c := &CommentsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.commentId = commentId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CommentsDeleteCall) Fields(s ...googleapi.Field) *CommentsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CommentsDeleteCall) Context(ctx context.Context) *CommentsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *CommentsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/comments/{commentId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":    c.fileId,
		"commentId": c.commentId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.comments.delete" call.
func (c *CommentsDeleteCall) Do() error {
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
	//   "description": "Deletes a comment.",
	//   "httpMethod": "DELETE",
	//   "id": "drive.comments.delete",
	//   "parameterOrder": [
	//     "fileId",
	//     "commentId"
	//   ],
	//   "parameters": {
	//     "commentId": {
	//       "description": "The ID of the comment.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/comments/{commentId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.comments.get":

type CommentsGetCall struct {
	s         *Service
	fileId    string
	commentId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Gets a comment by ID.
func (r *CommentsService) Get(fileId string, commentId string) *CommentsGetCall {
	c := &CommentsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.commentId = commentId
	return c
}

// IncludeDeleted sets the optional parameter "includeDeleted": If set,
// this will succeed when retrieving a deleted comment, and will include
// any deleted replies.
func (c *CommentsGetCall) IncludeDeleted(includeDeleted bool) *CommentsGetCall {
	c.opt_["includeDeleted"] = includeDeleted
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CommentsGetCall) Fields(s ...googleapi.Field) *CommentsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *CommentsGetCall) IfNoneMatch(entityTag string) *CommentsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CommentsGetCall) Context(ctx context.Context) *CommentsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *CommentsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["includeDeleted"]; ok {
		params.Set("includeDeleted", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/comments/{commentId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":    c.fileId,
		"commentId": c.commentId,
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

// Do executes the "drive.comments.get" call.
// Exactly one of *Comment or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Comment.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CommentsGetCall) Do() (*Comment, error) {
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
	ret := &Comment{
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
	//   "description": "Gets a comment by ID.",
	//   "httpMethod": "GET",
	//   "id": "drive.comments.get",
	//   "parameterOrder": [
	//     "fileId",
	//     "commentId"
	//   ],
	//   "parameters": {
	//     "commentId": {
	//       "description": "The ID of the comment.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "includeDeleted": {
	//       "default": "false",
	//       "description": "If set, this will succeed when retrieving a deleted comment, and will include any deleted replies.",
	//       "location": "query",
	//       "type": "boolean"
	//     }
	//   },
	//   "path": "files/{fileId}/comments/{commentId}",
	//   "response": {
	//     "$ref": "Comment"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.comments.insert":

type CommentsInsertCall struct {
	s       *Service
	fileId  string
	comment *Comment
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Insert: Creates a new comment on the given file.
func (r *CommentsService) Insert(fileId string, comment *Comment) *CommentsInsertCall {
	c := &CommentsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.comment = comment
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CommentsInsertCall) Fields(s ...googleapi.Field) *CommentsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CommentsInsertCall) Context(ctx context.Context) *CommentsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *CommentsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.comment)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/comments")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.comments.insert" call.
// Exactly one of *Comment or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Comment.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CommentsInsertCall) Do() (*Comment, error) {
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
	ret := &Comment{
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
	//   "description": "Creates a new comment on the given file.",
	//   "httpMethod": "POST",
	//   "id": "drive.comments.insert",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/comments",
	//   "request": {
	//     "$ref": "Comment"
	//   },
	//   "response": {
	//     "$ref": "Comment"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.comments.list":

type CommentsListCall struct {
	s      *Service
	fileId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// List: Lists a file's comments.
func (r *CommentsService) List(fileId string) *CommentsListCall {
	c := &CommentsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	return c
}

// IncludeDeleted sets the optional parameter "includeDeleted": If set,
// all comments and replies, including deleted comments and replies
// (with content stripped) will be returned.
func (c *CommentsListCall) IncludeDeleted(includeDeleted bool) *CommentsListCall {
	c.opt_["includeDeleted"] = includeDeleted
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of discussions to include in the response, used for paging.
func (c *CommentsListCall) MaxResults(maxResults int64) *CommentsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The continuation
// token, used to page through large result sets. To get the next page
// of results, set this parameter to the value of "nextPageToken" from
// the previous response.
func (c *CommentsListCall) PageToken(pageToken string) *CommentsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// UpdatedMin sets the optional parameter "updatedMin": Only discussions
// that were updated after this timestamp will be returned. Formatted as
// an RFC 3339 timestamp.
func (c *CommentsListCall) UpdatedMin(updatedMin string) *CommentsListCall {
	c.opt_["updatedMin"] = updatedMin
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CommentsListCall) Fields(s ...googleapi.Field) *CommentsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *CommentsListCall) IfNoneMatch(entityTag string) *CommentsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CommentsListCall) Context(ctx context.Context) *CommentsListCall {
	c.ctx_ = ctx
	return c
}

func (c *CommentsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["includeDeleted"]; ok {
		params.Set("includeDeleted", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["updatedMin"]; ok {
		params.Set("updatedMin", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/comments")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
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

// Do executes the "drive.comments.list" call.
// Exactly one of *CommentList or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CommentList.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *CommentsListCall) Do() (*CommentList, error) {
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
	ret := &CommentList{
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
	//   "description": "Lists a file's comments.",
	//   "httpMethod": "GET",
	//   "id": "drive.comments.list",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "includeDeleted": {
	//       "default": "false",
	//       "description": "If set, all comments and replies, including deleted comments and replies (with content stripped) will be returned.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "maxResults": {
	//       "default": "20",
	//       "description": "The maximum number of discussions to include in the response, used for paging.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The continuation token, used to page through large result sets. To get the next page of results, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "updatedMin": {
	//       "description": "Only discussions that were updated after this timestamp will be returned. Formatted as an RFC 3339 timestamp.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/comments",
	//   "response": {
	//     "$ref": "CommentList"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.comments.patch":

type CommentsPatchCall struct {
	s         *Service
	fileId    string
	commentId string
	comment   *Comment
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Patch: Updates an existing comment. This method supports patch
// semantics.
func (r *CommentsService) Patch(fileId string, commentId string, comment *Comment) *CommentsPatchCall {
	c := &CommentsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.commentId = commentId
	c.comment = comment
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CommentsPatchCall) Fields(s ...googleapi.Field) *CommentsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CommentsPatchCall) Context(ctx context.Context) *CommentsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *CommentsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.comment)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/comments/{commentId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":    c.fileId,
		"commentId": c.commentId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.comments.patch" call.
// Exactly one of *Comment or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Comment.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CommentsPatchCall) Do() (*Comment, error) {
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
	ret := &Comment{
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
	//   "description": "Updates an existing comment. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "drive.comments.patch",
	//   "parameterOrder": [
	//     "fileId",
	//     "commentId"
	//   ],
	//   "parameters": {
	//     "commentId": {
	//       "description": "The ID of the comment.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/comments/{commentId}",
	//   "request": {
	//     "$ref": "Comment"
	//   },
	//   "response": {
	//     "$ref": "Comment"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.comments.update":

type CommentsUpdateCall struct {
	s         *Service
	fileId    string
	commentId string
	comment   *Comment
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Update: Updates an existing comment.
func (r *CommentsService) Update(fileId string, commentId string, comment *Comment) *CommentsUpdateCall {
	c := &CommentsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.commentId = commentId
	c.comment = comment
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CommentsUpdateCall) Fields(s ...googleapi.Field) *CommentsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CommentsUpdateCall) Context(ctx context.Context) *CommentsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *CommentsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.comment)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/comments/{commentId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":    c.fileId,
		"commentId": c.commentId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.comments.update" call.
// Exactly one of *Comment or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Comment.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CommentsUpdateCall) Do() (*Comment, error) {
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
	ret := &Comment{
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
	//   "description": "Updates an existing comment.",
	//   "httpMethod": "PUT",
	//   "id": "drive.comments.update",
	//   "parameterOrder": [
	//     "fileId",
	//     "commentId"
	//   ],
	//   "parameters": {
	//     "commentId": {
	//       "description": "The ID of the comment.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/comments/{commentId}",
	//   "request": {
	//     "$ref": "Comment"
	//   },
	//   "response": {
	//     "$ref": "Comment"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.files.copy":

type FilesCopyCall struct {
	s      *Service
	fileId string
	file   *File
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Copy: Creates a copy of the specified file.
func (r *FilesService) Copy(fileId string, file *File) *FilesCopyCall {
	c := &FilesCopyCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.file = file
	return c
}

// Convert sets the optional parameter "convert": Whether to convert
// this file to the corresponding Google Docs format.
func (c *FilesCopyCall) Convert(convert bool) *FilesCopyCall {
	c.opt_["convert"] = convert
	return c
}

// Ocr sets the optional parameter "ocr": Whether to attempt OCR on
// .jpg, .png, .gif, or .pdf uploads.
func (c *FilesCopyCall) Ocr(ocr bool) *FilesCopyCall {
	c.opt_["ocr"] = ocr
	return c
}

// OcrLanguage sets the optional parameter "ocrLanguage": If ocr is
// true, hints at the language to use. Valid values are BCP 47 codes.
func (c *FilesCopyCall) OcrLanguage(ocrLanguage string) *FilesCopyCall {
	c.opt_["ocrLanguage"] = ocrLanguage
	return c
}

// Pinned sets the optional parameter "pinned": Whether to pin the head
// revision of the new copy. A file can have a maximum of 200 pinned
// revisions.
func (c *FilesCopyCall) Pinned(pinned bool) *FilesCopyCall {
	c.opt_["pinned"] = pinned
	return c
}

// TimedTextLanguage sets the optional parameter "timedTextLanguage":
// The language of the timed text.
func (c *FilesCopyCall) TimedTextLanguage(timedTextLanguage string) *FilesCopyCall {
	c.opt_["timedTextLanguage"] = timedTextLanguage
	return c
}

// TimedTextTrackName sets the optional parameter "timedTextTrackName":
// The timed text track name.
func (c *FilesCopyCall) TimedTextTrackName(timedTextTrackName string) *FilesCopyCall {
	c.opt_["timedTextTrackName"] = timedTextTrackName
	return c
}

// Visibility sets the optional parameter "visibility": The visibility
// of the new file. This parameter is only relevant when the source is
// not a native Google Doc and convert=false.
//
// Possible values:
//   "DEFAULT" (default) - The visibility of the new file is determined
// by the user's default visibility/sharing policies.
//   "PRIVATE" - The new file will be visible to only the owner.
func (c *FilesCopyCall) Visibility(visibility string) *FilesCopyCall {
	c.opt_["visibility"] = visibility
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *FilesCopyCall) Fields(s ...googleapi.Field) *FilesCopyCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *FilesCopyCall) Context(ctx context.Context) *FilesCopyCall {
	c.ctx_ = ctx
	return c
}

func (c *FilesCopyCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.file)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["convert"]; ok {
		params.Set("convert", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["ocr"]; ok {
		params.Set("ocr", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["ocrLanguage"]; ok {
		params.Set("ocrLanguage", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pinned"]; ok {
		params.Set("pinned", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["timedTextLanguage"]; ok {
		params.Set("timedTextLanguage", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["timedTextTrackName"]; ok {
		params.Set("timedTextTrackName", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["visibility"]; ok {
		params.Set("visibility", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/copy")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.files.copy" call.
// Exactly one of *File or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *File.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *FilesCopyCall) Do() (*File, error) {
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
	ret := &File{
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
	//   "description": "Creates a copy of the specified file.",
	//   "httpMethod": "POST",
	//   "id": "drive.files.copy",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "convert": {
	//       "default": "false",
	//       "description": "Whether to convert this file to the corresponding Google Docs format.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file to copy.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "ocr": {
	//       "default": "false",
	//       "description": "Whether to attempt OCR on .jpg, .png, .gif, or .pdf uploads.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "ocrLanguage": {
	//       "description": "If ocr is true, hints at the language to use. Valid values are BCP 47 codes.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pinned": {
	//       "default": "false",
	//       "description": "Whether to pin the head revision of the new copy. A file can have a maximum of 200 pinned revisions.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "timedTextLanguage": {
	//       "description": "The language of the timed text.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "timedTextTrackName": {
	//       "description": "The timed text track name.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "visibility": {
	//       "default": "DEFAULT",
	//       "description": "The visibility of the new file. This parameter is only relevant when the source is not a native Google Doc and convert=false.",
	//       "enum": [
	//         "DEFAULT",
	//         "PRIVATE"
	//       ],
	//       "enumDescriptions": [
	//         "The visibility of the new file is determined by the user's default visibility/sharing policies.",
	//         "The new file will be visible to only the owner."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/copy",
	//   "request": {
	//     "$ref": "File"
	//   },
	//   "response": {
	//     "$ref": "File"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.photos.readonly"
	//   ]
	// }

}

// method id "drive.files.delete":

type FilesDeleteCall struct {
	s      *Service
	fileId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Delete: Permanently deletes a file by ID. Skips the trash. The
// currently authenticated user must own the file.
func (r *FilesService) Delete(fileId string) *FilesDeleteCall {
	c := &FilesDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *FilesDeleteCall) Fields(s ...googleapi.Field) *FilesDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *FilesDeleteCall) Context(ctx context.Context) *FilesDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *FilesDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.files.delete" call.
func (c *FilesDeleteCall) Do() error {
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
	//   "description": "Permanently deletes a file by ID. Skips the trash. The currently authenticated user must own the file.",
	//   "httpMethod": "DELETE",
	//   "id": "drive.files.delete",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file to delete.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.files.emptyTrash":

type FilesEmptyTrashCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// EmptyTrash: Permanently deletes all of the user's trashed files.
func (r *FilesService) EmptyTrash() *FilesEmptyTrashCall {
	c := &FilesEmptyTrashCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *FilesEmptyTrashCall) Fields(s ...googleapi.Field) *FilesEmptyTrashCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *FilesEmptyTrashCall) Context(ctx context.Context) *FilesEmptyTrashCall {
	c.ctx_ = ctx
	return c
}

func (c *FilesEmptyTrashCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/trash")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.files.emptyTrash" call.
func (c *FilesEmptyTrashCall) Do() error {
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
	//   "description": "Permanently deletes all of the user's trashed files.",
	//   "httpMethod": "DELETE",
	//   "id": "drive.files.emptyTrash",
	//   "path": "files/trash",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive"
	//   ]
	// }

}

// method id "drive.files.generateIds":

type FilesGenerateIdsCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// GenerateIds: Generates a set of file IDs which can be provided in
// insert requests.
func (r *FilesService) GenerateIds() *FilesGenerateIdsCall {
	c := &FilesGenerateIdsCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// MaxResults sets the optional parameter "maxResults": Maximum number
// of IDs to return.
func (c *FilesGenerateIdsCall) MaxResults(maxResults int64) *FilesGenerateIdsCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// Space sets the optional parameter "space": The space in which the IDs
// can be used to create new files. Supported values are 'drive' and
// 'appDataFolder'.
func (c *FilesGenerateIdsCall) Space(space string) *FilesGenerateIdsCall {
	c.opt_["space"] = space
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *FilesGenerateIdsCall) Fields(s ...googleapi.Field) *FilesGenerateIdsCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *FilesGenerateIdsCall) IfNoneMatch(entityTag string) *FilesGenerateIdsCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *FilesGenerateIdsCall) Context(ctx context.Context) *FilesGenerateIdsCall {
	c.ctx_ = ctx
	return c
}

func (c *FilesGenerateIdsCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["space"]; ok {
		params.Set("space", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/generateIds")
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

// Do executes the "drive.files.generateIds" call.
// Exactly one of *GeneratedIds or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *GeneratedIds.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *FilesGenerateIdsCall) Do() (*GeneratedIds, error) {
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
	ret := &GeneratedIds{
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
	//   "description": "Generates a set of file IDs which can be provided in insert requests.",
	//   "httpMethod": "GET",
	//   "id": "drive.files.generateIds",
	//   "parameters": {
	//     "maxResults": {
	//       "default": "10",
	//       "description": "Maximum number of IDs to return.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "1000",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "space": {
	//       "default": "drive",
	//       "description": "The space in which the IDs can be used to create new files. Supported values are 'drive' and 'appDataFolder'.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/generateIds",
	//   "response": {
	//     "$ref": "GeneratedIds"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.files.get":

type FilesGetCall struct {
	s      *Service
	fileId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Get: Gets a file's metadata by ID.
func (r *FilesService) Get(fileId string) *FilesGetCall {
	c := &FilesGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	return c
}

// AcknowledgeAbuse sets the optional parameter "acknowledgeAbuse":
// Whether the user is acknowledging the risk of downloading known
// malware or other abusive files.
func (c *FilesGetCall) AcknowledgeAbuse(acknowledgeAbuse bool) *FilesGetCall {
	c.opt_["acknowledgeAbuse"] = acknowledgeAbuse
	return c
}

// Projection sets the optional parameter "projection": This parameter
// is deprecated and has no function.
//
// Possible values:
//   "BASIC" - Deprecated
//   "FULL" - Deprecated
func (c *FilesGetCall) Projection(projection string) *FilesGetCall {
	c.opt_["projection"] = projection
	return c
}

// RevisionId sets the optional parameter "revisionId": Specifies the
// Revision ID that should be downloaded. Ignored unless alt=media is
// specified.
func (c *FilesGetCall) RevisionId(revisionId string) *FilesGetCall {
	c.opt_["revisionId"] = revisionId
	return c
}

// UpdateViewedDate sets the optional parameter "updateViewedDate":
// Deprecated: Use files.update with modifiedDateBehavior=noChange,
// updateViewedDate=true and an empty request body.
func (c *FilesGetCall) UpdateViewedDate(updateViewedDate bool) *FilesGetCall {
	c.opt_["updateViewedDate"] = updateViewedDate
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *FilesGetCall) Fields(s ...googleapi.Field) *FilesGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *FilesGetCall) IfNoneMatch(entityTag string) *FilesGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do and Download methods.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *FilesGetCall) Context(ctx context.Context) *FilesGetCall {
	c.ctx_ = ctx
	return c
}

func (c *FilesGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["acknowledgeAbuse"]; ok {
		params.Set("acknowledgeAbuse", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["projection"]; ok {
		params.Set("projection", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["revisionId"]; ok {
		params.Set("revisionId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["updateViewedDate"]; ok {
		params.Set("updateViewedDate", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
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

// Download fetches the API endpoint's "media" value, instead of the normal
// API response value. If the returned error is nil, the Response is guaranteed to
// have a 2xx status code. Callers must close the Response.Body as usual.
func (c *FilesGetCall) Download() (*http.Response, error) {
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

// Do executes the "drive.files.get" call.
// Exactly one of *File or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *File.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *FilesGetCall) Do() (*File, error) {
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
	ret := &File{
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
	//   "description": "Gets a file's metadata by ID.",
	//   "httpMethod": "GET",
	//   "id": "drive.files.get",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "acknowledgeAbuse": {
	//       "default": "false",
	//       "description": "Whether the user is acknowledging the risk of downloading known malware or other abusive files.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "fileId": {
	//       "description": "The ID for the file in question.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "projection": {
	//       "description": "This parameter is deprecated and has no function.",
	//       "enum": [
	//         "BASIC",
	//         "FULL"
	//       ],
	//       "enumDescriptions": [
	//         "Deprecated",
	//         "Deprecated"
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "revisionId": {
	//       "description": "Specifies the Revision ID that should be downloaded. Ignored unless alt=media is specified.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "updateViewedDate": {
	//       "default": "false",
	//       "description": "Deprecated: Use files.update with modifiedDateBehavior=noChange, updateViewedDate=true and an empty request body.",
	//       "location": "query",
	//       "type": "boolean"
	//     }
	//   },
	//   "path": "files/{fileId}",
	//   "response": {
	//     "$ref": "File"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ],
	//   "supportsMediaDownload": true,
	//   "supportsSubscription": true
	// }

}

// method id "drive.files.insert":

type FilesInsertCall struct {
	s          *Service
	file       *File
	opt_       map[string]interface{}
	media_     io.Reader
	resumable_ googleapi.SizeReaderAt
	mediaType_ string
	protocol_  string
	ctx_       context.Context
}

// Insert: Insert a new file.
func (r *FilesService) Insert(file *File) *FilesInsertCall {
	c := &FilesInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.file = file
	return c
}

// Convert sets the optional parameter "convert": Whether to convert
// this file to the corresponding Google Docs format.
func (c *FilesInsertCall) Convert(convert bool) *FilesInsertCall {
	c.opt_["convert"] = convert
	return c
}

// Ocr sets the optional parameter "ocr": Whether to attempt OCR on
// .jpg, .png, .gif, or .pdf uploads.
func (c *FilesInsertCall) Ocr(ocr bool) *FilesInsertCall {
	c.opt_["ocr"] = ocr
	return c
}

// OcrLanguage sets the optional parameter "ocrLanguage": If ocr is
// true, hints at the language to use. Valid values are BCP 47 codes.
func (c *FilesInsertCall) OcrLanguage(ocrLanguage string) *FilesInsertCall {
	c.opt_["ocrLanguage"] = ocrLanguage
	return c
}

// Pinned sets the optional parameter "pinned": Whether to pin the head
// revision of the uploaded file. A file can have a maximum of 200
// pinned revisions.
func (c *FilesInsertCall) Pinned(pinned bool) *FilesInsertCall {
	c.opt_["pinned"] = pinned
	return c
}

// TimedTextLanguage sets the optional parameter "timedTextLanguage":
// The language of the timed text.
func (c *FilesInsertCall) TimedTextLanguage(timedTextLanguage string) *FilesInsertCall {
	c.opt_["timedTextLanguage"] = timedTextLanguage
	return c
}

// TimedTextTrackName sets the optional parameter "timedTextTrackName":
// The timed text track name.
func (c *FilesInsertCall) TimedTextTrackName(timedTextTrackName string) *FilesInsertCall {
	c.opt_["timedTextTrackName"] = timedTextTrackName
	return c
}

// UseContentAsIndexableText sets the optional parameter
// "useContentAsIndexableText": Whether to use the content as indexable
// text.
func (c *FilesInsertCall) UseContentAsIndexableText(useContentAsIndexableText bool) *FilesInsertCall {
	c.opt_["useContentAsIndexableText"] = useContentAsIndexableText
	return c
}

// Visibility sets the optional parameter "visibility": The visibility
// of the new file. This parameter is only relevant when convert=false.
//
// Possible values:
//   "DEFAULT" (default) - The visibility of the new file is determined
// by the user's default visibility/sharing policies.
//   "PRIVATE" - The new file will be visible to only the owner.
func (c *FilesInsertCall) Visibility(visibility string) *FilesInsertCall {
	c.opt_["visibility"] = visibility
	return c
}

// Media specifies the media to upload in a single chunk.
// At most one of Media and ResumableMedia may be set.
func (c *FilesInsertCall) Media(r io.Reader) *FilesInsertCall {
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
func (c *FilesInsertCall) ResumableMedia(ctx context.Context, r io.ReaderAt, size int64, mediaType string) *FilesInsertCall {
	c.ctx_ = ctx
	c.resumable_ = io.NewSectionReader(r, 0, size)
	c.mediaType_ = mediaType
	c.protocol_ = "resumable"
	return c
}

// ProgressUpdater provides a callback function that will be called after every chunk.
// It should be a low-latency function in order to not slow down the upload operation.
// This should only be called when using ResumableMedia (as opposed to Media).
func (c *FilesInsertCall) ProgressUpdater(pu googleapi.ProgressUpdater) *FilesInsertCall {
	c.opt_["progressUpdater"] = pu
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *FilesInsertCall) Fields(s ...googleapi.Field) *FilesInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
// This context will supersede any context previously provided to
// the ResumableMedia method.
func (c *FilesInsertCall) Context(ctx context.Context) *FilesInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *FilesInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.file)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["convert"]; ok {
		params.Set("convert", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["ocr"]; ok {
		params.Set("ocr", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["ocrLanguage"]; ok {
		params.Set("ocrLanguage", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pinned"]; ok {
		params.Set("pinned", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["timedTextLanguage"]; ok {
		params.Set("timedTextLanguage", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["timedTextTrackName"]; ok {
		params.Set("timedTextTrackName", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["useContentAsIndexableText"]; ok {
		params.Set("useContentAsIndexableText", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["visibility"]; ok {
		params.Set("visibility", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files")
	if c.media_ != nil || c.resumable_ != nil {
		urls = strings.Replace(urls, "https://www.googleapis.com/", "https://www.googleapis.com/upload/", 1)
		params.Set("uploadType", c.protocol_)
	}
	urls += "?" + params.Encode()
	if c.protocol_ != "resumable" {
		var cancel func()
		cancel, _ = googleapi.ConditionallyIncludeMedia(c.media_, &body, &ctype)
		if cancel != nil {
			defer cancel()
		}
	}
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
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

// Do executes the "drive.files.insert" call.
// Exactly one of *File or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *File.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *FilesInsertCall) Do() (*File, error) {
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
	ret := &File{
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
	//   "description": "Insert a new file.",
	//   "httpMethod": "POST",
	//   "id": "drive.files.insert",
	//   "mediaUpload": {
	//     "accept": [
	//       "*/*"
	//     ],
	//     "maxSize": "5120GB",
	//     "protocols": {
	//       "resumable": {
	//         "multipart": true,
	//         "path": "/resumable/upload/drive/v2/files"
	//       },
	//       "simple": {
	//         "multipart": true,
	//         "path": "/upload/drive/v2/files"
	//       }
	//     }
	//   },
	//   "parameters": {
	//     "convert": {
	//       "default": "false",
	//       "description": "Whether to convert this file to the corresponding Google Docs format.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "ocr": {
	//       "default": "false",
	//       "description": "Whether to attempt OCR on .jpg, .png, .gif, or .pdf uploads.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "ocrLanguage": {
	//       "description": "If ocr is true, hints at the language to use. Valid values are BCP 47 codes.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pinned": {
	//       "default": "false",
	//       "description": "Whether to pin the head revision of the uploaded file. A file can have a maximum of 200 pinned revisions.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "timedTextLanguage": {
	//       "description": "The language of the timed text.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "timedTextTrackName": {
	//       "description": "The timed text track name.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "useContentAsIndexableText": {
	//       "default": "false",
	//       "description": "Whether to use the content as indexable text.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "visibility": {
	//       "default": "DEFAULT",
	//       "description": "The visibility of the new file. This parameter is only relevant when convert=false.",
	//       "enum": [
	//         "DEFAULT",
	//         "PRIVATE"
	//       ],
	//       "enumDescriptions": [
	//         "The visibility of the new file is determined by the user's default visibility/sharing policies.",
	//         "The new file will be visible to only the owner."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "files",
	//   "request": {
	//     "$ref": "File"
	//   },
	//   "response": {
	//     "$ref": "File"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ],
	//   "supportsMediaUpload": true,
	//   "supportsSubscription": true
	// }

}

// method id "drive.files.list":

type FilesListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Lists the user's files.
func (r *FilesService) List() *FilesListCall {
	c := &FilesListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// Corpus sets the optional parameter "corpus": The body of items
// (files/documents) to which the query applies.
//
// Possible values:
//   "DEFAULT" - The items that the user has accessed.
//   "DOMAIN" - Items shared to the user's domain.
func (c *FilesListCall) Corpus(corpus string) *FilesListCall {
	c.opt_["corpus"] = corpus
	return c
}

// MaxResults sets the optional parameter "maxResults": Maximum number
// of files to return.
func (c *FilesListCall) MaxResults(maxResults int64) *FilesListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// OrderBy sets the optional parameter "orderBy": A comma-separated list
// of sort keys. Valid keys are 'createdDate', 'folder',
// 'lastViewedByMeDate', 'modifiedByMeDate', 'modifiedDate',
// 'quotaBytesUsed', 'recency', 'sharedWithMeDate', 'starred', and
// 'title'. Each key sorts ascending by default, but may be reversed
// with the 'desc' modifier. Example usage: ?orderBy=folder,modifiedDate
// desc,title. Please note that there is a current limitation for users
// with approximately one million files in which the requested sort
// order is ignored.
func (c *FilesListCall) OrderBy(orderBy string) *FilesListCall {
	c.opt_["orderBy"] = orderBy
	return c
}

// PageToken sets the optional parameter "pageToken": Page token for
// files.
func (c *FilesListCall) PageToken(pageToken string) *FilesListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Projection sets the optional parameter "projection": This parameter
// is deprecated and has no function.
//
// Possible values:
//   "BASIC" - Deprecated
//   "FULL" - Deprecated
func (c *FilesListCall) Projection(projection string) *FilesListCall {
	c.opt_["projection"] = projection
	return c
}

// Q sets the optional parameter "q": Query string for searching files.
func (c *FilesListCall) Q(q string) *FilesListCall {
	c.opt_["q"] = q
	return c
}

// Spaces sets the optional parameter "spaces": A comma-separated list
// of spaces to query. Supported values are 'drive', 'appDataFolder' and
// 'photos'.
func (c *FilesListCall) Spaces(spaces string) *FilesListCall {
	c.opt_["spaces"] = spaces
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *FilesListCall) Fields(s ...googleapi.Field) *FilesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *FilesListCall) IfNoneMatch(entityTag string) *FilesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *FilesListCall) Context(ctx context.Context) *FilesListCall {
	c.ctx_ = ctx
	return c
}

func (c *FilesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["corpus"]; ok {
		params.Set("corpus", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["orderBy"]; ok {
		params.Set("orderBy", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["projection"]; ok {
		params.Set("projection", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["q"]; ok {
		params.Set("q", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["spaces"]; ok {
		params.Set("spaces", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files")
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

// Do executes the "drive.files.list" call.
// Exactly one of *FileList or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *FileList.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *FilesListCall) Do() (*FileList, error) {
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
	ret := &FileList{
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
	//   "description": "Lists the user's files.",
	//   "httpMethod": "GET",
	//   "id": "drive.files.list",
	//   "parameters": {
	//     "corpus": {
	//       "description": "The body of items (files/documents) to which the query applies.",
	//       "enum": [
	//         "DEFAULT",
	//         "DOMAIN"
	//       ],
	//       "enumDescriptions": [
	//         "The items that the user has accessed.",
	//         "Items shared to the user's domain."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "100",
	//       "description": "Maximum number of files to return.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "orderBy": {
	//       "description": "A comma-separated list of sort keys. Valid keys are 'createdDate', 'folder', 'lastViewedByMeDate', 'modifiedByMeDate', 'modifiedDate', 'quotaBytesUsed', 'recency', 'sharedWithMeDate', 'starred', and 'title'. Each key sorts ascending by default, but may be reversed with the 'desc' modifier. Example usage: ?orderBy=folder,modifiedDate desc,title. Please note that there is a current limitation for users with approximately one million files in which the requested sort order is ignored.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageToken": {
	//       "description": "Page token for files.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "projection": {
	//       "description": "This parameter is deprecated and has no function.",
	//       "enum": [
	//         "BASIC",
	//         "FULL"
	//       ],
	//       "enumDescriptions": [
	//         "Deprecated",
	//         "Deprecated"
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "q": {
	//       "description": "Query string for searching files.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "spaces": {
	//       "description": "A comma-separated list of spaces to query. Supported values are 'drive', 'appDataFolder' and 'photos'.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "files",
	//   "response": {
	//     "$ref": "FileList"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.files.patch":

type FilesPatchCall struct {
	s      *Service
	fileId string
	file   *File
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Patch: Updates file metadata and/or content. This method supports
// patch semantics.
func (r *FilesService) Patch(fileId string, file *File) *FilesPatchCall {
	c := &FilesPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.file = file
	return c
}

// AddParents sets the optional parameter "addParents": Comma-separated
// list of parent IDs to add.
func (c *FilesPatchCall) AddParents(addParents string) *FilesPatchCall {
	c.opt_["addParents"] = addParents
	return c
}

// Convert sets the optional parameter "convert": This parameter is
// deprecated and has no function.
func (c *FilesPatchCall) Convert(convert bool) *FilesPatchCall {
	c.opt_["convert"] = convert
	return c
}

// ModifiedDateBehavior sets the optional parameter
// "modifiedDateBehavior": Determines the behavior in which modifiedDate
// is updated. This overrides setModifiedDate.
//
// Possible values:
//   "fromBody" - Set modifiedDate to the value provided in the body of
// the request. No change if no value was provided.
//   "fromBodyIfNeeded" - Set modifiedDate to the value provided in the
// body of the request depending on other contents of the update.
//   "fromBodyOrNow" - Set modifiedDate to the value provided in the
// body of the request, or to the current time if no value was provided.
//   "noChange" - Maintain the previous value of modifiedDate.
//   "now" - Set modifiedDate to the current time.
//   "nowIfNeeded" - Set modifiedDate to the current time depending on
// contents of the update.
func (c *FilesPatchCall) ModifiedDateBehavior(modifiedDateBehavior string) *FilesPatchCall {
	c.opt_["modifiedDateBehavior"] = modifiedDateBehavior
	return c
}

// NewRevision sets the optional parameter "newRevision": Whether a blob
// upload should create a new revision. If false, the blob data in the
// current head revision is replaced. If true or not set, a new blob is
// created as head revision, and previous unpinned revisions are
// preserved for a short period of time. Pinned revisions are stored
// indefinitely, using additional storage quota, up to a maximum of 200
// revisions. For details on how revisions are retained, see the Drive
// Help Center.
func (c *FilesPatchCall) NewRevision(newRevision bool) *FilesPatchCall {
	c.opt_["newRevision"] = newRevision
	return c
}

// Ocr sets the optional parameter "ocr": Whether to attempt OCR on
// .jpg, .png, .gif, or .pdf uploads.
func (c *FilesPatchCall) Ocr(ocr bool) *FilesPatchCall {
	c.opt_["ocr"] = ocr
	return c
}

// OcrLanguage sets the optional parameter "ocrLanguage": If ocr is
// true, hints at the language to use. Valid values are BCP 47 codes.
func (c *FilesPatchCall) OcrLanguage(ocrLanguage string) *FilesPatchCall {
	c.opt_["ocrLanguage"] = ocrLanguage
	return c
}

// Pinned sets the optional parameter "pinned": Whether to pin the new
// revision. A file can have a maximum of 200 pinned revisions.
func (c *FilesPatchCall) Pinned(pinned bool) *FilesPatchCall {
	c.opt_["pinned"] = pinned
	return c
}

// RemoveParents sets the optional parameter "removeParents":
// Comma-separated list of parent IDs to remove.
func (c *FilesPatchCall) RemoveParents(removeParents string) *FilesPatchCall {
	c.opt_["removeParents"] = removeParents
	return c
}

// SetModifiedDate sets the optional parameter "setModifiedDate":
// Whether to set the modified date with the supplied modified date.
func (c *FilesPatchCall) SetModifiedDate(setModifiedDate bool) *FilesPatchCall {
	c.opt_["setModifiedDate"] = setModifiedDate
	return c
}

// TimedTextLanguage sets the optional parameter "timedTextLanguage":
// The language of the timed text.
func (c *FilesPatchCall) TimedTextLanguage(timedTextLanguage string) *FilesPatchCall {
	c.opt_["timedTextLanguage"] = timedTextLanguage
	return c
}

// TimedTextTrackName sets the optional parameter "timedTextTrackName":
// The timed text track name.
func (c *FilesPatchCall) TimedTextTrackName(timedTextTrackName string) *FilesPatchCall {
	c.opt_["timedTextTrackName"] = timedTextTrackName
	return c
}

// UpdateViewedDate sets the optional parameter "updateViewedDate":
// Whether to update the view date after successfully updating the file.
func (c *FilesPatchCall) UpdateViewedDate(updateViewedDate bool) *FilesPatchCall {
	c.opt_["updateViewedDate"] = updateViewedDate
	return c
}

// UseContentAsIndexableText sets the optional parameter
// "useContentAsIndexableText": Whether to use the content as indexable
// text.
func (c *FilesPatchCall) UseContentAsIndexableText(useContentAsIndexableText bool) *FilesPatchCall {
	c.opt_["useContentAsIndexableText"] = useContentAsIndexableText
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *FilesPatchCall) Fields(s ...googleapi.Field) *FilesPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *FilesPatchCall) Context(ctx context.Context) *FilesPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *FilesPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.file)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["addParents"]; ok {
		params.Set("addParents", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["convert"]; ok {
		params.Set("convert", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["modifiedDateBehavior"]; ok {
		params.Set("modifiedDateBehavior", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["newRevision"]; ok {
		params.Set("newRevision", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["ocr"]; ok {
		params.Set("ocr", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["ocrLanguage"]; ok {
		params.Set("ocrLanguage", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pinned"]; ok {
		params.Set("pinned", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["removeParents"]; ok {
		params.Set("removeParents", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["setModifiedDate"]; ok {
		params.Set("setModifiedDate", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["timedTextLanguage"]; ok {
		params.Set("timedTextLanguage", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["timedTextTrackName"]; ok {
		params.Set("timedTextTrackName", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["updateViewedDate"]; ok {
		params.Set("updateViewedDate", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["useContentAsIndexableText"]; ok {
		params.Set("useContentAsIndexableText", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.files.patch" call.
// Exactly one of *File or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *File.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *FilesPatchCall) Do() (*File, error) {
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
	ret := &File{
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
	//   "description": "Updates file metadata and/or content. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "drive.files.patch",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "addParents": {
	//       "description": "Comma-separated list of parent IDs to add.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "convert": {
	//       "default": "false",
	//       "description": "This parameter is deprecated and has no function.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "modifiedDateBehavior": {
	//       "description": "Determines the behavior in which modifiedDate is updated. This overrides setModifiedDate.",
	//       "enum": [
	//         "fromBody",
	//         "fromBodyIfNeeded",
	//         "fromBodyOrNow",
	//         "noChange",
	//         "now",
	//         "nowIfNeeded"
	//       ],
	//       "enumDescriptions": [
	//         "Set modifiedDate to the value provided in the body of the request. No change if no value was provided.",
	//         "Set modifiedDate to the value provided in the body of the request depending on other contents of the update.",
	//         "Set modifiedDate to the value provided in the body of the request, or to the current time if no value was provided.",
	//         "Maintain the previous value of modifiedDate.",
	//         "Set modifiedDate to the current time.",
	//         "Set modifiedDate to the current time depending on contents of the update."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "newRevision": {
	//       "default": "true",
	//       "description": "Whether a blob upload should create a new revision. If false, the blob data in the current head revision is replaced. If true or not set, a new blob is created as head revision, and previous unpinned revisions are preserved for a short period of time. Pinned revisions are stored indefinitely, using additional storage quota, up to a maximum of 200 revisions. For details on how revisions are retained, see the Drive Help Center.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "ocr": {
	//       "default": "false",
	//       "description": "Whether to attempt OCR on .jpg, .png, .gif, or .pdf uploads.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "ocrLanguage": {
	//       "description": "If ocr is true, hints at the language to use. Valid values are BCP 47 codes.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pinned": {
	//       "default": "false",
	//       "description": "Whether to pin the new revision. A file can have a maximum of 200 pinned revisions.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "removeParents": {
	//       "description": "Comma-separated list of parent IDs to remove.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "setModifiedDate": {
	//       "default": "false",
	//       "description": "Whether to set the modified date with the supplied modified date.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "timedTextLanguage": {
	//       "description": "The language of the timed text.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "timedTextTrackName": {
	//       "description": "The timed text track name.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "updateViewedDate": {
	//       "default": "true",
	//       "description": "Whether to update the view date after successfully updating the file.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "useContentAsIndexableText": {
	//       "default": "false",
	//       "description": "Whether to use the content as indexable text.",
	//       "location": "query",
	//       "type": "boolean"
	//     }
	//   },
	//   "path": "files/{fileId}",
	//   "request": {
	//     "$ref": "File"
	//   },
	//   "response": {
	//     "$ref": "File"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.scripts"
	//   ]
	// }

}

// method id "drive.files.touch":

type FilesTouchCall struct {
	s      *Service
	fileId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Touch: Set the file's updated time to the current server time.
func (r *FilesService) Touch(fileId string) *FilesTouchCall {
	c := &FilesTouchCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *FilesTouchCall) Fields(s ...googleapi.Field) *FilesTouchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *FilesTouchCall) Context(ctx context.Context) *FilesTouchCall {
	c.ctx_ = ctx
	return c
}

func (c *FilesTouchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/touch")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.files.touch" call.
// Exactly one of *File or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *File.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *FilesTouchCall) Do() (*File, error) {
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
	ret := &File{
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
	//   "description": "Set the file's updated time to the current server time.",
	//   "httpMethod": "POST",
	//   "id": "drive.files.touch",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/touch",
	//   "response": {
	//     "$ref": "File"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata"
	//   ]
	// }

}

// method id "drive.files.trash":

type FilesTrashCall struct {
	s      *Service
	fileId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Trash: Moves a file to the trash. The currently authenticated user
// must own the file.
func (r *FilesService) Trash(fileId string) *FilesTrashCall {
	c := &FilesTrashCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *FilesTrashCall) Fields(s ...googleapi.Field) *FilesTrashCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *FilesTrashCall) Context(ctx context.Context) *FilesTrashCall {
	c.ctx_ = ctx
	return c
}

func (c *FilesTrashCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/trash")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.files.trash" call.
// Exactly one of *File or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *File.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *FilesTrashCall) Do() (*File, error) {
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
	ret := &File{
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
	//   "description": "Moves a file to the trash. The currently authenticated user must own the file.",
	//   "httpMethod": "POST",
	//   "id": "drive.files.trash",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file to trash.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/trash",
	//   "response": {
	//     "$ref": "File"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.files.untrash":

type FilesUntrashCall struct {
	s      *Service
	fileId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Untrash: Restores a file from the trash.
func (r *FilesService) Untrash(fileId string) *FilesUntrashCall {
	c := &FilesUntrashCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *FilesUntrashCall) Fields(s ...googleapi.Field) *FilesUntrashCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *FilesUntrashCall) Context(ctx context.Context) *FilesUntrashCall {
	c.ctx_ = ctx
	return c
}

func (c *FilesUntrashCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/untrash")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.files.untrash" call.
// Exactly one of *File or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *File.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *FilesUntrashCall) Do() (*File, error) {
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
	ret := &File{
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
	//   "description": "Restores a file from the trash.",
	//   "httpMethod": "POST",
	//   "id": "drive.files.untrash",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file to untrash.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/untrash",
	//   "response": {
	//     "$ref": "File"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.files.update":

type FilesUpdateCall struct {
	s          *Service
	fileId     string
	file       *File
	opt_       map[string]interface{}
	media_     io.Reader
	resumable_ googleapi.SizeReaderAt
	mediaType_ string
	protocol_  string
	ctx_       context.Context
}

// Update: Updates file metadata and/or content.
func (r *FilesService) Update(fileId string, file *File) *FilesUpdateCall {
	c := &FilesUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.file = file
	return c
}

// AddParents sets the optional parameter "addParents": Comma-separated
// list of parent IDs to add.
func (c *FilesUpdateCall) AddParents(addParents string) *FilesUpdateCall {
	c.opt_["addParents"] = addParents
	return c
}

// Convert sets the optional parameter "convert": This parameter is
// deprecated and has no function.
func (c *FilesUpdateCall) Convert(convert bool) *FilesUpdateCall {
	c.opt_["convert"] = convert
	return c
}

// ModifiedDateBehavior sets the optional parameter
// "modifiedDateBehavior": Determines the behavior in which modifiedDate
// is updated. This overrides setModifiedDate.
//
// Possible values:
//   "fromBody" - Set modifiedDate to the value provided in the body of
// the request. No change if no value was provided.
//   "fromBodyIfNeeded" - Set modifiedDate to the value provided in the
// body of the request depending on other contents of the update.
//   "fromBodyOrNow" - Set modifiedDate to the value provided in the
// body of the request, or to the current time if no value was provided.
//   "noChange" - Maintain the previous value of modifiedDate.
//   "now" - Set modifiedDate to the current time.
//   "nowIfNeeded" - Set modifiedDate to the current time depending on
// contents of the update.
func (c *FilesUpdateCall) ModifiedDateBehavior(modifiedDateBehavior string) *FilesUpdateCall {
	c.opt_["modifiedDateBehavior"] = modifiedDateBehavior
	return c
}

// NewRevision sets the optional parameter "newRevision": Whether a blob
// upload should create a new revision. If false, the blob data in the
// current head revision is replaced. If true or not set, a new blob is
// created as head revision, and previous unpinned revisions are
// preserved for a short period of time. Pinned revisions are stored
// indefinitely, using additional storage quota, up to a maximum of 200
// revisions. For details on how revisions are retained, see the Drive
// Help Center.
func (c *FilesUpdateCall) NewRevision(newRevision bool) *FilesUpdateCall {
	c.opt_["newRevision"] = newRevision
	return c
}

// Ocr sets the optional parameter "ocr": Whether to attempt OCR on
// .jpg, .png, .gif, or .pdf uploads.
func (c *FilesUpdateCall) Ocr(ocr bool) *FilesUpdateCall {
	c.opt_["ocr"] = ocr
	return c
}

// OcrLanguage sets the optional parameter "ocrLanguage": If ocr is
// true, hints at the language to use. Valid values are BCP 47 codes.
func (c *FilesUpdateCall) OcrLanguage(ocrLanguage string) *FilesUpdateCall {
	c.opt_["ocrLanguage"] = ocrLanguage
	return c
}

// Pinned sets the optional parameter "pinned": Whether to pin the new
// revision. A file can have a maximum of 200 pinned revisions.
func (c *FilesUpdateCall) Pinned(pinned bool) *FilesUpdateCall {
	c.opt_["pinned"] = pinned
	return c
}

// RemoveParents sets the optional parameter "removeParents":
// Comma-separated list of parent IDs to remove.
func (c *FilesUpdateCall) RemoveParents(removeParents string) *FilesUpdateCall {
	c.opt_["removeParents"] = removeParents
	return c
}

// SetModifiedDate sets the optional parameter "setModifiedDate":
// Whether to set the modified date with the supplied modified date.
func (c *FilesUpdateCall) SetModifiedDate(setModifiedDate bool) *FilesUpdateCall {
	c.opt_["setModifiedDate"] = setModifiedDate
	return c
}

// TimedTextLanguage sets the optional parameter "timedTextLanguage":
// The language of the timed text.
func (c *FilesUpdateCall) TimedTextLanguage(timedTextLanguage string) *FilesUpdateCall {
	c.opt_["timedTextLanguage"] = timedTextLanguage
	return c
}

// TimedTextTrackName sets the optional parameter "timedTextTrackName":
// The timed text track name.
func (c *FilesUpdateCall) TimedTextTrackName(timedTextTrackName string) *FilesUpdateCall {
	c.opt_["timedTextTrackName"] = timedTextTrackName
	return c
}

// UpdateViewedDate sets the optional parameter "updateViewedDate":
// Whether to update the view date after successfully updating the file.
func (c *FilesUpdateCall) UpdateViewedDate(updateViewedDate bool) *FilesUpdateCall {
	c.opt_["updateViewedDate"] = updateViewedDate
	return c
}

// UseContentAsIndexableText sets the optional parameter
// "useContentAsIndexableText": Whether to use the content as indexable
// text.
func (c *FilesUpdateCall) UseContentAsIndexableText(useContentAsIndexableText bool) *FilesUpdateCall {
	c.opt_["useContentAsIndexableText"] = useContentAsIndexableText
	return c
}

// Media specifies the media to upload in a single chunk.
// At most one of Media and ResumableMedia may be set.
func (c *FilesUpdateCall) Media(r io.Reader) *FilesUpdateCall {
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
func (c *FilesUpdateCall) ResumableMedia(ctx context.Context, r io.ReaderAt, size int64, mediaType string) *FilesUpdateCall {
	c.ctx_ = ctx
	c.resumable_ = io.NewSectionReader(r, 0, size)
	c.mediaType_ = mediaType
	c.protocol_ = "resumable"
	return c
}

// ProgressUpdater provides a callback function that will be called after every chunk.
// It should be a low-latency function in order to not slow down the upload operation.
// This should only be called when using ResumableMedia (as opposed to Media).
func (c *FilesUpdateCall) ProgressUpdater(pu googleapi.ProgressUpdater) *FilesUpdateCall {
	c.opt_["progressUpdater"] = pu
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *FilesUpdateCall) Fields(s ...googleapi.Field) *FilesUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
// This context will supersede any context previously provided to
// the ResumableMedia method.
func (c *FilesUpdateCall) Context(ctx context.Context) *FilesUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *FilesUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.file)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["addParents"]; ok {
		params.Set("addParents", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["convert"]; ok {
		params.Set("convert", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["modifiedDateBehavior"]; ok {
		params.Set("modifiedDateBehavior", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["newRevision"]; ok {
		params.Set("newRevision", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["ocr"]; ok {
		params.Set("ocr", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["ocrLanguage"]; ok {
		params.Set("ocrLanguage", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pinned"]; ok {
		params.Set("pinned", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["removeParents"]; ok {
		params.Set("removeParents", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["setModifiedDate"]; ok {
		params.Set("setModifiedDate", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["timedTextLanguage"]; ok {
		params.Set("timedTextLanguage", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["timedTextTrackName"]; ok {
		params.Set("timedTextTrackName", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["updateViewedDate"]; ok {
		params.Set("updateViewedDate", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["useContentAsIndexableText"]; ok {
		params.Set("useContentAsIndexableText", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}")
	if c.media_ != nil || c.resumable_ != nil {
		urls = strings.Replace(urls, "https://www.googleapis.com/", "https://www.googleapis.com/upload/", 1)
		params.Set("uploadType", c.protocol_)
	}
	urls += "?" + params.Encode()
	if c.protocol_ != "resumable" {
		var cancel func()
		cancel, _ = googleapi.ConditionallyIncludeMedia(c.media_, &body, &ctype)
		if cancel != nil {
			defer cancel()
		}
	}
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
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

// Do executes the "drive.files.update" call.
// Exactly one of *File or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *File.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *FilesUpdateCall) Do() (*File, error) {
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
	ret := &File{
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
	//   "description": "Updates file metadata and/or content.",
	//   "httpMethod": "PUT",
	//   "id": "drive.files.update",
	//   "mediaUpload": {
	//     "accept": [
	//       "*/*"
	//     ],
	//     "maxSize": "5120GB",
	//     "protocols": {
	//       "resumable": {
	//         "multipart": true,
	//         "path": "/resumable/upload/drive/v2/files/{fileId}"
	//       },
	//       "simple": {
	//         "multipart": true,
	//         "path": "/upload/drive/v2/files/{fileId}"
	//       }
	//     }
	//   },
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "addParents": {
	//       "description": "Comma-separated list of parent IDs to add.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "convert": {
	//       "default": "false",
	//       "description": "This parameter is deprecated and has no function.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "modifiedDateBehavior": {
	//       "description": "Determines the behavior in which modifiedDate is updated. This overrides setModifiedDate.",
	//       "enum": [
	//         "fromBody",
	//         "fromBodyIfNeeded",
	//         "fromBodyOrNow",
	//         "noChange",
	//         "now",
	//         "nowIfNeeded"
	//       ],
	//       "enumDescriptions": [
	//         "Set modifiedDate to the value provided in the body of the request. No change if no value was provided.",
	//         "Set modifiedDate to the value provided in the body of the request depending on other contents of the update.",
	//         "Set modifiedDate to the value provided in the body of the request, or to the current time if no value was provided.",
	//         "Maintain the previous value of modifiedDate.",
	//         "Set modifiedDate to the current time.",
	//         "Set modifiedDate to the current time depending on contents of the update."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "newRevision": {
	//       "default": "true",
	//       "description": "Whether a blob upload should create a new revision. If false, the blob data in the current head revision is replaced. If true or not set, a new blob is created as head revision, and previous unpinned revisions are preserved for a short period of time. Pinned revisions are stored indefinitely, using additional storage quota, up to a maximum of 200 revisions. For details on how revisions are retained, see the Drive Help Center.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "ocr": {
	//       "default": "false",
	//       "description": "Whether to attempt OCR on .jpg, .png, .gif, or .pdf uploads.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "ocrLanguage": {
	//       "description": "If ocr is true, hints at the language to use. Valid values are BCP 47 codes.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pinned": {
	//       "default": "false",
	//       "description": "Whether to pin the new revision. A file can have a maximum of 200 pinned revisions.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "removeParents": {
	//       "description": "Comma-separated list of parent IDs to remove.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "setModifiedDate": {
	//       "default": "false",
	//       "description": "Whether to set the modified date with the supplied modified date.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "timedTextLanguage": {
	//       "description": "The language of the timed text.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "timedTextTrackName": {
	//       "description": "The timed text track name.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "updateViewedDate": {
	//       "default": "true",
	//       "description": "Whether to update the view date after successfully updating the file.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "useContentAsIndexableText": {
	//       "default": "false",
	//       "description": "Whether to use the content as indexable text.",
	//       "location": "query",
	//       "type": "boolean"
	//     }
	//   },
	//   "path": "files/{fileId}",
	//   "request": {
	//     "$ref": "File"
	//   },
	//   "response": {
	//     "$ref": "File"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.scripts"
	//   ],
	//   "supportsMediaUpload": true
	// }

}

// method id "drive.files.watch":

type FilesWatchCall struct {
	s       *Service
	fileId  string
	channel *Channel
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Watch: Subscribe to changes on a file
func (r *FilesService) Watch(fileId string, channel *Channel) *FilesWatchCall {
	c := &FilesWatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.channel = channel
	return c
}

// AcknowledgeAbuse sets the optional parameter "acknowledgeAbuse":
// Whether the user is acknowledging the risk of downloading known
// malware or other abusive files.
func (c *FilesWatchCall) AcknowledgeAbuse(acknowledgeAbuse bool) *FilesWatchCall {
	c.opt_["acknowledgeAbuse"] = acknowledgeAbuse
	return c
}

// Projection sets the optional parameter "projection": This parameter
// is deprecated and has no function.
//
// Possible values:
//   "BASIC" - Deprecated
//   "FULL" - Deprecated
func (c *FilesWatchCall) Projection(projection string) *FilesWatchCall {
	c.opt_["projection"] = projection
	return c
}

// RevisionId sets the optional parameter "revisionId": Specifies the
// Revision ID that should be downloaded. Ignored unless alt=media is
// specified.
func (c *FilesWatchCall) RevisionId(revisionId string) *FilesWatchCall {
	c.opt_["revisionId"] = revisionId
	return c
}

// UpdateViewedDate sets the optional parameter "updateViewedDate":
// Deprecated: Use files.update with modifiedDateBehavior=noChange,
// updateViewedDate=true and an empty request body.
func (c *FilesWatchCall) UpdateViewedDate(updateViewedDate bool) *FilesWatchCall {
	c.opt_["updateViewedDate"] = updateViewedDate
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *FilesWatchCall) Fields(s ...googleapi.Field) *FilesWatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do and Download methods.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *FilesWatchCall) Context(ctx context.Context) *FilesWatchCall {
	c.ctx_ = ctx
	return c
}

func (c *FilesWatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.channel)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["acknowledgeAbuse"]; ok {
		params.Set("acknowledgeAbuse", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["projection"]; ok {
		params.Set("projection", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["revisionId"]; ok {
		params.Set("revisionId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["updateViewedDate"]; ok {
		params.Set("updateViewedDate", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/watch")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Download fetches the API endpoint's "media" value, instead of the normal
// API response value. If the returned error is nil, the Response is guaranteed to
// have a 2xx status code. Callers must close the Response.Body as usual.
func (c *FilesWatchCall) Download() (*http.Response, error) {
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

// Do executes the "drive.files.watch" call.
// Exactly one of *Channel or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Channel.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *FilesWatchCall) Do() (*Channel, error) {
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
	ret := &Channel{
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
	//   "description": "Subscribe to changes on a file",
	//   "httpMethod": "POST",
	//   "id": "drive.files.watch",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "acknowledgeAbuse": {
	//       "default": "false",
	//       "description": "Whether the user is acknowledging the risk of downloading known malware or other abusive files.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "fileId": {
	//       "description": "The ID for the file in question.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "projection": {
	//       "description": "This parameter is deprecated and has no function.",
	//       "enum": [
	//         "BASIC",
	//         "FULL"
	//       ],
	//       "enumDescriptions": [
	//         "Deprecated",
	//         "Deprecated"
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "revisionId": {
	//       "description": "Specifies the Revision ID that should be downloaded. Ignored unless alt=media is specified.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "updateViewedDate": {
	//       "default": "false",
	//       "description": "Deprecated: Use files.update with modifiedDateBehavior=noChange, updateViewedDate=true and an empty request body.",
	//       "location": "query",
	//       "type": "boolean"
	//     }
	//   },
	//   "path": "files/{fileId}/watch",
	//   "request": {
	//     "$ref": "Channel",
	//     "parameterName": "resource"
	//   },
	//   "response": {
	//     "$ref": "Channel"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ],
	//   "supportsMediaDownload": true,
	//   "supportsSubscription": true
	// }

}

// method id "drive.parents.delete":

type ParentsDeleteCall struct {
	s        *Service
	fileId   string
	parentId string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Delete: Removes a parent from a file.
func (r *ParentsService) Delete(fileId string, parentId string) *ParentsDeleteCall {
	c := &ParentsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.parentId = parentId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ParentsDeleteCall) Fields(s ...googleapi.Field) *ParentsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ParentsDeleteCall) Context(ctx context.Context) *ParentsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ParentsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/parents/{parentId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":   c.fileId,
		"parentId": c.parentId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.parents.delete" call.
func (c *ParentsDeleteCall) Do() error {
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
	//   "description": "Removes a parent from a file.",
	//   "httpMethod": "DELETE",
	//   "id": "drive.parents.delete",
	//   "parameterOrder": [
	//     "fileId",
	//     "parentId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "parentId": {
	//       "description": "The ID of the parent.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/parents/{parentId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.parents.get":

type ParentsGetCall struct {
	s        *Service
	fileId   string
	parentId string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Get: Gets a specific parent reference.
func (r *ParentsService) Get(fileId string, parentId string) *ParentsGetCall {
	c := &ParentsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.parentId = parentId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ParentsGetCall) Fields(s ...googleapi.Field) *ParentsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ParentsGetCall) IfNoneMatch(entityTag string) *ParentsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ParentsGetCall) Context(ctx context.Context) *ParentsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ParentsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/parents/{parentId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":   c.fileId,
		"parentId": c.parentId,
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

// Do executes the "drive.parents.get" call.
// Exactly one of *ParentReference or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ParentReference.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ParentsGetCall) Do() (*ParentReference, error) {
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
	ret := &ParentReference{
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
	//   "description": "Gets a specific parent reference.",
	//   "httpMethod": "GET",
	//   "id": "drive.parents.get",
	//   "parameterOrder": [
	//     "fileId",
	//     "parentId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "parentId": {
	//       "description": "The ID of the parent.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/parents/{parentId}",
	//   "response": {
	//     "$ref": "ParentReference"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.parents.insert":

type ParentsInsertCall struct {
	s               *Service
	fileId          string
	parentreference *ParentReference
	opt_            map[string]interface{}
	ctx_            context.Context
}

// Insert: Adds a parent folder for a file.
func (r *ParentsService) Insert(fileId string, parentreference *ParentReference) *ParentsInsertCall {
	c := &ParentsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.parentreference = parentreference
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ParentsInsertCall) Fields(s ...googleapi.Field) *ParentsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ParentsInsertCall) Context(ctx context.Context) *ParentsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ParentsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.parentreference)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/parents")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.parents.insert" call.
// Exactly one of *ParentReference or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ParentReference.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ParentsInsertCall) Do() (*ParentReference, error) {
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
	ret := &ParentReference{
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
	//   "description": "Adds a parent folder for a file.",
	//   "httpMethod": "POST",
	//   "id": "drive.parents.insert",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/parents",
	//   "request": {
	//     "$ref": "ParentReference"
	//   },
	//   "response": {
	//     "$ref": "ParentReference"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.parents.list":

type ParentsListCall struct {
	s      *Service
	fileId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// List: Lists a file's parents.
func (r *ParentsService) List(fileId string) *ParentsListCall {
	c := &ParentsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ParentsListCall) Fields(s ...googleapi.Field) *ParentsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ParentsListCall) IfNoneMatch(entityTag string) *ParentsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ParentsListCall) Context(ctx context.Context) *ParentsListCall {
	c.ctx_ = ctx
	return c
}

func (c *ParentsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/parents")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
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

// Do executes the "drive.parents.list" call.
// Exactly one of *ParentList or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ParentList.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ParentsListCall) Do() (*ParentList, error) {
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
	ret := &ParentList{
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
	//   "description": "Lists a file's parents.",
	//   "httpMethod": "GET",
	//   "id": "drive.parents.list",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/parents",
	//   "response": {
	//     "$ref": "ParentList"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.permissions.delete":

type PermissionsDeleteCall struct {
	s            *Service
	fileId       string
	permissionId string
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Delete: Deletes a permission from a file.
func (r *PermissionsService) Delete(fileId string, permissionId string) *PermissionsDeleteCall {
	c := &PermissionsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.permissionId = permissionId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PermissionsDeleteCall) Fields(s ...googleapi.Field) *PermissionsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PermissionsDeleteCall) Context(ctx context.Context) *PermissionsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *PermissionsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/permissions/{permissionId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":       c.fileId,
		"permissionId": c.permissionId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.permissions.delete" call.
func (c *PermissionsDeleteCall) Do() error {
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
	//   "description": "Deletes a permission from a file.",
	//   "httpMethod": "DELETE",
	//   "id": "drive.permissions.delete",
	//   "parameterOrder": [
	//     "fileId",
	//     "permissionId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID for the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "permissionId": {
	//       "description": "The ID for the permission.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/permissions/{permissionId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.permissions.get":

type PermissionsGetCall struct {
	s            *Service
	fileId       string
	permissionId string
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Get: Gets a permission by ID.
func (r *PermissionsService) Get(fileId string, permissionId string) *PermissionsGetCall {
	c := &PermissionsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.permissionId = permissionId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PermissionsGetCall) Fields(s ...googleapi.Field) *PermissionsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PermissionsGetCall) IfNoneMatch(entityTag string) *PermissionsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PermissionsGetCall) Context(ctx context.Context) *PermissionsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *PermissionsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/permissions/{permissionId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":       c.fileId,
		"permissionId": c.permissionId,
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

// Do executes the "drive.permissions.get" call.
// Exactly one of *Permission or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Permission.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PermissionsGetCall) Do() (*Permission, error) {
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
	ret := &Permission{
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
	//   "description": "Gets a permission by ID.",
	//   "httpMethod": "GET",
	//   "id": "drive.permissions.get",
	//   "parameterOrder": [
	//     "fileId",
	//     "permissionId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID for the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "permissionId": {
	//       "description": "The ID for the permission.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/permissions/{permissionId}",
	//   "response": {
	//     "$ref": "Permission"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.permissions.getIdForEmail":

type PermissionsGetIdForEmailCall struct {
	s     *Service
	email string
	opt_  map[string]interface{}
	ctx_  context.Context
}

// GetIdForEmail: Returns the permission ID for an email address.
func (r *PermissionsService) GetIdForEmail(email string) *PermissionsGetIdForEmailCall {
	c := &PermissionsGetIdForEmailCall{s: r.s, opt_: make(map[string]interface{})}
	c.email = email
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PermissionsGetIdForEmailCall) Fields(s ...googleapi.Field) *PermissionsGetIdForEmailCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PermissionsGetIdForEmailCall) IfNoneMatch(entityTag string) *PermissionsGetIdForEmailCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PermissionsGetIdForEmailCall) Context(ctx context.Context) *PermissionsGetIdForEmailCall {
	c.ctx_ = ctx
	return c
}

func (c *PermissionsGetIdForEmailCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "permissionIds/{email}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"email": c.email,
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

// Do executes the "drive.permissions.getIdForEmail" call.
// Exactly one of *PermissionId or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *PermissionId.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PermissionsGetIdForEmailCall) Do() (*PermissionId, error) {
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
	ret := &PermissionId{
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
	//   "description": "Returns the permission ID for an email address.",
	//   "httpMethod": "GET",
	//   "id": "drive.permissions.getIdForEmail",
	//   "parameterOrder": [
	//     "email"
	//   ],
	//   "parameters": {
	//     "email": {
	//       "description": "The email address for which to return a permission ID",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "permissionIds/{email}",
	//   "response": {
	//     "$ref": "PermissionId"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.apps.readonly",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.permissions.insert":

type PermissionsInsertCall struct {
	s          *Service
	fileId     string
	permission *Permission
	opt_       map[string]interface{}
	ctx_       context.Context
}

// Insert: Inserts a permission for a file.
func (r *PermissionsService) Insert(fileId string, permission *Permission) *PermissionsInsertCall {
	c := &PermissionsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.permission = permission
	return c
}

// EmailMessage sets the optional parameter "emailMessage": A custom
// message to include in notification emails.
func (c *PermissionsInsertCall) EmailMessage(emailMessage string) *PermissionsInsertCall {
	c.opt_["emailMessage"] = emailMessage
	return c
}

// SendNotificationEmails sets the optional parameter
// "sendNotificationEmails": Whether to send notification emails when
// sharing to users or groups. This parameter is ignored and an email is
// sent if the role is owner.
func (c *PermissionsInsertCall) SendNotificationEmails(sendNotificationEmails bool) *PermissionsInsertCall {
	c.opt_["sendNotificationEmails"] = sendNotificationEmails
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PermissionsInsertCall) Fields(s ...googleapi.Field) *PermissionsInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PermissionsInsertCall) Context(ctx context.Context) *PermissionsInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *PermissionsInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.permission)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["emailMessage"]; ok {
		params.Set("emailMessage", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["sendNotificationEmails"]; ok {
		params.Set("sendNotificationEmails", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/permissions")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.permissions.insert" call.
// Exactly one of *Permission or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Permission.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PermissionsInsertCall) Do() (*Permission, error) {
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
	ret := &Permission{
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
	//   "description": "Inserts a permission for a file.",
	//   "httpMethod": "POST",
	//   "id": "drive.permissions.insert",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "emailMessage": {
	//       "description": "A custom message to include in notification emails.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "fileId": {
	//       "description": "The ID for the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "sendNotificationEmails": {
	//       "default": "true",
	//       "description": "Whether to send notification emails when sharing to users or groups. This parameter is ignored and an email is sent if the role is owner.",
	//       "location": "query",
	//       "type": "boolean"
	//     }
	//   },
	//   "path": "files/{fileId}/permissions",
	//   "request": {
	//     "$ref": "Permission"
	//   },
	//   "response": {
	//     "$ref": "Permission"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.permissions.list":

type PermissionsListCall struct {
	s      *Service
	fileId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// List: Lists a file's permissions.
func (r *PermissionsService) List(fileId string) *PermissionsListCall {
	c := &PermissionsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PermissionsListCall) Fields(s ...googleapi.Field) *PermissionsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PermissionsListCall) IfNoneMatch(entityTag string) *PermissionsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PermissionsListCall) Context(ctx context.Context) *PermissionsListCall {
	c.ctx_ = ctx
	return c
}

func (c *PermissionsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/permissions")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
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

// Do executes the "drive.permissions.list" call.
// Exactly one of *PermissionList or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *PermissionList.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *PermissionsListCall) Do() (*PermissionList, error) {
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
	ret := &PermissionList{
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
	//   "description": "Lists a file's permissions.",
	//   "httpMethod": "GET",
	//   "id": "drive.permissions.list",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID for the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/permissions",
	//   "response": {
	//     "$ref": "PermissionList"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.permissions.patch":

type PermissionsPatchCall struct {
	s            *Service
	fileId       string
	permissionId string
	permission   *Permission
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Patch: Updates a permission using patch semantics.
func (r *PermissionsService) Patch(fileId string, permissionId string, permission *Permission) *PermissionsPatchCall {
	c := &PermissionsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.permissionId = permissionId
	c.permission = permission
	return c
}

// TransferOwnership sets the optional parameter "transferOwnership":
// Whether changing a role to 'owner' downgrades the current owners to
// writers. Does nothing if the specified role is not 'owner'.
func (c *PermissionsPatchCall) TransferOwnership(transferOwnership bool) *PermissionsPatchCall {
	c.opt_["transferOwnership"] = transferOwnership
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PermissionsPatchCall) Fields(s ...googleapi.Field) *PermissionsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PermissionsPatchCall) Context(ctx context.Context) *PermissionsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *PermissionsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.permission)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["transferOwnership"]; ok {
		params.Set("transferOwnership", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/permissions/{permissionId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":       c.fileId,
		"permissionId": c.permissionId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.permissions.patch" call.
// Exactly one of *Permission or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Permission.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PermissionsPatchCall) Do() (*Permission, error) {
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
	ret := &Permission{
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
	//   "description": "Updates a permission using patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "drive.permissions.patch",
	//   "parameterOrder": [
	//     "fileId",
	//     "permissionId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID for the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "permissionId": {
	//       "description": "The ID for the permission.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "transferOwnership": {
	//       "default": "false",
	//       "description": "Whether changing a role to 'owner' downgrades the current owners to writers. Does nothing if the specified role is not 'owner'.",
	//       "location": "query",
	//       "type": "boolean"
	//     }
	//   },
	//   "path": "files/{fileId}/permissions/{permissionId}",
	//   "request": {
	//     "$ref": "Permission"
	//   },
	//   "response": {
	//     "$ref": "Permission"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.permissions.update":

type PermissionsUpdateCall struct {
	s            *Service
	fileId       string
	permissionId string
	permission   *Permission
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Update: Updates a permission.
func (r *PermissionsService) Update(fileId string, permissionId string, permission *Permission) *PermissionsUpdateCall {
	c := &PermissionsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.permissionId = permissionId
	c.permission = permission
	return c
}

// TransferOwnership sets the optional parameter "transferOwnership":
// Whether changing a role to 'owner' downgrades the current owners to
// writers. Does nothing if the specified role is not 'owner'.
func (c *PermissionsUpdateCall) TransferOwnership(transferOwnership bool) *PermissionsUpdateCall {
	c.opt_["transferOwnership"] = transferOwnership
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PermissionsUpdateCall) Fields(s ...googleapi.Field) *PermissionsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PermissionsUpdateCall) Context(ctx context.Context) *PermissionsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *PermissionsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.permission)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["transferOwnership"]; ok {
		params.Set("transferOwnership", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/permissions/{permissionId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":       c.fileId,
		"permissionId": c.permissionId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.permissions.update" call.
// Exactly one of *Permission or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Permission.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PermissionsUpdateCall) Do() (*Permission, error) {
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
	ret := &Permission{
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
	//   "description": "Updates a permission.",
	//   "httpMethod": "PUT",
	//   "id": "drive.permissions.update",
	//   "parameterOrder": [
	//     "fileId",
	//     "permissionId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID for the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "permissionId": {
	//       "description": "The ID for the permission.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "transferOwnership": {
	//       "default": "false",
	//       "description": "Whether changing a role to 'owner' downgrades the current owners to writers. Does nothing if the specified role is not 'owner'.",
	//       "location": "query",
	//       "type": "boolean"
	//     }
	//   },
	//   "path": "files/{fileId}/permissions/{permissionId}",
	//   "request": {
	//     "$ref": "Permission"
	//   },
	//   "response": {
	//     "$ref": "Permission"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.properties.delete":

type PropertiesDeleteCall struct {
	s           *Service
	fileId      string
	propertyKey string
	opt_        map[string]interface{}
	ctx_        context.Context
}

// Delete: Deletes a property.
func (r *PropertiesService) Delete(fileId string, propertyKey string) *PropertiesDeleteCall {
	c := &PropertiesDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.propertyKey = propertyKey
	return c
}

// Visibility sets the optional parameter "visibility": The visibility
// of the property.
func (c *PropertiesDeleteCall) Visibility(visibility string) *PropertiesDeleteCall {
	c.opt_["visibility"] = visibility
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PropertiesDeleteCall) Fields(s ...googleapi.Field) *PropertiesDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PropertiesDeleteCall) Context(ctx context.Context) *PropertiesDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *PropertiesDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["visibility"]; ok {
		params.Set("visibility", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/properties/{propertyKey}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":      c.fileId,
		"propertyKey": c.propertyKey,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.properties.delete" call.
func (c *PropertiesDeleteCall) Do() error {
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
	//   "description": "Deletes a property.",
	//   "httpMethod": "DELETE",
	//   "id": "drive.properties.delete",
	//   "parameterOrder": [
	//     "fileId",
	//     "propertyKey"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "propertyKey": {
	//       "description": "The key of the property.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "visibility": {
	//       "default": "private",
	//       "description": "The visibility of the property.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/properties/{propertyKey}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata"
	//   ]
	// }

}

// method id "drive.properties.get":

type PropertiesGetCall struct {
	s           *Service
	fileId      string
	propertyKey string
	opt_        map[string]interface{}
	ctx_        context.Context
}

// Get: Gets a property by its key.
func (r *PropertiesService) Get(fileId string, propertyKey string) *PropertiesGetCall {
	c := &PropertiesGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.propertyKey = propertyKey
	return c
}

// Visibility sets the optional parameter "visibility": The visibility
// of the property.
func (c *PropertiesGetCall) Visibility(visibility string) *PropertiesGetCall {
	c.opt_["visibility"] = visibility
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PropertiesGetCall) Fields(s ...googleapi.Field) *PropertiesGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PropertiesGetCall) IfNoneMatch(entityTag string) *PropertiesGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PropertiesGetCall) Context(ctx context.Context) *PropertiesGetCall {
	c.ctx_ = ctx
	return c
}

func (c *PropertiesGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["visibility"]; ok {
		params.Set("visibility", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/properties/{propertyKey}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":      c.fileId,
		"propertyKey": c.propertyKey,
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

// Do executes the "drive.properties.get" call.
// Exactly one of *Property or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Property.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PropertiesGetCall) Do() (*Property, error) {
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
	ret := &Property{
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
	//   "description": "Gets a property by its key.",
	//   "httpMethod": "GET",
	//   "id": "drive.properties.get",
	//   "parameterOrder": [
	//     "fileId",
	//     "propertyKey"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "propertyKey": {
	//       "description": "The key of the property.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "visibility": {
	//       "default": "private",
	//       "description": "The visibility of the property.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/properties/{propertyKey}",
	//   "response": {
	//     "$ref": "Property"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.properties.insert":

type PropertiesInsertCall struct {
	s        *Service
	fileId   string
	property *Property
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Insert: Adds a property to a file.
func (r *PropertiesService) Insert(fileId string, property *Property) *PropertiesInsertCall {
	c := &PropertiesInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.property = property
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PropertiesInsertCall) Fields(s ...googleapi.Field) *PropertiesInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PropertiesInsertCall) Context(ctx context.Context) *PropertiesInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *PropertiesInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.property)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/properties")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.properties.insert" call.
// Exactly one of *Property or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Property.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PropertiesInsertCall) Do() (*Property, error) {
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
	ret := &Property{
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
	//   "description": "Adds a property to a file.",
	//   "httpMethod": "POST",
	//   "id": "drive.properties.insert",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/properties",
	//   "request": {
	//     "$ref": "Property"
	//   },
	//   "response": {
	//     "$ref": "Property"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata"
	//   ]
	// }

}

// method id "drive.properties.list":

type PropertiesListCall struct {
	s      *Service
	fileId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// List: Lists a file's properties.
func (r *PropertiesService) List(fileId string) *PropertiesListCall {
	c := &PropertiesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PropertiesListCall) Fields(s ...googleapi.Field) *PropertiesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PropertiesListCall) IfNoneMatch(entityTag string) *PropertiesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PropertiesListCall) Context(ctx context.Context) *PropertiesListCall {
	c.ctx_ = ctx
	return c
}

func (c *PropertiesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/properties")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
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

// Do executes the "drive.properties.list" call.
// Exactly one of *PropertyList or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *PropertyList.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PropertiesListCall) Do() (*PropertyList, error) {
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
	ret := &PropertyList{
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
	//   "description": "Lists a file's properties.",
	//   "httpMethod": "GET",
	//   "id": "drive.properties.list",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/properties",
	//   "response": {
	//     "$ref": "PropertyList"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.properties.patch":

type PropertiesPatchCall struct {
	s           *Service
	fileId      string
	propertyKey string
	property    *Property
	opt_        map[string]interface{}
	ctx_        context.Context
}

// Patch: Updates a property. This method supports patch semantics.
func (r *PropertiesService) Patch(fileId string, propertyKey string, property *Property) *PropertiesPatchCall {
	c := &PropertiesPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.propertyKey = propertyKey
	c.property = property
	return c
}

// Visibility sets the optional parameter "visibility": The visibility
// of the property.
func (c *PropertiesPatchCall) Visibility(visibility string) *PropertiesPatchCall {
	c.opt_["visibility"] = visibility
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PropertiesPatchCall) Fields(s ...googleapi.Field) *PropertiesPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PropertiesPatchCall) Context(ctx context.Context) *PropertiesPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *PropertiesPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.property)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["visibility"]; ok {
		params.Set("visibility", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/properties/{propertyKey}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":      c.fileId,
		"propertyKey": c.propertyKey,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.properties.patch" call.
// Exactly one of *Property or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Property.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PropertiesPatchCall) Do() (*Property, error) {
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
	ret := &Property{
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
	//   "description": "Updates a property. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "drive.properties.patch",
	//   "parameterOrder": [
	//     "fileId",
	//     "propertyKey"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "propertyKey": {
	//       "description": "The key of the property.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "visibility": {
	//       "default": "private",
	//       "description": "The visibility of the property.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/properties/{propertyKey}",
	//   "request": {
	//     "$ref": "Property"
	//   },
	//   "response": {
	//     "$ref": "Property"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata"
	//   ]
	// }

}

// method id "drive.properties.update":

type PropertiesUpdateCall struct {
	s           *Service
	fileId      string
	propertyKey string
	property    *Property
	opt_        map[string]interface{}
	ctx_        context.Context
}

// Update: Updates a property.
func (r *PropertiesService) Update(fileId string, propertyKey string, property *Property) *PropertiesUpdateCall {
	c := &PropertiesUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.propertyKey = propertyKey
	c.property = property
	return c
}

// Visibility sets the optional parameter "visibility": The visibility
// of the property.
func (c *PropertiesUpdateCall) Visibility(visibility string) *PropertiesUpdateCall {
	c.opt_["visibility"] = visibility
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PropertiesUpdateCall) Fields(s ...googleapi.Field) *PropertiesUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PropertiesUpdateCall) Context(ctx context.Context) *PropertiesUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *PropertiesUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.property)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["visibility"]; ok {
		params.Set("visibility", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/properties/{propertyKey}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":      c.fileId,
		"propertyKey": c.propertyKey,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.properties.update" call.
// Exactly one of *Property or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Property.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PropertiesUpdateCall) Do() (*Property, error) {
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
	ret := &Property{
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
	//   "description": "Updates a property.",
	//   "httpMethod": "PUT",
	//   "id": "drive.properties.update",
	//   "parameterOrder": [
	//     "fileId",
	//     "propertyKey"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "propertyKey": {
	//       "description": "The key of the property.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "visibility": {
	//       "default": "private",
	//       "description": "The visibility of the property.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/properties/{propertyKey}",
	//   "request": {
	//     "$ref": "Property"
	//   },
	//   "response": {
	//     "$ref": "Property"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata"
	//   ]
	// }

}

// method id "drive.realtime.get":

type RealtimeGetCall struct {
	s      *Service
	fileId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Get: Exports the contents of the Realtime API data model associated
// with this file as JSON.
func (r *RealtimeService) Get(fileId string) *RealtimeGetCall {
	c := &RealtimeGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	return c
}

// Revision sets the optional parameter "revision": The revision of the
// Realtime API data model to export. Revisions start at 1 (the initial
// empty data model) and are incremented with each change. If this
// parameter is excluded, the most recent data model will be returned.
func (c *RealtimeGetCall) Revision(revision int64) *RealtimeGetCall {
	c.opt_["revision"] = revision
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RealtimeGetCall) Fields(s ...googleapi.Field) *RealtimeGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *RealtimeGetCall) IfNoneMatch(entityTag string) *RealtimeGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do and Download methods.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RealtimeGetCall) Context(ctx context.Context) *RealtimeGetCall {
	c.ctx_ = ctx
	return c
}

func (c *RealtimeGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["revision"]; ok {
		params.Set("revision", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/realtime")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
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

// Download fetches the API endpoint's "media" value, instead of the normal
// API response value. If the returned error is nil, the Response is guaranteed to
// have a 2xx status code. Callers must close the Response.Body as usual.
func (c *RealtimeGetCall) Download() (*http.Response, error) {
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

// Do executes the "drive.realtime.get" call.
func (c *RealtimeGetCall) Do() error {
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
	//   "description": "Exports the contents of the Realtime API data model associated with this file as JSON.",
	//   "httpMethod": "GET",
	//   "id": "drive.realtime.get",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file that the Realtime API data model is associated with.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "revision": {
	//       "description": "The revision of the Realtime API data model to export. Revisions start at 1 (the initial empty data model) and are incremented with each change. If this parameter is excluded, the most recent data model will be returned.",
	//       "format": "int32",
	//       "location": "query",
	//       "minimum": "1",
	//       "type": "integer"
	//     }
	//   },
	//   "path": "files/{fileId}/realtime",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ],
	//   "supportsMediaDownload": true
	// }

}

// method id "drive.realtime.update":

type RealtimeUpdateCall struct {
	s          *Service
	fileId     string
	opt_       map[string]interface{}
	media_     io.Reader
	resumable_ googleapi.SizeReaderAt
	mediaType_ string
	protocol_  string
	ctx_       context.Context
}

// Update: Overwrites the Realtime API data model associated with this
// file with the provided JSON data model.
func (r *RealtimeService) Update(fileId string) *RealtimeUpdateCall {
	c := &RealtimeUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	return c
}

// BaseRevision sets the optional parameter "baseRevision": The revision
// of the model to diff the uploaded model against. If set, the uploaded
// model is diffed against the provided revision and those differences
// are merged with any changes made to the model after the provided
// revision. If not set, the uploaded model replaces the current model
// on the server.
func (c *RealtimeUpdateCall) BaseRevision(baseRevision string) *RealtimeUpdateCall {
	c.opt_["baseRevision"] = baseRevision
	return c
}

// Media specifies the media to upload in a single chunk.
// At most one of Media and ResumableMedia may be set.
func (c *RealtimeUpdateCall) Media(r io.Reader) *RealtimeUpdateCall {
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
func (c *RealtimeUpdateCall) ResumableMedia(ctx context.Context, r io.ReaderAt, size int64, mediaType string) *RealtimeUpdateCall {
	c.ctx_ = ctx
	c.resumable_ = io.NewSectionReader(r, 0, size)
	c.mediaType_ = mediaType
	c.protocol_ = "resumable"
	return c
}

// ProgressUpdater provides a callback function that will be called after every chunk.
// It should be a low-latency function in order to not slow down the upload operation.
// This should only be called when using ResumableMedia (as opposed to Media).
func (c *RealtimeUpdateCall) ProgressUpdater(pu googleapi.ProgressUpdater) *RealtimeUpdateCall {
	c.opt_["progressUpdater"] = pu
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RealtimeUpdateCall) Fields(s ...googleapi.Field) *RealtimeUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
// This context will supersede any context previously provided to
// the ResumableMedia method.
func (c *RealtimeUpdateCall) Context(ctx context.Context) *RealtimeUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *RealtimeUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["baseRevision"]; ok {
		params.Set("baseRevision", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/realtime")
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
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
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

// Do executes the "drive.realtime.update" call.
func (c *RealtimeUpdateCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
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
			return err
		}
		defer res.Body.Close()
	}
	return nil
	// {
	//   "description": "Overwrites the Realtime API data model associated with this file with the provided JSON data model.",
	//   "httpMethod": "PUT",
	//   "id": "drive.realtime.update",
	//   "mediaUpload": {
	//     "accept": [
	//       "*/*"
	//     ],
	//     "maxSize": "10MB",
	//     "protocols": {
	//       "resumable": {
	//         "multipart": true,
	//         "path": "/resumable/upload/drive/v2/files/{fileId}/realtime"
	//       },
	//       "simple": {
	//         "multipart": true,
	//         "path": "/upload/drive/v2/files/{fileId}/realtime"
	//       }
	//     }
	//   },
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "baseRevision": {
	//       "description": "The revision of the model to diff the uploaded model against. If set, the uploaded model is diffed against the provided revision and those differences are merged with any changes made to the model after the provided revision. If not set, the uploaded model replaces the current model on the server.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file that the Realtime API data model is associated with.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/realtime",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ],
	//   "supportsMediaUpload": true
	// }

}

// method id "drive.replies.delete":

type RepliesDeleteCall struct {
	s         *Service
	fileId    string
	commentId string
	replyId   string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Delete: Deletes a reply.
func (r *RepliesService) Delete(fileId string, commentId string, replyId string) *RepliesDeleteCall {
	c := &RepliesDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.commentId = commentId
	c.replyId = replyId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RepliesDeleteCall) Fields(s ...googleapi.Field) *RepliesDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RepliesDeleteCall) Context(ctx context.Context) *RepliesDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *RepliesDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/comments/{commentId}/replies/{replyId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":    c.fileId,
		"commentId": c.commentId,
		"replyId":   c.replyId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.replies.delete" call.
func (c *RepliesDeleteCall) Do() error {
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
	//   "description": "Deletes a reply.",
	//   "httpMethod": "DELETE",
	//   "id": "drive.replies.delete",
	//   "parameterOrder": [
	//     "fileId",
	//     "commentId",
	//     "replyId"
	//   ],
	//   "parameters": {
	//     "commentId": {
	//       "description": "The ID of the comment.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "replyId": {
	//       "description": "The ID of the reply.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/comments/{commentId}/replies/{replyId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.replies.get":

type RepliesGetCall struct {
	s         *Service
	fileId    string
	commentId string
	replyId   string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Gets a reply.
func (r *RepliesService) Get(fileId string, commentId string, replyId string) *RepliesGetCall {
	c := &RepliesGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.commentId = commentId
	c.replyId = replyId
	return c
}

// IncludeDeleted sets the optional parameter "includeDeleted": If set,
// this will succeed when retrieving a deleted reply.
func (c *RepliesGetCall) IncludeDeleted(includeDeleted bool) *RepliesGetCall {
	c.opt_["includeDeleted"] = includeDeleted
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RepliesGetCall) Fields(s ...googleapi.Field) *RepliesGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *RepliesGetCall) IfNoneMatch(entityTag string) *RepliesGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RepliesGetCall) Context(ctx context.Context) *RepliesGetCall {
	c.ctx_ = ctx
	return c
}

func (c *RepliesGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["includeDeleted"]; ok {
		params.Set("includeDeleted", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/comments/{commentId}/replies/{replyId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":    c.fileId,
		"commentId": c.commentId,
		"replyId":   c.replyId,
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

// Do executes the "drive.replies.get" call.
// Exactly one of *CommentReply or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CommentReply.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *RepliesGetCall) Do() (*CommentReply, error) {
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
	ret := &CommentReply{
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
	//   "description": "Gets a reply.",
	//   "httpMethod": "GET",
	//   "id": "drive.replies.get",
	//   "parameterOrder": [
	//     "fileId",
	//     "commentId",
	//     "replyId"
	//   ],
	//   "parameters": {
	//     "commentId": {
	//       "description": "The ID of the comment.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "includeDeleted": {
	//       "default": "false",
	//       "description": "If set, this will succeed when retrieving a deleted reply.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "replyId": {
	//       "description": "The ID of the reply.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/comments/{commentId}/replies/{replyId}",
	//   "response": {
	//     "$ref": "CommentReply"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.replies.insert":

type RepliesInsertCall struct {
	s            *Service
	fileId       string
	commentId    string
	commentreply *CommentReply
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Insert: Creates a new reply to the given comment.
func (r *RepliesService) Insert(fileId string, commentId string, commentreply *CommentReply) *RepliesInsertCall {
	c := &RepliesInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.commentId = commentId
	c.commentreply = commentreply
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RepliesInsertCall) Fields(s ...googleapi.Field) *RepliesInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RepliesInsertCall) Context(ctx context.Context) *RepliesInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *RepliesInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.commentreply)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/comments/{commentId}/replies")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":    c.fileId,
		"commentId": c.commentId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.replies.insert" call.
// Exactly one of *CommentReply or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CommentReply.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *RepliesInsertCall) Do() (*CommentReply, error) {
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
	ret := &CommentReply{
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
	//   "description": "Creates a new reply to the given comment.",
	//   "httpMethod": "POST",
	//   "id": "drive.replies.insert",
	//   "parameterOrder": [
	//     "fileId",
	//     "commentId"
	//   ],
	//   "parameters": {
	//     "commentId": {
	//       "description": "The ID of the comment.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/comments/{commentId}/replies",
	//   "request": {
	//     "$ref": "CommentReply"
	//   },
	//   "response": {
	//     "$ref": "CommentReply"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.replies.list":

type RepliesListCall struct {
	s         *Service
	fileId    string
	commentId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// List: Lists all of the replies to a comment.
func (r *RepliesService) List(fileId string, commentId string) *RepliesListCall {
	c := &RepliesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.commentId = commentId
	return c
}

// IncludeDeleted sets the optional parameter "includeDeleted": If set,
// all replies, including deleted replies (with content stripped) will
// be returned.
func (c *RepliesListCall) IncludeDeleted(includeDeleted bool) *RepliesListCall {
	c.opt_["includeDeleted"] = includeDeleted
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of replies to include in the response, used for paging.
func (c *RepliesListCall) MaxResults(maxResults int64) *RepliesListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The continuation
// token, used to page through large result sets. To get the next page
// of results, set this parameter to the value of "nextPageToken" from
// the previous response.
func (c *RepliesListCall) PageToken(pageToken string) *RepliesListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RepliesListCall) Fields(s ...googleapi.Field) *RepliesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *RepliesListCall) IfNoneMatch(entityTag string) *RepliesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RepliesListCall) Context(ctx context.Context) *RepliesListCall {
	c.ctx_ = ctx
	return c
}

func (c *RepliesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["includeDeleted"]; ok {
		params.Set("includeDeleted", fmt.Sprintf("%v", v))
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/comments/{commentId}/replies")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":    c.fileId,
		"commentId": c.commentId,
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

// Do executes the "drive.replies.list" call.
// Exactly one of *CommentReplyList or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *CommentReplyList.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *RepliesListCall) Do() (*CommentReplyList, error) {
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
	ret := &CommentReplyList{
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
	//   "description": "Lists all of the replies to a comment.",
	//   "httpMethod": "GET",
	//   "id": "drive.replies.list",
	//   "parameterOrder": [
	//     "fileId",
	//     "commentId"
	//   ],
	//   "parameters": {
	//     "commentId": {
	//       "description": "The ID of the comment.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "includeDeleted": {
	//       "default": "false",
	//       "description": "If set, all replies, including deleted replies (with content stripped) will be returned.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "maxResults": {
	//       "default": "20",
	//       "description": "The maximum number of replies to include in the response, used for paging.",
	//       "format": "int32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The continuation token, used to page through large result sets. To get the next page of results, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/comments/{commentId}/replies",
	//   "response": {
	//     "$ref": "CommentReplyList"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.replies.patch":

type RepliesPatchCall struct {
	s            *Service
	fileId       string
	commentId    string
	replyId      string
	commentreply *CommentReply
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Patch: Updates an existing reply. This method supports patch
// semantics.
func (r *RepliesService) Patch(fileId string, commentId string, replyId string, commentreply *CommentReply) *RepliesPatchCall {
	c := &RepliesPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.commentId = commentId
	c.replyId = replyId
	c.commentreply = commentreply
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RepliesPatchCall) Fields(s ...googleapi.Field) *RepliesPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RepliesPatchCall) Context(ctx context.Context) *RepliesPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *RepliesPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.commentreply)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/comments/{commentId}/replies/{replyId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":    c.fileId,
		"commentId": c.commentId,
		"replyId":   c.replyId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.replies.patch" call.
// Exactly one of *CommentReply or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CommentReply.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *RepliesPatchCall) Do() (*CommentReply, error) {
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
	ret := &CommentReply{
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
	//   "description": "Updates an existing reply. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "drive.replies.patch",
	//   "parameterOrder": [
	//     "fileId",
	//     "commentId",
	//     "replyId"
	//   ],
	//   "parameters": {
	//     "commentId": {
	//       "description": "The ID of the comment.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "replyId": {
	//       "description": "The ID of the reply.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/comments/{commentId}/replies/{replyId}",
	//   "request": {
	//     "$ref": "CommentReply"
	//   },
	//   "response": {
	//     "$ref": "CommentReply"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.replies.update":

type RepliesUpdateCall struct {
	s            *Service
	fileId       string
	commentId    string
	replyId      string
	commentreply *CommentReply
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Update: Updates an existing reply.
func (r *RepliesService) Update(fileId string, commentId string, replyId string, commentreply *CommentReply) *RepliesUpdateCall {
	c := &RepliesUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.commentId = commentId
	c.replyId = replyId
	c.commentreply = commentreply
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RepliesUpdateCall) Fields(s ...googleapi.Field) *RepliesUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RepliesUpdateCall) Context(ctx context.Context) *RepliesUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *RepliesUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.commentreply)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/comments/{commentId}/replies/{replyId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":    c.fileId,
		"commentId": c.commentId,
		"replyId":   c.replyId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.replies.update" call.
// Exactly one of *CommentReply or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CommentReply.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *RepliesUpdateCall) Do() (*CommentReply, error) {
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
	ret := &CommentReply{
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
	//   "description": "Updates an existing reply.",
	//   "httpMethod": "PUT",
	//   "id": "drive.replies.update",
	//   "parameterOrder": [
	//     "fileId",
	//     "commentId",
	//     "replyId"
	//   ],
	//   "parameters": {
	//     "commentId": {
	//       "description": "The ID of the comment.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "replyId": {
	//       "description": "The ID of the reply.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/comments/{commentId}/replies/{replyId}",
	//   "request": {
	//     "$ref": "CommentReply"
	//   },
	//   "response": {
	//     "$ref": "CommentReply"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.revisions.delete":

type RevisionsDeleteCall struct {
	s          *Service
	fileId     string
	revisionId string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// Delete: Removes a revision.
func (r *RevisionsService) Delete(fileId string, revisionId string) *RevisionsDeleteCall {
	c := &RevisionsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.revisionId = revisionId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RevisionsDeleteCall) Fields(s ...googleapi.Field) *RevisionsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RevisionsDeleteCall) Context(ctx context.Context) *RevisionsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *RevisionsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/revisions/{revisionId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":     c.fileId,
		"revisionId": c.revisionId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.revisions.delete" call.
func (c *RevisionsDeleteCall) Do() error {
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
	//   "description": "Removes a revision.",
	//   "httpMethod": "DELETE",
	//   "id": "drive.revisions.delete",
	//   "parameterOrder": [
	//     "fileId",
	//     "revisionId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "revisionId": {
	//       "description": "The ID of the revision.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/revisions/{revisionId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.revisions.get":

type RevisionsGetCall struct {
	s          *Service
	fileId     string
	revisionId string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// Get: Gets a specific revision.
func (r *RevisionsService) Get(fileId string, revisionId string) *RevisionsGetCall {
	c := &RevisionsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.revisionId = revisionId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RevisionsGetCall) Fields(s ...googleapi.Field) *RevisionsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *RevisionsGetCall) IfNoneMatch(entityTag string) *RevisionsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RevisionsGetCall) Context(ctx context.Context) *RevisionsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *RevisionsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/revisions/{revisionId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":     c.fileId,
		"revisionId": c.revisionId,
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

// Do executes the "drive.revisions.get" call.
// Exactly one of *Revision or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Revision.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *RevisionsGetCall) Do() (*Revision, error) {
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
	ret := &Revision{
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
	//   "description": "Gets a specific revision.",
	//   "httpMethod": "GET",
	//   "id": "drive.revisions.get",
	//   "parameterOrder": [
	//     "fileId",
	//     "revisionId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "revisionId": {
	//       "description": "The ID of the revision.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/revisions/{revisionId}",
	//   "response": {
	//     "$ref": "Revision"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.revisions.list":

type RevisionsListCall struct {
	s      *Service
	fileId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// List: Lists a file's revisions.
func (r *RevisionsService) List(fileId string) *RevisionsListCall {
	c := &RevisionsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RevisionsListCall) Fields(s ...googleapi.Field) *RevisionsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *RevisionsListCall) IfNoneMatch(entityTag string) *RevisionsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RevisionsListCall) Context(ctx context.Context) *RevisionsListCall {
	c.ctx_ = ctx
	return c
}

func (c *RevisionsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/revisions")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId": c.fileId,
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

// Do executes the "drive.revisions.list" call.
// Exactly one of *RevisionList or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *RevisionList.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *RevisionsListCall) Do() (*RevisionList, error) {
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
	ret := &RevisionList{
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
	//   "description": "Lists a file's revisions.",
	//   "httpMethod": "GET",
	//   "id": "drive.revisions.list",
	//   "parameterOrder": [
	//     "fileId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID of the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/revisions",
	//   "response": {
	//     "$ref": "RevisionList"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file",
	//     "https://www.googleapis.com/auth/drive.metadata",
	//     "https://www.googleapis.com/auth/drive.metadata.readonly",
	//     "https://www.googleapis.com/auth/drive.photos.readonly",
	//     "https://www.googleapis.com/auth/drive.readonly"
	//   ]
	// }

}

// method id "drive.revisions.patch":

type RevisionsPatchCall struct {
	s          *Service
	fileId     string
	revisionId string
	revision   *Revision
	opt_       map[string]interface{}
	ctx_       context.Context
}

// Patch: Updates a revision. This method supports patch semantics.
func (r *RevisionsService) Patch(fileId string, revisionId string, revision *Revision) *RevisionsPatchCall {
	c := &RevisionsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.revisionId = revisionId
	c.revision = revision
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RevisionsPatchCall) Fields(s ...googleapi.Field) *RevisionsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RevisionsPatchCall) Context(ctx context.Context) *RevisionsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *RevisionsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.revision)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/revisions/{revisionId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":     c.fileId,
		"revisionId": c.revisionId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.revisions.patch" call.
// Exactly one of *Revision or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Revision.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *RevisionsPatchCall) Do() (*Revision, error) {
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
	ret := &Revision{
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
	//   "description": "Updates a revision. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "drive.revisions.patch",
	//   "parameterOrder": [
	//     "fileId",
	//     "revisionId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID for the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "revisionId": {
	//       "description": "The ID for the revision.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/revisions/{revisionId}",
	//   "request": {
	//     "$ref": "Revision"
	//   },
	//   "response": {
	//     "$ref": "Revision"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}

// method id "drive.revisions.update":

type RevisionsUpdateCall struct {
	s          *Service
	fileId     string
	revisionId string
	revision   *Revision
	opt_       map[string]interface{}
	ctx_       context.Context
}

// Update: Updates a revision.
func (r *RevisionsService) Update(fileId string, revisionId string, revision *Revision) *RevisionsUpdateCall {
	c := &RevisionsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.fileId = fileId
	c.revisionId = revisionId
	c.revision = revision
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *RevisionsUpdateCall) Fields(s ...googleapi.Field) *RevisionsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *RevisionsUpdateCall) Context(ctx context.Context) *RevisionsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *RevisionsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.revision)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "files/{fileId}/revisions/{revisionId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"fileId":     c.fileId,
		"revisionId": c.revisionId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "drive.revisions.update" call.
// Exactly one of *Revision or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Revision.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *RevisionsUpdateCall) Do() (*Revision, error) {
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
	ret := &Revision{
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
	//   "description": "Updates a revision.",
	//   "httpMethod": "PUT",
	//   "id": "drive.revisions.update",
	//   "parameterOrder": [
	//     "fileId",
	//     "revisionId"
	//   ],
	//   "parameters": {
	//     "fileId": {
	//       "description": "The ID for the file.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "revisionId": {
	//       "description": "The ID for the revision.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "files/{fileId}/revisions/{revisionId}",
	//   "request": {
	//     "$ref": "Revision"
	//   },
	//   "response": {
	//     "$ref": "Revision"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/drive",
	//     "https://www.googleapis.com/auth/drive.appdata",
	//     "https://www.googleapis.com/auth/drive.file"
	//   ]
	// }

}
