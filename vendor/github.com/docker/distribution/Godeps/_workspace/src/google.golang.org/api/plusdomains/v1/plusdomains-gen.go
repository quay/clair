// Package plusdomains provides access to the Google+ Domains API.
//
// See https://developers.google.com/+/domains/
//
// Usage example:
//
//   import "google.golang.org/api/plusdomains/v1"
//   ...
//   plusdomainsService, err := plusdomains.New(oauthHttpClient)
package plusdomains // import "google.golang.org/api/plusdomains/v1"

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

const apiId = "plusDomains:v1"
const apiName = "plusDomains"
const apiVersion = "v1"
const basePath = "https://www.googleapis.com/plusDomains/v1/"

// OAuth2 scopes used by this API.
const (
	// View your circles and the people and pages in them
	PlusCirclesReadScope = "https://www.googleapis.com/auth/plus.circles.read"

	// Manage your circles and add people and pages. People and pages you
	// add to your circles will be notified. Others may see this information
	// publicly. People you add to circles can use Hangouts with you.
	PlusCirclesWriteScope = "https://www.googleapis.com/auth/plus.circles.write"

	// Know your basic profile info and list of people in your circles.
	PlusLoginScope = "https://www.googleapis.com/auth/plus.login"

	// Know who you are on Google
	PlusMeScope = "https://www.googleapis.com/auth/plus.me"

	// Send your photos and videos to Google+
	PlusMediaUploadScope = "https://www.googleapis.com/auth/plus.media.upload"

	// View your own Google+ profile and profiles visible to you
	PlusProfilesReadScope = "https://www.googleapis.com/auth/plus.profiles.read"

	// View your Google+ posts, comments, and stream
	PlusStreamReadScope = "https://www.googleapis.com/auth/plus.stream.read"

	// Manage your Google+ posts, comments, and stream
	PlusStreamWriteScope = "https://www.googleapis.com/auth/plus.stream.write"

	// View your email address
	UserinfoEmailScope = "https://www.googleapis.com/auth/userinfo.email"

	// View your basic profile info
	UserinfoProfileScope = "https://www.googleapis.com/auth/userinfo.profile"
)

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.Activities = NewActivitiesService(s)
	s.Audiences = NewAudiencesService(s)
	s.Circles = NewCirclesService(s)
	s.Comments = NewCommentsService(s)
	s.Media = NewMediaService(s)
	s.People = NewPeopleService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	Activities *ActivitiesService

	Audiences *AudiencesService

	Circles *CirclesService

	Comments *CommentsService

	Media *MediaService

	People *PeopleService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewActivitiesService(s *Service) *ActivitiesService {
	rs := &ActivitiesService{s: s}
	return rs
}

type ActivitiesService struct {
	s *Service
}

func NewAudiencesService(s *Service) *AudiencesService {
	rs := &AudiencesService{s: s}
	return rs
}

type AudiencesService struct {
	s *Service
}

func NewCirclesService(s *Service) *CirclesService {
	rs := &CirclesService{s: s}
	return rs
}

type CirclesService struct {
	s *Service
}

func NewCommentsService(s *Service) *CommentsService {
	rs := &CommentsService{s: s}
	return rs
}

type CommentsService struct {
	s *Service
}

func NewMediaService(s *Service) *MediaService {
	rs := &MediaService{s: s}
	return rs
}

type MediaService struct {
	s *Service
}

func NewPeopleService(s *Service) *PeopleService {
	rs := &PeopleService{s: s}
	return rs
}

type PeopleService struct {
	s *Service
}

type Acl struct {
	// Description: Description of the access granted, suitable for display.
	Description string `json:"description,omitempty"`

	// DomainRestricted: Whether access is restricted to the domain.
	DomainRestricted bool `json:"domainRestricted,omitempty"`

	// Items: The list of access entries.
	Items []*PlusDomainsAclentryResource `json:"items,omitempty"`

	// Kind: Identifies this resource as a collection of access controls.
	// Value: "plus#acl".
	Kind string `json:"kind,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Description") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Acl) MarshalJSON() ([]byte, error) {
	type noMethod Acl
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type Activity struct {
	// Access: Identifies who has access to see this activity.
	Access *Acl `json:"access,omitempty"`

	// Actor: The person who performed this activity.
	Actor *ActivityActor `json:"actor,omitempty"`

	// Address: Street address where this activity occurred.
	Address string `json:"address,omitempty"`

	// Annotation: Additional content added by the person who shared this
	// activity, applicable only when resharing an activity.
	Annotation string `json:"annotation,omitempty"`

	// CrosspostSource: If this activity is a crosspost from another system,
	// this property specifies the ID of the original activity.
	CrosspostSource string `json:"crosspostSource,omitempty"`

	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Geocode: Latitude and longitude where this activity occurred. Format
	// is latitude followed by longitude, space separated.
	Geocode string `json:"geocode,omitempty"`

	// Id: The ID of this activity.
	Id string `json:"id,omitempty"`

	// Kind: Identifies this resource as an activity. Value:
	// "plus#activity".
	Kind string `json:"kind,omitempty"`

	// Location: The location where this activity occurred.
	Location *Place `json:"location,omitempty"`

	// Object: The object of this activity.
	Object *ActivityObject `json:"object,omitempty"`

	// PlaceId: ID of the place where this activity occurred.
	PlaceId string `json:"placeId,omitempty"`

	// PlaceName: Name of the place where this activity occurred.
	PlaceName string `json:"placeName,omitempty"`

	// Provider: The service provider that initially published this
	// activity.
	Provider *ActivityProvider `json:"provider,omitempty"`

	// Published: The time at which this activity was initially published.
	// Formatted as an RFC 3339 timestamp.
	Published string `json:"published,omitempty"`

	// Radius: Radius, in meters, of the region where this activity
	// occurred, centered at the latitude and longitude identified in
	// geocode.
	Radius string `json:"radius,omitempty"`

	// Title: Title of this activity.
	Title string `json:"title,omitempty"`

	// Updated: The time at which this activity was last updated. Formatted
	// as an RFC 3339 timestamp.
	Updated string `json:"updated,omitempty"`

	// Url: The link to this activity.
	Url string `json:"url,omitempty"`

	// Verb: This activity's verb, which indicates the action that was
	// performed. Possible values include, but are not limited to, the
	// following values:
	// - "post" - Publish content to the stream.
	// - "share" - Reshare an activity.
	Verb string `json:"verb,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Access") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Activity) MarshalJSON() ([]byte, error) {
	type noMethod Activity
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityActor: The person who performed this activity.
type ActivityActor struct {
	// ClientSpecificActorInfo: Actor info specific to particular clients.
	ClientSpecificActorInfo *ActivityActorClientSpecificActorInfo `json:"clientSpecificActorInfo,omitempty"`

	// DisplayName: The name of the actor, suitable for display.
	DisplayName string `json:"displayName,omitempty"`

	// Id: The ID of the actor's Person resource.
	Id string `json:"id,omitempty"`

	// Image: The image representation of the actor.
	Image *ActivityActorImage `json:"image,omitempty"`

	// Name: An object representation of the individual components of name.
	Name *ActivityActorName `json:"name,omitempty"`

	// Url: The link to the actor's Google profile.
	Url string `json:"url,omitempty"`

	// Verification: Verification status of actor.
	Verification *ActivityActorVerification `json:"verification,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "ClientSpecificActorInfo") to unconditionally include in API
	// requests. By default, fields with empty values are omitted from API
	// requests. However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityActor) MarshalJSON() ([]byte, error) {
	type noMethod ActivityActor
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityActorClientSpecificActorInfo: Actor info specific to
// particular clients.
type ActivityActorClientSpecificActorInfo struct {
	// YoutubeActorInfo: Actor info specific to YouTube clients.
	YoutubeActorInfo *ActivityActorClientSpecificActorInfoYoutubeActorInfo `json:"youtubeActorInfo,omitempty"`

	// ForceSendFields is a list of field names (e.g. "YoutubeActorInfo") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityActorClientSpecificActorInfo) MarshalJSON() ([]byte, error) {
	type noMethod ActivityActorClientSpecificActorInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityActorClientSpecificActorInfoYoutubeActorInfo: Actor info
// specific to YouTube clients.
type ActivityActorClientSpecificActorInfoYoutubeActorInfo struct {
	// ChannelId: ID of the YouTube channel owned by the Actor.
	ChannelId string `json:"channelId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityActorClientSpecificActorInfoYoutubeActorInfo) MarshalJSON() ([]byte, error) {
	type noMethod ActivityActorClientSpecificActorInfoYoutubeActorInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityActorImage: The image representation of the actor.
type ActivityActorImage struct {
	// Url: The URL of the actor's profile photo. To resize the image and
	// crop it to a square, append the query string ?sz=x, where x is the
	// dimension in pixels of each side.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Url") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityActorImage) MarshalJSON() ([]byte, error) {
	type noMethod ActivityActorImage
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityActorName: An object representation of the individual
// components of name.
type ActivityActorName struct {
	// FamilyName: The family name ("last name") of the actor.
	FamilyName string `json:"familyName,omitempty"`

	// GivenName: The given name ("first name") of the actor.
	GivenName string `json:"givenName,omitempty"`

	// ForceSendFields is a list of field names (e.g. "FamilyName") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityActorName) MarshalJSON() ([]byte, error) {
	type noMethod ActivityActorName
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityActorVerification: Verification status of actor.
type ActivityActorVerification struct {
	// AdHocVerified: Verification for one-time or manual processes.
	AdHocVerified string `json:"adHocVerified,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AdHocVerified") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityActorVerification) MarshalJSON() ([]byte, error) {
	type noMethod ActivityActorVerification
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObject: The object of this activity.
type ActivityObject struct {
	// Actor: If this activity's object is itself another activity, such as
	// when a person reshares an activity, this property specifies the
	// original activity's actor.
	Actor *ActivityObjectActor `json:"actor,omitempty"`

	// Attachments: The media objects attached to this activity.
	Attachments []*ActivityObjectAttachments `json:"attachments,omitempty"`

	// Content: The HTML-formatted content, which is suitable for display.
	Content string `json:"content,omitempty"`

	// Id: The ID of the object. When resharing an activity, this is the ID
	// of the activity that is being reshared.
	Id string `json:"id,omitempty"`

	// ObjectType: The type of the object. Possible values include, but are
	// not limited to, the following values:
	// - "note" - Textual content.
	// - "activity" - A Google+ activity.
	ObjectType string `json:"objectType,omitempty"`

	// OriginalContent: The content (text) as provided by the author, which
	// is stored without any HTML formatting. When creating or updating an
	// activity, this value must be supplied as plain text in the request.
	OriginalContent string `json:"originalContent,omitempty"`

	// Plusoners: People who +1'd this activity.
	Plusoners *ActivityObjectPlusoners `json:"plusoners,omitempty"`

	// Replies: Comments in reply to this activity.
	Replies *ActivityObjectReplies `json:"replies,omitempty"`

	// Resharers: People who reshared this activity.
	Resharers *ActivityObjectResharers `json:"resharers,omitempty"`

	// StatusForViewer: Status of the activity as seen by the viewer.
	StatusForViewer *ActivityObjectStatusForViewer `json:"statusForViewer,omitempty"`

	// Url: The URL that points to the linked resource.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Actor") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObject) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObject
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObjectActor: If this activity's object is itself another
// activity, such as when a person reshares an activity, this property
// specifies the original activity's actor.
type ActivityObjectActor struct {
	// ClientSpecificActorInfo: Actor info specific to particular clients.
	ClientSpecificActorInfo *ActivityObjectActorClientSpecificActorInfo `json:"clientSpecificActorInfo,omitempty"`

	// DisplayName: The original actor's name, which is suitable for
	// display.
	DisplayName string `json:"displayName,omitempty"`

	// Id: ID of the original actor.
	Id string `json:"id,omitempty"`

	// Image: The image representation of the original actor.
	Image *ActivityObjectActorImage `json:"image,omitempty"`

	// Url: A link to the original actor's Google profile.
	Url string `json:"url,omitempty"`

	// Verification: Verification status of actor.
	Verification *ActivityObjectActorVerification `json:"verification,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "ClientSpecificActorInfo") to unconditionally include in API
	// requests. By default, fields with empty values are omitted from API
	// requests. However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectActor) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectActor
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObjectActorClientSpecificActorInfo: Actor info specific to
// particular clients.
type ActivityObjectActorClientSpecificActorInfo struct {
	// YoutubeActorInfo: Actor info specific to YouTube clients.
	YoutubeActorInfo *ActivityObjectActorClientSpecificActorInfoYoutubeActorInfo `json:"youtubeActorInfo,omitempty"`

	// ForceSendFields is a list of field names (e.g. "YoutubeActorInfo") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectActorClientSpecificActorInfo) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectActorClientSpecificActorInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObjectActorClientSpecificActorInfoYoutubeActorInfo: Actor
// info specific to YouTube clients.
type ActivityObjectActorClientSpecificActorInfoYoutubeActorInfo struct {
	// ChannelId: ID of the YouTube channel owned by the Actor.
	ChannelId string `json:"channelId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectActorClientSpecificActorInfoYoutubeActorInfo) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectActorClientSpecificActorInfoYoutubeActorInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObjectActorImage: The image representation of the original
// actor.
type ActivityObjectActorImage struct {
	// Url: A URL that points to a thumbnail photo of the original actor.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Url") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectActorImage) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectActorImage
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObjectActorVerification: Verification status of actor.
type ActivityObjectActorVerification struct {
	// AdHocVerified: Verification for one-time or manual processes.
	AdHocVerified string `json:"adHocVerified,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AdHocVerified") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectActorVerification) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectActorVerification
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ActivityObjectAttachments struct {
	// Content: If the attachment is an article, this property contains a
	// snippet of text from the article. It can also include descriptions
	// for other types.
	Content string `json:"content,omitempty"`

	// DisplayName: The title of the attachment, such as a photo caption or
	// an article title.
	DisplayName string `json:"displayName,omitempty"`

	// Embed: If the attachment is a video, the embeddable link.
	Embed *ActivityObjectAttachmentsEmbed `json:"embed,omitempty"`

	// FullImage: The full image URL for photo attachments.
	FullImage *ActivityObjectAttachmentsFullImage `json:"fullImage,omitempty"`

	// Id: The ID of the attachment.
	Id string `json:"id,omitempty"`

	// Image: The preview image for photos or videos.
	Image *ActivityObjectAttachmentsImage `json:"image,omitempty"`

	// ObjectType: The type of media object. Possible values include, but
	// are not limited to, the following values:
	// - "photo" - A photo.
	// - "album" - A photo album.
	// - "video" - A video.
	// - "article" - An article, specified by a link.
	ObjectType string `json:"objectType,omitempty"`

	// PreviewThumbnails: When previewing, these are the optional thumbnails
	// for the post. When posting an article, choose one by setting the
	// attachment.image.url property. If you don't choose one, one will be
	// chosen for you.
	PreviewThumbnails []*ActivityObjectAttachmentsPreviewThumbnails `json:"previewThumbnails,omitempty"`

	// Thumbnails: If the attachment is an album, this property is a list of
	// potential additional thumbnails from the album.
	Thumbnails []*ActivityObjectAttachmentsThumbnails `json:"thumbnails,omitempty"`

	// Url: The link to the attachment, which should be of type text/html.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Content") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectAttachments) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectAttachments
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObjectAttachmentsEmbed: If the attachment is a video, the
// embeddable link.
type ActivityObjectAttachmentsEmbed struct {
	// Type: Media type of the link.
	Type string `json:"type,omitempty"`

	// Url: URL of the link.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Type") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectAttachmentsEmbed) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectAttachmentsEmbed
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObjectAttachmentsFullImage: The full image URL for photo
// attachments.
type ActivityObjectAttachmentsFullImage struct {
	// Height: The height, in pixels, of the linked resource.
	Height int64 `json:"height,omitempty"`

	// Type: Media type of the link.
	Type string `json:"type,omitempty"`

	// Url: URL of the image.
	Url string `json:"url,omitempty"`

	// Width: The width, in pixels, of the linked resource.
	Width int64 `json:"width,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Height") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectAttachmentsFullImage) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectAttachmentsFullImage
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObjectAttachmentsImage: The preview image for photos or
// videos.
type ActivityObjectAttachmentsImage struct {
	// Height: The height, in pixels, of the linked resource.
	Height int64 `json:"height,omitempty"`

	// Type: Media type of the link.
	Type string `json:"type,omitempty"`

	// Url: Image URL.
	Url string `json:"url,omitempty"`

	// Width: The width, in pixels, of the linked resource.
	Width int64 `json:"width,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Height") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectAttachmentsImage) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectAttachmentsImage
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ActivityObjectAttachmentsPreviewThumbnails struct {
	// Url: URL of the thumbnail image.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Url") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectAttachmentsPreviewThumbnails) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectAttachmentsPreviewThumbnails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ActivityObjectAttachmentsThumbnails struct {
	// Description: Potential name of the thumbnail.
	Description string `json:"description,omitempty"`

	// Image: Image resource.
	Image *ActivityObjectAttachmentsThumbnailsImage `json:"image,omitempty"`

	// Url: URL of the webpage containing the image.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Description") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectAttachmentsThumbnails) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectAttachmentsThumbnails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObjectAttachmentsThumbnailsImage: Image resource.
type ActivityObjectAttachmentsThumbnailsImage struct {
	// Height: The height, in pixels, of the linked resource.
	Height int64 `json:"height,omitempty"`

	// Type: Media type of the link.
	Type string `json:"type,omitempty"`

	// Url: Image url.
	Url string `json:"url,omitempty"`

	// Width: The width, in pixels, of the linked resource.
	Width int64 `json:"width,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Height") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectAttachmentsThumbnailsImage) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectAttachmentsThumbnailsImage
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObjectPlusoners: People who +1'd this activity.
type ActivityObjectPlusoners struct {
	// SelfLink: The URL for the collection of people who +1'd this
	// activity.
	SelfLink string `json:"selfLink,omitempty"`

	// TotalItems: Total number of people who +1'd this activity.
	TotalItems int64 `json:"totalItems,omitempty"`

	// ForceSendFields is a list of field names (e.g. "SelfLink") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectPlusoners) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectPlusoners
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObjectReplies: Comments in reply to this activity.
type ActivityObjectReplies struct {
	// SelfLink: The URL for the collection of comments in reply to this
	// activity.
	SelfLink string `json:"selfLink,omitempty"`

	// TotalItems: Total number of comments on this activity.
	TotalItems int64 `json:"totalItems,omitempty"`

	// ForceSendFields is a list of field names (e.g. "SelfLink") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectReplies) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectReplies
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObjectResharers: People who reshared this activity.
type ActivityObjectResharers struct {
	// SelfLink: The URL for the collection of resharers.
	SelfLink string `json:"selfLink,omitempty"`

	// TotalItems: Total number of people who reshared this activity.
	TotalItems int64 `json:"totalItems,omitempty"`

	// ForceSendFields is a list of field names (e.g. "SelfLink") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectResharers) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectResharers
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityObjectStatusForViewer: Status of the activity as seen by the
// viewer.
type ActivityObjectStatusForViewer struct {
	// CanComment: Whether the viewer can comment on the activity.
	CanComment bool `json:"canComment,omitempty"`

	// CanPlusone: Whether the viewer can +1 the activity.
	CanPlusone bool `json:"canPlusone,omitempty"`

	// CanUpdate: Whether the viewer can edit or delete the activity.
	CanUpdate bool `json:"canUpdate,omitempty"`

	// IsPlusOned: Whether the viewer has +1'd the activity.
	IsPlusOned bool `json:"isPlusOned,omitempty"`

	// ResharingDisabled: Whether reshares are disabled for the activity.
	ResharingDisabled bool `json:"resharingDisabled,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CanComment") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityObjectStatusForViewer) MarshalJSON() ([]byte, error) {
	type noMethod ActivityObjectStatusForViewer
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ActivityProvider: The service provider that initially published this
// activity.
type ActivityProvider struct {
	// Title: Name of the service provider.
	Title string `json:"title,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Title") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ActivityProvider) MarshalJSON() ([]byte, error) {
	type noMethod ActivityProvider
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ActivityFeed struct {
	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Id: The ID of this collection of activities. Deprecated.
	Id string `json:"id,omitempty"`

	// Items: The activities in this page of results.
	Items []*Activity `json:"items,omitempty"`

	// Kind: Identifies this resource as a collection of activities. Value:
	// "plus#activityFeed".
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to the next page of activities.
	NextLink string `json:"nextLink,omitempty"`

	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// SelfLink: Link to this activity resource.
	SelfLink string `json:"selfLink,omitempty"`

	// Title: The title of this collection of activities, which is a
	// truncated portion of the content.
	Title string `json:"title,omitempty"`

	// Updated: The time at which this collection of activities was last
	// updated. Formatted as an RFC 3339 timestamp.
	Updated string `json:"updated,omitempty"`

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

func (s *ActivityFeed) MarshalJSON() ([]byte, error) {
	type noMethod ActivityFeed
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type Audience struct {
	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Item: The access control list entry.
	Item *PlusDomainsAclentryResource `json:"item,omitempty"`

	// Kind: Identifies this resource as an audience. Value:
	// "plus#audience".
	Kind string `json:"kind,omitempty"`

	// MemberCount: The number of people in this circle. This only applies
	// if entity_type is CIRCLE.
	MemberCount int64 `json:"memberCount,omitempty"`

	// Visibility: The circle members' visibility as chosen by the owner of
	// the circle. This only applies for items with "item.type" equals
	// "circle". Possible values are:
	// - "public" - Members are visible to the public.
	// - "limited" - Members are visible to a limited audience.
	// - "private" - Members are visible to the owner only.
	Visibility string `json:"visibility,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Etag") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Audience) MarshalJSON() ([]byte, error) {
	type noMethod Audience
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type AudiencesFeed struct {
	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Items: The audiences in this result.
	Items []*Audience `json:"items,omitempty"`

	// Kind: Identifies this resource as a collection of audiences. Value:
	// "plus#audienceFeed".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// TotalItems: The total number of ACL entries. The number of entries in
	// this response may be smaller due to paging.
	TotalItems int64 `json:"totalItems,omitempty"`

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

func (s *AudiencesFeed) MarshalJSON() ([]byte, error) {
	type noMethod AudiencesFeed
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type Circle struct {
	// Description: The description of this circle.
	Description string `json:"description,omitempty"`

	// DisplayName: The circle name.
	DisplayName string `json:"displayName,omitempty"`

	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Id: The ID of the circle.
	Id string `json:"id,omitempty"`

	// Kind: Identifies this resource as a circle. Value: "plus#circle".
	Kind string `json:"kind,omitempty"`

	// People: The people in this circle.
	People *CirclePeople `json:"people,omitempty"`

	// SelfLink: Link to this circle resource
	SelfLink string `json:"selfLink,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Description") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Circle) MarshalJSON() ([]byte, error) {
	type noMethod Circle
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CirclePeople: The people in this circle.
type CirclePeople struct {
	// TotalItems: The total number of people in this circle.
	TotalItems int64 `json:"totalItems,omitempty"`

	// ForceSendFields is a list of field names (e.g. "TotalItems") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CirclePeople) MarshalJSON() ([]byte, error) {
	type noMethod CirclePeople
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type CircleFeed struct {
	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Items: The circles in this page of results.
	Items []*Circle `json:"items,omitempty"`

	// Kind: Identifies this resource as a collection of circles. Value:
	// "plus#circleFeed".
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to the next page of circles.
	NextLink string `json:"nextLink,omitempty"`

	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// SelfLink: Link to this page of circles.
	SelfLink string `json:"selfLink,omitempty"`

	// Title: The title of this list of resources.
	Title string `json:"title,omitempty"`

	// TotalItems: The total number of circles. The number of circles in
	// this response may be smaller due to paging.
	TotalItems int64 `json:"totalItems,omitempty"`

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

func (s *CircleFeed) MarshalJSON() ([]byte, error) {
	type noMethod CircleFeed
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type Comment struct {
	// Actor: The person who posted this comment.
	Actor *CommentActor `json:"actor,omitempty"`

	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Id: The ID of this comment.
	Id string `json:"id,omitempty"`

	// InReplyTo: The activity this comment replied to.
	InReplyTo []*CommentInReplyTo `json:"inReplyTo,omitempty"`

	// Kind: Identifies this resource as a comment. Value: "plus#comment".
	Kind string `json:"kind,omitempty"`

	// Object: The object of this comment.
	Object *CommentObject `json:"object,omitempty"`

	// Plusoners: People who +1'd this comment.
	Plusoners *CommentPlusoners `json:"plusoners,omitempty"`

	// Published: The time at which this comment was initially published.
	// Formatted as an RFC 3339 timestamp.
	Published string `json:"published,omitempty"`

	// SelfLink: Link to this comment resource.
	SelfLink string `json:"selfLink,omitempty"`

	// Updated: The time at which this comment was last updated. Formatted
	// as an RFC 3339 timestamp.
	Updated string `json:"updated,omitempty"`

	// Verb: This comment's verb, indicating what action was performed.
	// Possible values are:
	// - "post" - Publish content to the stream.
	Verb string `json:"verb,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Actor") to
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

// CommentActor: The person who posted this comment.
type CommentActor struct {
	// ClientSpecificActorInfo: Actor info specific to particular clients.
	ClientSpecificActorInfo *CommentActorClientSpecificActorInfo `json:"clientSpecificActorInfo,omitempty"`

	// DisplayName: The name of this actor, suitable for display.
	DisplayName string `json:"displayName,omitempty"`

	// Id: The ID of the actor.
	Id string `json:"id,omitempty"`

	// Image: The image representation of this actor.
	Image *CommentActorImage `json:"image,omitempty"`

	// Url: A link to the Person resource for this actor.
	Url string `json:"url,omitempty"`

	// Verification: Verification status of actor.
	Verification *CommentActorVerification `json:"verification,omitempty"`

	// ForceSendFields is a list of field names (e.g.
	// "ClientSpecificActorInfo") to unconditionally include in API
	// requests. By default, fields with empty values are omitted from API
	// requests. However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CommentActor) MarshalJSON() ([]byte, error) {
	type noMethod CommentActor
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentActorClientSpecificActorInfo: Actor info specific to
// particular clients.
type CommentActorClientSpecificActorInfo struct {
	// YoutubeActorInfo: Actor info specific to YouTube clients.
	YoutubeActorInfo *CommentActorClientSpecificActorInfoYoutubeActorInfo `json:"youtubeActorInfo,omitempty"`

	// ForceSendFields is a list of field names (e.g. "YoutubeActorInfo") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CommentActorClientSpecificActorInfo) MarshalJSON() ([]byte, error) {
	type noMethod CommentActorClientSpecificActorInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentActorClientSpecificActorInfoYoutubeActorInfo: Actor info
// specific to YouTube clients.
type CommentActorClientSpecificActorInfoYoutubeActorInfo struct {
	// ChannelId: ID of the YouTube channel owned by the Actor.
	ChannelId string `json:"channelId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ChannelId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CommentActorClientSpecificActorInfoYoutubeActorInfo) MarshalJSON() ([]byte, error) {
	type noMethod CommentActorClientSpecificActorInfoYoutubeActorInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentActorImage: The image representation of this actor.
type CommentActorImage struct {
	// Url: The URL of the actor's profile photo. To resize the image and
	// crop it to a square, append the query string ?sz=x, where x is the
	// dimension in pixels of each side.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Url") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CommentActorImage) MarshalJSON() ([]byte, error) {
	type noMethod CommentActorImage
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentActorVerification: Verification status of actor.
type CommentActorVerification struct {
	// AdHocVerified: Verification for one-time or manual processes.
	AdHocVerified string `json:"adHocVerified,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AdHocVerified") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CommentActorVerification) MarshalJSON() ([]byte, error) {
	type noMethod CommentActorVerification
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type CommentInReplyTo struct {
	// Id: The ID of the activity.
	Id string `json:"id,omitempty"`

	// Url: The URL of the activity.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CommentInReplyTo) MarshalJSON() ([]byte, error) {
	type noMethod CommentInReplyTo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentObject: The object of this comment.
type CommentObject struct {
	// Content: The HTML-formatted content, suitable for display.
	Content string `json:"content,omitempty"`

	// ObjectType: The object type of this comment. Possible values are:
	// - "comment" - A comment in reply to an activity.
	ObjectType string `json:"objectType,omitempty"`

	// OriginalContent: The content (text) as provided by the author, stored
	// without any HTML formatting. When creating or updating a comment,
	// this value must be supplied as plain text in the request.
	OriginalContent string `json:"originalContent,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Content") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CommentObject) MarshalJSON() ([]byte, error) {
	type noMethod CommentObject
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CommentPlusoners: People who +1'd this comment.
type CommentPlusoners struct {
	// TotalItems: Total number of people who +1'd this comment.
	TotalItems int64 `json:"totalItems,omitempty"`

	// ForceSendFields is a list of field names (e.g. "TotalItems") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CommentPlusoners) MarshalJSON() ([]byte, error) {
	type noMethod CommentPlusoners
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type CommentFeed struct {
	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Id: The ID of this collection of comments.
	Id string `json:"id,omitempty"`

	// Items: The comments in this page of results.
	Items []*Comment `json:"items,omitempty"`

	// Kind: Identifies this resource as a collection of comments. Value:
	// "plus#commentFeed".
	Kind string `json:"kind,omitempty"`

	// NextLink: Link to the next page of activities.
	NextLink string `json:"nextLink,omitempty"`

	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// Title: The title of this collection of comments.
	Title string `json:"title,omitempty"`

	// Updated: The time at which this collection of comments was last
	// updated. Formatted as an RFC 3339 timestamp.
	Updated string `json:"updated,omitempty"`

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

func (s *CommentFeed) MarshalJSON() ([]byte, error) {
	type noMethod CommentFeed
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type Media struct {
	// Author: The person who uploaded this media.
	Author *MediaAuthor `json:"author,omitempty"`

	// DisplayName: The display name for this media.
	DisplayName string `json:"displayName,omitempty"`

	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Exif: Exif information of the media item.
	Exif *MediaExif `json:"exif,omitempty"`

	// Height: The height in pixels of the original image.
	Height int64 `json:"height,omitempty"`

	// Id: ID of this media, which is generated by the API.
	Id string `json:"id,omitempty"`

	// Kind: The type of resource.
	Kind string `json:"kind,omitempty"`

	// MediaCreatedTime: The time at which this media was originally created
	// in UTC. Formatted as an RFC 3339 timestamp that matches this example:
	// 2010-11-25T14:30:27.655Z
	MediaCreatedTime string `json:"mediaCreatedTime,omitempty"`

	// MediaUrl: The URL of this photo or video's still image.
	MediaUrl string `json:"mediaUrl,omitempty"`

	// Published: The time at which this media was uploaded. Formatted as an
	// RFC 3339 timestamp.
	Published string `json:"published,omitempty"`

	// SizeBytes: The size in bytes of this video.
	SizeBytes int64 `json:"sizeBytes,omitempty,string"`

	// Streams: The list of video streams for this video. There might be
	// several different streams available for a single video, either Flash
	// or MPEG, of various sizes
	Streams []*Videostream `json:"streams,omitempty"`

	// Summary: A description, or caption, for this media.
	Summary string `json:"summary,omitempty"`

	// Updated: The time at which this media was last updated. This includes
	// changes to media metadata. Formatted as an RFC 3339 timestamp.
	Updated string `json:"updated,omitempty"`

	// Url: The URL for the page that hosts this media.
	Url string `json:"url,omitempty"`

	// VideoDuration: The duration in milliseconds of this video.
	VideoDuration int64 `json:"videoDuration,omitempty,string"`

	// VideoStatus: The encoding status of this video. Possible values are:
	//
	// - "UPLOADING" - Not all the video bytes have been received.
	// - "PENDING" - Video not yet processed.
	// - "FAILED" - Video processing failed.
	// - "READY" - A single video stream is playable.
	// - "FINAL" - All video streams are playable.
	VideoStatus string `json:"videoStatus,omitempty"`

	// Width: The width in pixels of the original image.
	Width int64 `json:"width,omitempty"`

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

func (s *Media) MarshalJSON() ([]byte, error) {
	type noMethod Media
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// MediaAuthor: The person who uploaded this media.
type MediaAuthor struct {
	// DisplayName: The author's name.
	DisplayName string `json:"displayName,omitempty"`

	// Id: ID of the author.
	Id string `json:"id,omitempty"`

	// Image: The author's Google profile image.
	Image *MediaAuthorImage `json:"image,omitempty"`

	// Url: A link to the author's Google profile.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DisplayName") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *MediaAuthor) MarshalJSON() ([]byte, error) {
	type noMethod MediaAuthor
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// MediaAuthorImage: The author's Google profile image.
type MediaAuthorImage struct {
	// Url: The URL of the author's profile photo. To resize the image and
	// crop it to a square, append the query string ?sz=x, where x is the
	// dimension in pixels of each side.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Url") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *MediaAuthorImage) MarshalJSON() ([]byte, error) {
	type noMethod MediaAuthorImage
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// MediaExif: Exif information of the media item.
type MediaExif struct {
	// Time: The time the media was captured. Formatted as an RFC 3339
	// timestamp.
	Time string `json:"time,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Time") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *MediaExif) MarshalJSON() ([]byte, error) {
	type noMethod MediaExif
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PeopleFeed struct {
	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Items: The people in this page of results. Each item includes the id,
	// displayName, image, and url for the person. To retrieve additional
	// profile data, see the people.get method.
	Items []*Person `json:"items,omitempty"`

	// Kind: Identifies this resource as a collection of people. Value:
	// "plus#peopleFeed".
	Kind string `json:"kind,omitempty"`

	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// SelfLink: Link to this resource.
	SelfLink string `json:"selfLink,omitempty"`

	// Title: The title of this collection of people.
	Title string `json:"title,omitempty"`

	// TotalItems: The total number of people available in this list. The
	// number of people in a response might be smaller due to paging. This
	// might not be set for all collections.
	TotalItems int64 `json:"totalItems,omitempty"`

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

func (s *PeopleFeed) MarshalJSON() ([]byte, error) {
	type noMethod PeopleFeed
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type Person struct {
	// AboutMe: A short biography for this person.
	AboutMe string `json:"aboutMe,omitempty"`

	// Birthday: The person's date of birth, represented as YYYY-MM-DD.
	Birthday string `json:"birthday,omitempty"`

	// BraggingRights: The "bragging rights" line of this person.
	BraggingRights string `json:"braggingRights,omitempty"`

	// CircledByCount: For followers who are visible, the number of people
	// who have added this person or page to a circle.
	CircledByCount int64 `json:"circledByCount,omitempty"`

	// Cover: The cover photo content.
	Cover *PersonCover `json:"cover,omitempty"`

	// CurrentLocation: (this field is not currently used)
	CurrentLocation string `json:"currentLocation,omitempty"`

	// DisplayName: The name of this person, which is suitable for display.
	DisplayName string `json:"displayName,omitempty"`

	// Domain: The hosted domain name for the user's Google Apps account.
	// For instance, example.com. The plus.profile.emails.read or email
	// scope is needed to get this domain name.
	Domain string `json:"domain,omitempty"`

	// Emails: A list of email addresses that this person has, including
	// their Google account email address, and the public verified email
	// addresses on their Google+ profile. The plus.profile.emails.read
	// scope is needed to retrieve these email addresses, or the email scope
	// can be used to retrieve just the Google account email address.
	Emails []*PersonEmails `json:"emails,omitempty"`

	// Etag: ETag of this response for caching purposes.
	Etag string `json:"etag,omitempty"`

	// Gender: The person's gender. Possible values include, but are not
	// limited to, the following values:
	// - "male" - Male gender.
	// - "female" - Female gender.
	// - "other" - Other.
	Gender string `json:"gender,omitempty"`

	// Id: The ID of this person.
	Id string `json:"id,omitempty"`

	// Image: The representation of the person's profile photo.
	Image *PersonImage `json:"image,omitempty"`

	// IsPlusUser: Whether this user has signed up for Google+.
	IsPlusUser bool `json:"isPlusUser,omitempty"`

	// Kind: Identifies this resource as a person. Value: "plus#person".
	Kind string `json:"kind,omitempty"`

	// Name: An object representation of the individual components of a
	// person's name.
	Name *PersonName `json:"name,omitempty"`

	// Nickname: The nickname of this person.
	Nickname string `json:"nickname,omitempty"`

	// ObjectType: Type of person within Google+. Possible values include,
	// but are not limited to, the following values:
	// - "person" - represents an actual person.
	// - "page" - represents a page.
	ObjectType string `json:"objectType,omitempty"`

	// Occupation: The occupation of this person.
	Occupation string `json:"occupation,omitempty"`

	// Organizations: A list of current or past organizations with which
	// this person is associated.
	Organizations []*PersonOrganizations `json:"organizations,omitempty"`

	// PlacesLived: A list of places where this person has lived.
	PlacesLived []*PersonPlacesLived `json:"placesLived,omitempty"`

	// PlusOneCount: If a Google+ Page, the number of people who have +1'd
	// this page.
	PlusOneCount int64 `json:"plusOneCount,omitempty"`

	// RelationshipStatus: The person's relationship status. Possible values
	// include, but are not limited to, the following values:
	// - "single" - Person is single.
	// - "in_a_relationship" - Person is in a relationship.
	// - "engaged" - Person is engaged.
	// - "married" - Person is married.
	// - "its_complicated" - The relationship is complicated.
	// - "open_relationship" - Person is in an open relationship.
	// - "widowed" - Person is widowed.
	// - "in_domestic_partnership" - Person is in a domestic partnership.
	// - "in_civil_union" - Person is in a civil union.
	RelationshipStatus string `json:"relationshipStatus,omitempty"`

	// Skills: The person's skills.
	Skills string `json:"skills,omitempty"`

	// Tagline: The brief description (tagline) of this person.
	Tagline string `json:"tagline,omitempty"`

	// Url: The URL of this person's profile.
	Url string `json:"url,omitempty"`

	// Urls: A list of URLs for this person.
	Urls []*PersonUrls `json:"urls,omitempty"`

	// Verified: Whether the person or Google+ Page has been verified.
	Verified bool `json:"verified,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AboutMe") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Person) MarshalJSON() ([]byte, error) {
	type noMethod Person
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PersonCover: The cover photo content.
type PersonCover struct {
	// CoverInfo: Extra information about the cover photo.
	CoverInfo *PersonCoverCoverInfo `json:"coverInfo,omitempty"`

	// CoverPhoto: The person's primary cover image.
	CoverPhoto *PersonCoverCoverPhoto `json:"coverPhoto,omitempty"`

	// Layout: The layout of the cover art. Possible values include, but are
	// not limited to, the following values:
	// - "banner" - One large image banner.
	Layout string `json:"layout,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CoverInfo") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PersonCover) MarshalJSON() ([]byte, error) {
	type noMethod PersonCover
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PersonCoverCoverInfo: Extra information about the cover photo.
type PersonCoverCoverInfo struct {
	// LeftImageOffset: The difference between the left position of the
	// cover image and the actual displayed cover image. Only valid for
	// banner layout.
	LeftImageOffset int64 `json:"leftImageOffset,omitempty"`

	// TopImageOffset: The difference between the top position of the cover
	// image and the actual displayed cover image. Only valid for banner
	// layout.
	TopImageOffset int64 `json:"topImageOffset,omitempty"`

	// ForceSendFields is a list of field names (e.g. "LeftImageOffset") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PersonCoverCoverInfo) MarshalJSON() ([]byte, error) {
	type noMethod PersonCoverCoverInfo
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PersonCoverCoverPhoto: The person's primary cover image.
type PersonCoverCoverPhoto struct {
	// Height: The height of the image.
	Height int64 `json:"height,omitempty"`

	// Url: The URL of the image.
	Url string `json:"url,omitempty"`

	// Width: The width of the image.
	Width int64 `json:"width,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Height") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PersonCoverCoverPhoto) MarshalJSON() ([]byte, error) {
	type noMethod PersonCoverCoverPhoto
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PersonEmails struct {
	// Type: The type of address. Possible values include, but are not
	// limited to, the following values:
	// - "account" - Google account email address.
	// - "home" - Home email address.
	// - "work" - Work email address.
	// - "other" - Other.
	Type string `json:"type,omitempty"`

	// Value: The email address.
	Value string `json:"value,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Type") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PersonEmails) MarshalJSON() ([]byte, error) {
	type noMethod PersonEmails
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PersonImage: The representation of the person's profile photo.
type PersonImage struct {
	// IsDefault: Whether the person's profile photo is the default one
	IsDefault bool `json:"isDefault,omitempty"`

	// Url: The URL of the person's profile photo. To resize the image and
	// crop it to a square, append the query string ?sz=x, where x is the
	// dimension in pixels of each side.
	Url string `json:"url,omitempty"`

	// ForceSendFields is a list of field names (e.g. "IsDefault") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PersonImage) MarshalJSON() ([]byte, error) {
	type noMethod PersonImage
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PersonName: An object representation of the individual components of
// a person's name.
type PersonName struct {
	// FamilyName: The family name (last name) of this person.
	FamilyName string `json:"familyName,omitempty"`

	// Formatted: The full name of this person, including middle names,
	// suffixes, etc.
	Formatted string `json:"formatted,omitempty"`

	// GivenName: The given name (first name) of this person.
	GivenName string `json:"givenName,omitempty"`

	// HonorificPrefix: The honorific prefixes (such as "Dr." or "Mrs.") for
	// this person.
	HonorificPrefix string `json:"honorificPrefix,omitempty"`

	// HonorificSuffix: The honorific suffixes (such as "Jr.") for this
	// person.
	HonorificSuffix string `json:"honorificSuffix,omitempty"`

	// MiddleName: The middle name of this person.
	MiddleName string `json:"middleName,omitempty"`

	// ForceSendFields is a list of field names (e.g. "FamilyName") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PersonName) MarshalJSON() ([]byte, error) {
	type noMethod PersonName
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PersonOrganizations struct {
	// Department: The department within the organization. Deprecated.
	Department string `json:"department,omitempty"`

	// Description: A short description of the person's role in this
	// organization. Deprecated.
	Description string `json:"description,omitempty"`

	// EndDate: The date that the person left this organization.
	EndDate string `json:"endDate,omitempty"`

	// Location: The location of this organization. Deprecated.
	Location string `json:"location,omitempty"`

	// Name: The name of the organization.
	Name string `json:"name,omitempty"`

	// Primary: If "true", indicates this organization is the person's
	// primary one, which is typically interpreted as the current one.
	Primary bool `json:"primary,omitempty"`

	// StartDate: The date that the person joined this organization.
	StartDate string `json:"startDate,omitempty"`

	// Title: The person's job title or role within the organization.
	Title string `json:"title,omitempty"`

	// Type: The type of organization. Possible values include, but are not
	// limited to, the following values:
	// - "work" - Work.
	// - "school" - School.
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Department") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PersonOrganizations) MarshalJSON() ([]byte, error) {
	type noMethod PersonOrganizations
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PersonPlacesLived struct {
	// Primary: If "true", this place of residence is this person's primary
	// residence.
	Primary bool `json:"primary,omitempty"`

	// Value: A place where this person has lived. For example: "Seattle,
	// WA", "Near Toronto".
	Value string `json:"value,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Primary") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PersonPlacesLived) MarshalJSON() ([]byte, error) {
	type noMethod PersonPlacesLived
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PersonUrls struct {
	// Label: The label of the URL.
	Label string `json:"label,omitempty"`

	// Type: The type of URL. Possible values include, but are not limited
	// to, the following values:
	// - "otherProfile" - URL for another profile.
	// - "contributor" - URL to a site for which this person is a
	// contributor.
	// - "website" - URL for this Google+ Page's primary website.
	// - "other" - Other URL.
	Type string `json:"type,omitempty"`

	// Value: The URL value.
	Value string `json:"value,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Label") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PersonUrls) MarshalJSON() ([]byte, error) {
	type noMethod PersonUrls
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type Place struct {
	// Address: The physical address of the place.
	Address *PlaceAddress `json:"address,omitempty"`

	// DisplayName: The display name of the place.
	DisplayName string `json:"displayName,omitempty"`

	// Id: The id of the place.
	Id string `json:"id,omitempty"`

	// Kind: Identifies this resource as a place. Value: "plus#place".
	Kind string `json:"kind,omitempty"`

	// Position: The position of the place.
	Position *PlacePosition `json:"position,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Address") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Place) MarshalJSON() ([]byte, error) {
	type noMethod Place
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlaceAddress: The physical address of the place.
type PlaceAddress struct {
	// Formatted: The formatted address for display.
	Formatted string `json:"formatted,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Formatted") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlaceAddress) MarshalJSON() ([]byte, error) {
	type noMethod PlaceAddress
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PlacePosition: The position of the place.
type PlacePosition struct {
	// Latitude: The latitude of this position.
	Latitude float64 `json:"latitude,omitempty"`

	// Longitude: The longitude of this position.
	Longitude float64 `json:"longitude,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Latitude") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlacePosition) MarshalJSON() ([]byte, error) {
	type noMethod PlacePosition
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type PlusDomainsAclentryResource struct {
	// DisplayName: A descriptive name for this entry. Suitable for display.
	DisplayName string `json:"displayName,omitempty"`

	// Id: The ID of the entry. For entries of type "person" or "circle",
	// this is the ID of the resource. For other types, this property is not
	// set.
	Id string `json:"id,omitempty"`

	// Type: The type of entry describing to whom access is granted.
	// Possible values are:
	// - "person" - Access to an individual.
	// - "circle" - Access to members of a circle.
	// - "myCircles" - Access to members of all the person's circles.
	// - "extendedCircles" - Access to members of all the person's circles,
	// plus all of the people in their circles.
	// - "domain" - Access to members of the person's Google Apps domain.
	// - "public" - Access to anyone on the web.
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DisplayName") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PlusDomainsAclentryResource) MarshalJSON() ([]byte, error) {
	type noMethod PlusDomainsAclentryResource
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type Videostream struct {
	// Height: The height, in pixels, of the video resource.
	Height int64 `json:"height,omitempty"`

	// Type: MIME type of the video stream.
	Type string `json:"type,omitempty"`

	// Url: URL of the video stream.
	Url string `json:"url,omitempty"`

	// Width: The width, in pixels, of the video resource.
	Width int64 `json:"width,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Height") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Videostream) MarshalJSON() ([]byte, error) {
	type noMethod Videostream
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "plusDomains.activities.get":

type ActivitiesGetCall struct {
	s          *Service
	activityId string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// Get: Get an activity.
func (r *ActivitiesService) Get(activityId string) *ActivitiesGetCall {
	c := &ActivitiesGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.activityId = activityId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ActivitiesGetCall) Fields(s ...googleapi.Field) *ActivitiesGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ActivitiesGetCall) IfNoneMatch(entityTag string) *ActivitiesGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ActivitiesGetCall) Context(ctx context.Context) *ActivitiesGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ActivitiesGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "activities/{activityId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"activityId": c.activityId,
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

// Do executes the "plusDomains.activities.get" call.
// Exactly one of *Activity or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Activity.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ActivitiesGetCall) Do() (*Activity, error) {
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
	ret := &Activity{
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
	//   "description": "Get an activity.",
	//   "httpMethod": "GET",
	//   "id": "plusDomains.activities.get",
	//   "parameterOrder": [
	//     "activityId"
	//   ],
	//   "parameters": {
	//     "activityId": {
	//       "description": "The ID of the activity to get.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "activities/{activityId}",
	//   "response": {
	//     "$ref": "Activity"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.login",
	//     "https://www.googleapis.com/auth/plus.me",
	//     "https://www.googleapis.com/auth/plus.stream.read"
	//   ]
	// }

}

// method id "plusDomains.activities.insert":

type ActivitiesInsertCall struct {
	s        *Service
	userId   string
	activity *Activity
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Insert: Create a new activity for the authenticated user.
func (r *ActivitiesService) Insert(userId string, activity *Activity) *ActivitiesInsertCall {
	c := &ActivitiesInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.userId = userId
	c.activity = activity
	return c
}

// Preview sets the optional parameter "preview": If "true", extract the
// potential media attachments for a URL. The response will include all
// possible attachments for a URL, including video, photos, and articles
// based on the content of the page.
func (c *ActivitiesInsertCall) Preview(preview bool) *ActivitiesInsertCall {
	c.opt_["preview"] = preview
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ActivitiesInsertCall) Fields(s ...googleapi.Field) *ActivitiesInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ActivitiesInsertCall) Context(ctx context.Context) *ActivitiesInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *ActivitiesInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.activity)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["preview"]; ok {
		params.Set("preview", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "people/{userId}/activities")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"userId": c.userId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "plusDomains.activities.insert" call.
// Exactly one of *Activity or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Activity.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ActivitiesInsertCall) Do() (*Activity, error) {
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
	ret := &Activity{
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
	//   "description": "Create a new activity for the authenticated user.",
	//   "httpMethod": "POST",
	//   "id": "plusDomains.activities.insert",
	//   "parameterOrder": [
	//     "userId"
	//   ],
	//   "parameters": {
	//     "preview": {
	//       "description": "If \"true\", extract the potential media attachments for a URL. The response will include all possible attachments for a URL, including video, photos, and articles based on the content of the page.",
	//       "location": "query",
	//       "type": "boolean"
	//     },
	//     "userId": {
	//       "description": "The ID of the user to create the activity on behalf of. Its value should be \"me\", to indicate the authenticated user.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "people/{userId}/activities",
	//   "request": {
	//     "$ref": "Activity"
	//   },
	//   "response": {
	//     "$ref": "Activity"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.login",
	//     "https://www.googleapis.com/auth/plus.me",
	//     "https://www.googleapis.com/auth/plus.stream.write"
	//   ]
	// }

}

// method id "plusDomains.activities.list":

type ActivitiesListCall struct {
	s          *Service
	userId     string
	collection string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// List: List all of the activities in the specified collection for a
// particular user.
func (r *ActivitiesService) List(userId string, collection string) *ActivitiesListCall {
	c := &ActivitiesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.userId = userId
	c.collection = collection
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of activities to include in the response, which is used for
// paging. For any response, the actual number returned might be less
// than the specified maxResults.
func (c *ActivitiesListCall) MaxResults(maxResults int64) *ActivitiesListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The continuation
// token, which is used to page through large result sets. To get the
// next page of results, set this parameter to the value of
// "nextPageToken" from the previous response.
func (c *ActivitiesListCall) PageToken(pageToken string) *ActivitiesListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ActivitiesListCall) Fields(s ...googleapi.Field) *ActivitiesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ActivitiesListCall) IfNoneMatch(entityTag string) *ActivitiesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ActivitiesListCall) Context(ctx context.Context) *ActivitiesListCall {
	c.ctx_ = ctx
	return c
}

func (c *ActivitiesListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "people/{userId}/activities/{collection}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"userId":     c.userId,
		"collection": c.collection,
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

// Do executes the "plusDomains.activities.list" call.
// Exactly one of *ActivityFeed or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ActivityFeed.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ActivitiesListCall) Do() (*ActivityFeed, error) {
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
	ret := &ActivityFeed{
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
	//   "description": "List all of the activities in the specified collection for a particular user.",
	//   "httpMethod": "GET",
	//   "id": "plusDomains.activities.list",
	//   "parameterOrder": [
	//     "userId",
	//     "collection"
	//   ],
	//   "parameters": {
	//     "collection": {
	//       "description": "The collection of activities to list.",
	//       "enum": [
	//         "user"
	//       ],
	//       "enumDescriptions": [
	//         "All activities created by the specified user that the authenticated user is authorized to view."
	//       ],
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "20",
	//       "description": "The maximum number of activities to include in the response, which is used for paging. For any response, the actual number returned might be less than the specified maxResults.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The continuation token, which is used to page through large result sets. To get the next page of results, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "userId": {
	//       "description": "The ID of the user to get activities for. The special value \"me\" can be used to indicate the authenticated user.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "people/{userId}/activities/{collection}",
	//   "response": {
	//     "$ref": "ActivityFeed"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.login",
	//     "https://www.googleapis.com/auth/plus.me",
	//     "https://www.googleapis.com/auth/plus.stream.read"
	//   ]
	// }

}

// method id "plusDomains.audiences.list":

type AudiencesListCall struct {
	s      *Service
	userId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// List: List all of the audiences to which a user can share.
func (r *AudiencesService) List(userId string) *AudiencesListCall {
	c := &AudiencesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.userId = userId
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of circles to include in the response, which is used for
// paging. For any response, the actual number returned might be less
// than the specified maxResults.
func (c *AudiencesListCall) MaxResults(maxResults int64) *AudiencesListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The continuation
// token, which is used to page through large result sets. To get the
// next page of results, set this parameter to the value of
// "nextPageToken" from the previous response.
func (c *AudiencesListCall) PageToken(pageToken string) *AudiencesListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AudiencesListCall) Fields(s ...googleapi.Field) *AudiencesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AudiencesListCall) IfNoneMatch(entityTag string) *AudiencesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AudiencesListCall) Context(ctx context.Context) *AudiencesListCall {
	c.ctx_ = ctx
	return c
}

func (c *AudiencesListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "people/{userId}/audiences")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"userId": c.userId,
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

// Do executes the "plusDomains.audiences.list" call.
// Exactly one of *AudiencesFeed or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *AudiencesFeed.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AudiencesListCall) Do() (*AudiencesFeed, error) {
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
	ret := &AudiencesFeed{
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
	//   "description": "List all of the audiences to which a user can share.",
	//   "httpMethod": "GET",
	//   "id": "plusDomains.audiences.list",
	//   "parameterOrder": [
	//     "userId"
	//   ],
	//   "parameters": {
	//     "maxResults": {
	//       "default": "20",
	//       "description": "The maximum number of circles to include in the response, which is used for paging. For any response, the actual number returned might be less than the specified maxResults.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The continuation token, which is used to page through large result sets. To get the next page of results, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "userId": {
	//       "description": "The ID of the user to get audiences for. The special value \"me\" can be used to indicate the authenticated user.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "people/{userId}/audiences",
	//   "response": {
	//     "$ref": "AudiencesFeed"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.circles.read",
	//     "https://www.googleapis.com/auth/plus.login",
	//     "https://www.googleapis.com/auth/plus.me"
	//   ]
	// }

}

// method id "plusDomains.circles.addPeople":

type CirclesAddPeopleCall struct {
	s        *Service
	circleId string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// AddPeople: Add a person to a circle. Google+ limits certain circle
// operations, including the number of circle adds. Learn More.
func (r *CirclesService) AddPeople(circleId string) *CirclesAddPeopleCall {
	c := &CirclesAddPeopleCall{s: r.s, opt_: make(map[string]interface{})}
	c.circleId = circleId
	return c
}

// Email sets the optional parameter "email": Email of the people to add
// to the circle. Optional, can be repeated.
func (c *CirclesAddPeopleCall) Email(email string) *CirclesAddPeopleCall {
	c.opt_["email"] = email
	return c
}

// UserId sets the optional parameter "userId": IDs of the people to add
// to the circle. Optional, can be repeated.
func (c *CirclesAddPeopleCall) UserId(userId string) *CirclesAddPeopleCall {
	c.opt_["userId"] = userId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CirclesAddPeopleCall) Fields(s ...googleapi.Field) *CirclesAddPeopleCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CirclesAddPeopleCall) Context(ctx context.Context) *CirclesAddPeopleCall {
	c.ctx_ = ctx
	return c
}

func (c *CirclesAddPeopleCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["email"]; ok {
		params.Set("email", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["userId"]; ok {
		params.Set("userId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "circles/{circleId}/people")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"circleId": c.circleId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "plusDomains.circles.addPeople" call.
// Exactly one of *Circle or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Circle.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CirclesAddPeopleCall) Do() (*Circle, error) {
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
	ret := &Circle{
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
	//   "description": "Add a person to a circle. Google+ limits certain circle operations, including the number of circle adds. Learn More.",
	//   "httpMethod": "PUT",
	//   "id": "plusDomains.circles.addPeople",
	//   "parameterOrder": [
	//     "circleId"
	//   ],
	//   "parameters": {
	//     "circleId": {
	//       "description": "The ID of the circle to add the person to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "email": {
	//       "description": "Email of the people to add to the circle. Optional, can be repeated.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "userId": {
	//       "description": "IDs of the people to add to the circle. Optional, can be repeated.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "circles/{circleId}/people",
	//   "response": {
	//     "$ref": "Circle"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.circles.write",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "plusDomains.circles.get":

type CirclesGetCall struct {
	s        *Service
	circleId string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Get: Get a circle.
func (r *CirclesService) Get(circleId string) *CirclesGetCall {
	c := &CirclesGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.circleId = circleId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CirclesGetCall) Fields(s ...googleapi.Field) *CirclesGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *CirclesGetCall) IfNoneMatch(entityTag string) *CirclesGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CirclesGetCall) Context(ctx context.Context) *CirclesGetCall {
	c.ctx_ = ctx
	return c
}

func (c *CirclesGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "circles/{circleId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"circleId": c.circleId,
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

// Do executes the "plusDomains.circles.get" call.
// Exactly one of *Circle or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Circle.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CirclesGetCall) Do() (*Circle, error) {
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
	ret := &Circle{
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
	//   "description": "Get a circle.",
	//   "httpMethod": "GET",
	//   "id": "plusDomains.circles.get",
	//   "parameterOrder": [
	//     "circleId"
	//   ],
	//   "parameters": {
	//     "circleId": {
	//       "description": "The ID of the circle to get.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "circles/{circleId}",
	//   "response": {
	//     "$ref": "Circle"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.circles.read",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "plusDomains.circles.insert":

type CirclesInsertCall struct {
	s      *Service
	userId string
	circle *Circle
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Insert: Create a new circle for the authenticated user.
func (r *CirclesService) Insert(userId string, circle *Circle) *CirclesInsertCall {
	c := &CirclesInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.userId = userId
	c.circle = circle
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CirclesInsertCall) Fields(s ...googleapi.Field) *CirclesInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CirclesInsertCall) Context(ctx context.Context) *CirclesInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *CirclesInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.circle)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "people/{userId}/circles")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"userId": c.userId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "plusDomains.circles.insert" call.
// Exactly one of *Circle or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Circle.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CirclesInsertCall) Do() (*Circle, error) {
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
	ret := &Circle{
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
	//   "description": "Create a new circle for the authenticated user.",
	//   "httpMethod": "POST",
	//   "id": "plusDomains.circles.insert",
	//   "parameterOrder": [
	//     "userId"
	//   ],
	//   "parameters": {
	//     "userId": {
	//       "description": "The ID of the user to create the circle on behalf of. The value \"me\" can be used to indicate the authenticated user.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "people/{userId}/circles",
	//   "request": {
	//     "$ref": "Circle"
	//   },
	//   "response": {
	//     "$ref": "Circle"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.circles.write",
	//     "https://www.googleapis.com/auth/plus.login",
	//     "https://www.googleapis.com/auth/plus.me"
	//   ]
	// }

}

// method id "plusDomains.circles.list":

type CirclesListCall struct {
	s      *Service
	userId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// List: List all of the circles for a user.
func (r *CirclesService) List(userId string) *CirclesListCall {
	c := &CirclesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.userId = userId
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of circles to include in the response, which is used for
// paging. For any response, the actual number returned might be less
// than the specified maxResults.
func (c *CirclesListCall) MaxResults(maxResults int64) *CirclesListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The continuation
// token, which is used to page through large result sets. To get the
// next page of results, set this parameter to the value of
// "nextPageToken" from the previous response.
func (c *CirclesListCall) PageToken(pageToken string) *CirclesListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CirclesListCall) Fields(s ...googleapi.Field) *CirclesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *CirclesListCall) IfNoneMatch(entityTag string) *CirclesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CirclesListCall) Context(ctx context.Context) *CirclesListCall {
	c.ctx_ = ctx
	return c
}

func (c *CirclesListCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "people/{userId}/circles")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"userId": c.userId,
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

// Do executes the "plusDomains.circles.list" call.
// Exactly one of *CircleFeed or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CircleFeed.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *CirclesListCall) Do() (*CircleFeed, error) {
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
	ret := &CircleFeed{
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
	//   "description": "List all of the circles for a user.",
	//   "httpMethod": "GET",
	//   "id": "plusDomains.circles.list",
	//   "parameterOrder": [
	//     "userId"
	//   ],
	//   "parameters": {
	//     "maxResults": {
	//       "default": "20",
	//       "description": "The maximum number of circles to include in the response, which is used for paging. For any response, the actual number returned might be less than the specified maxResults.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The continuation token, which is used to page through large result sets. To get the next page of results, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "userId": {
	//       "description": "The ID of the user to get circles for. The special value \"me\" can be used to indicate the authenticated user.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "people/{userId}/circles",
	//   "response": {
	//     "$ref": "CircleFeed"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.circles.read",
	//     "https://www.googleapis.com/auth/plus.login",
	//     "https://www.googleapis.com/auth/plus.me"
	//   ]
	// }

}

// method id "plusDomains.circles.patch":

type CirclesPatchCall struct {
	s        *Service
	circleId string
	circle   *Circle
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Patch: Update a circle's description. This method supports patch
// semantics.
func (r *CirclesService) Patch(circleId string, circle *Circle) *CirclesPatchCall {
	c := &CirclesPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.circleId = circleId
	c.circle = circle
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CirclesPatchCall) Fields(s ...googleapi.Field) *CirclesPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CirclesPatchCall) Context(ctx context.Context) *CirclesPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *CirclesPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.circle)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "circles/{circleId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"circleId": c.circleId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "plusDomains.circles.patch" call.
// Exactly one of *Circle or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Circle.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CirclesPatchCall) Do() (*Circle, error) {
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
	ret := &Circle{
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
	//   "description": "Update a circle's description. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "plusDomains.circles.patch",
	//   "parameterOrder": [
	//     "circleId"
	//   ],
	//   "parameters": {
	//     "circleId": {
	//       "description": "The ID of the circle to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "circles/{circleId}",
	//   "request": {
	//     "$ref": "Circle"
	//   },
	//   "response": {
	//     "$ref": "Circle"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.circles.write",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "plusDomains.circles.remove":

type CirclesRemoveCall struct {
	s        *Service
	circleId string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Remove: Delete a circle.
func (r *CirclesService) Remove(circleId string) *CirclesRemoveCall {
	c := &CirclesRemoveCall{s: r.s, opt_: make(map[string]interface{})}
	c.circleId = circleId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CirclesRemoveCall) Fields(s ...googleapi.Field) *CirclesRemoveCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CirclesRemoveCall) Context(ctx context.Context) *CirclesRemoveCall {
	c.ctx_ = ctx
	return c
}

func (c *CirclesRemoveCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "circles/{circleId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"circleId": c.circleId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "plusDomains.circles.remove" call.
func (c *CirclesRemoveCall) Do() error {
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
	//   "description": "Delete a circle.",
	//   "httpMethod": "DELETE",
	//   "id": "plusDomains.circles.remove",
	//   "parameterOrder": [
	//     "circleId"
	//   ],
	//   "parameters": {
	//     "circleId": {
	//       "description": "The ID of the circle to delete.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "circles/{circleId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.circles.write",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "plusDomains.circles.removePeople":

type CirclesRemovePeopleCall struct {
	s        *Service
	circleId string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// RemovePeople: Remove a person from a circle.
func (r *CirclesService) RemovePeople(circleId string) *CirclesRemovePeopleCall {
	c := &CirclesRemovePeopleCall{s: r.s, opt_: make(map[string]interface{})}
	c.circleId = circleId
	return c
}

// Email sets the optional parameter "email": Email of the people to add
// to the circle. Optional, can be repeated.
func (c *CirclesRemovePeopleCall) Email(email string) *CirclesRemovePeopleCall {
	c.opt_["email"] = email
	return c
}

// UserId sets the optional parameter "userId": IDs of the people to
// remove from the circle. Optional, can be repeated.
func (c *CirclesRemovePeopleCall) UserId(userId string) *CirclesRemovePeopleCall {
	c.opt_["userId"] = userId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CirclesRemovePeopleCall) Fields(s ...googleapi.Field) *CirclesRemovePeopleCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CirclesRemovePeopleCall) Context(ctx context.Context) *CirclesRemovePeopleCall {
	c.ctx_ = ctx
	return c
}

func (c *CirclesRemovePeopleCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["email"]; ok {
		params.Set("email", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["userId"]; ok {
		params.Set("userId", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "circles/{circleId}/people")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"circleId": c.circleId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "plusDomains.circles.removePeople" call.
func (c *CirclesRemovePeopleCall) Do() error {
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
	//   "description": "Remove a person from a circle.",
	//   "httpMethod": "DELETE",
	//   "id": "plusDomains.circles.removePeople",
	//   "parameterOrder": [
	//     "circleId"
	//   ],
	//   "parameters": {
	//     "circleId": {
	//       "description": "The ID of the circle to remove the person from.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "email": {
	//       "description": "Email of the people to add to the circle. Optional, can be repeated.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "userId": {
	//       "description": "IDs of the people to remove from the circle. Optional, can be repeated.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "circles/{circleId}/people",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.circles.write",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "plusDomains.circles.update":

type CirclesUpdateCall struct {
	s        *Service
	circleId string
	circle   *Circle
	opt_     map[string]interface{}
	ctx_     context.Context
}

// Update: Update a circle's description.
func (r *CirclesService) Update(circleId string, circle *Circle) *CirclesUpdateCall {
	c := &CirclesUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.circleId = circleId
	c.circle = circle
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CirclesUpdateCall) Fields(s ...googleapi.Field) *CirclesUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CirclesUpdateCall) Context(ctx context.Context) *CirclesUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *CirclesUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.circle)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "circles/{circleId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"circleId": c.circleId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "plusDomains.circles.update" call.
// Exactly one of *Circle or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Circle.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CirclesUpdateCall) Do() (*Circle, error) {
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
	ret := &Circle{
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
	//   "description": "Update a circle's description.",
	//   "httpMethod": "PUT",
	//   "id": "plusDomains.circles.update",
	//   "parameterOrder": [
	//     "circleId"
	//   ],
	//   "parameters": {
	//     "circleId": {
	//       "description": "The ID of the circle to update.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "circles/{circleId}",
	//   "request": {
	//     "$ref": "Circle"
	//   },
	//   "response": {
	//     "$ref": "Circle"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.circles.write",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}

// method id "plusDomains.comments.get":

type CommentsGetCall struct {
	s         *Service
	commentId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Get a comment.
func (r *CommentsService) Get(commentId string) *CommentsGetCall {
	c := &CommentsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.commentId = commentId
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
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "comments/{commentId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
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

// Do executes the "plusDomains.comments.get" call.
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
	//   "description": "Get a comment.",
	//   "httpMethod": "GET",
	//   "id": "plusDomains.comments.get",
	//   "parameterOrder": [
	//     "commentId"
	//   ],
	//   "parameters": {
	//     "commentId": {
	//       "description": "The ID of the comment to get.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "comments/{commentId}",
	//   "response": {
	//     "$ref": "Comment"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.login",
	//     "https://www.googleapis.com/auth/plus.stream.read"
	//   ]
	// }

}

// method id "plusDomains.comments.insert":

type CommentsInsertCall struct {
	s          *Service
	activityId string
	comment    *Comment
	opt_       map[string]interface{}
	ctx_       context.Context
}

// Insert: Create a new comment in reply to an activity.
func (r *CommentsService) Insert(activityId string, comment *Comment) *CommentsInsertCall {
	c := &CommentsInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.activityId = activityId
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "activities/{activityId}/comments")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"activityId": c.activityId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "plusDomains.comments.insert" call.
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
	//   "description": "Create a new comment in reply to an activity.",
	//   "httpMethod": "POST",
	//   "id": "plusDomains.comments.insert",
	//   "parameterOrder": [
	//     "activityId"
	//   ],
	//   "parameters": {
	//     "activityId": {
	//       "description": "The ID of the activity to reply to.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "activities/{activityId}/comments",
	//   "request": {
	//     "$ref": "Comment"
	//   },
	//   "response": {
	//     "$ref": "Comment"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.login",
	//     "https://www.googleapis.com/auth/plus.stream.write"
	//   ]
	// }

}

// method id "plusDomains.comments.list":

type CommentsListCall struct {
	s          *Service
	activityId string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// List: List all of the comments for an activity.
func (r *CommentsService) List(activityId string) *CommentsListCall {
	c := &CommentsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.activityId = activityId
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of comments to include in the response, which is used for
// paging. For any response, the actual number returned might be less
// than the specified maxResults.
func (c *CommentsListCall) MaxResults(maxResults int64) *CommentsListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The continuation
// token, which is used to page through large result sets. To get the
// next page of results, set this parameter to the value of
// "nextPageToken" from the previous response.
func (c *CommentsListCall) PageToken(pageToken string) *CommentsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// SortOrder sets the optional parameter "sortOrder": The order in which
// to sort the list of comments.
//
// Possible values:
//   "ascending" (default) - Sort oldest comments first.
//   "descending" - Sort newest comments first.
func (c *CommentsListCall) SortOrder(sortOrder string) *CommentsListCall {
	c.opt_["sortOrder"] = sortOrder
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
	if v, ok := c.opt_["maxResults"]; ok {
		params.Set("maxResults", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["sortOrder"]; ok {
		params.Set("sortOrder", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "activities/{activityId}/comments")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"activityId": c.activityId,
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

// Do executes the "plusDomains.comments.list" call.
// Exactly one of *CommentFeed or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *CommentFeed.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *CommentsListCall) Do() (*CommentFeed, error) {
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
	ret := &CommentFeed{
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
	//   "description": "List all of the comments for an activity.",
	//   "httpMethod": "GET",
	//   "id": "plusDomains.comments.list",
	//   "parameterOrder": [
	//     "activityId"
	//   ],
	//   "parameters": {
	//     "activityId": {
	//       "description": "The ID of the activity to get comments for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "20",
	//       "description": "The maximum number of comments to include in the response, which is used for paging. For any response, the actual number returned might be less than the specified maxResults.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "500",
	//       "minimum": "0",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The continuation token, which is used to page through large result sets. To get the next page of results, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "sortOrder": {
	//       "default": "ascending",
	//       "description": "The order in which to sort the list of comments.",
	//       "enum": [
	//         "ascending",
	//         "descending"
	//       ],
	//       "enumDescriptions": [
	//         "Sort oldest comments first.",
	//         "Sort newest comments first."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "activities/{activityId}/comments",
	//   "response": {
	//     "$ref": "CommentFeed"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.login",
	//     "https://www.googleapis.com/auth/plus.stream.read"
	//   ]
	// }

}

// method id "plusDomains.media.insert":

type MediaInsertCall struct {
	s          *Service
	userId     string
	collection string
	media      *Media
	opt_       map[string]interface{}
	media_     io.Reader
	resumable_ googleapi.SizeReaderAt
	mediaType_ string
	protocol_  string
	ctx_       context.Context
}

// Insert: Add a new media item to an album. The current upload size
// limitations are 36MB for a photo and 1GB for a video. Uploads do not
// count against quota if photos are less than 2048 pixels on their
// longest side or videos are less than 15 minutes in length.
func (r *MediaService) Insert(userId string, collection string, media *Media) *MediaInsertCall {
	c := &MediaInsertCall{s: r.s, opt_: make(map[string]interface{})}
	c.userId = userId
	c.collection = collection
	c.media = media
	return c
}

// Media specifies the media to upload in a single chunk.
// At most one of Media and ResumableMedia may be set.
func (c *MediaInsertCall) Media(r io.Reader) *MediaInsertCall {
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
func (c *MediaInsertCall) ResumableMedia(ctx context.Context, r io.ReaderAt, size int64, mediaType string) *MediaInsertCall {
	c.ctx_ = ctx
	c.resumable_ = io.NewSectionReader(r, 0, size)
	c.mediaType_ = mediaType
	c.protocol_ = "resumable"
	return c
}

// ProgressUpdater provides a callback function that will be called after every chunk.
// It should be a low-latency function in order to not slow down the upload operation.
// This should only be called when using ResumableMedia (as opposed to Media).
func (c *MediaInsertCall) ProgressUpdater(pu googleapi.ProgressUpdater) *MediaInsertCall {
	c.opt_["progressUpdater"] = pu
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *MediaInsertCall) Fields(s ...googleapi.Field) *MediaInsertCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
// This context will supersede any context previously provided to
// the ResumableMedia method.
func (c *MediaInsertCall) Context(ctx context.Context) *MediaInsertCall {
	c.ctx_ = ctx
	return c
}

func (c *MediaInsertCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.media)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "people/{userId}/media/{collection}")
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
	googleapi.Expand(req.URL, map[string]string{
		"userId":     c.userId,
		"collection": c.collection,
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

// Do executes the "plusDomains.media.insert" call.
// Exactly one of *Media or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Media.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *MediaInsertCall) Do() (*Media, error) {
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
	ret := &Media{
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
	//   "description": "Add a new media item to an album. The current upload size limitations are 36MB for a photo and 1GB for a video. Uploads do not count against quota if photos are less than 2048 pixels on their longest side or videos are less than 15 minutes in length.",
	//   "httpMethod": "POST",
	//   "id": "plusDomains.media.insert",
	//   "mediaUpload": {
	//     "accept": [
	//       "image/*",
	//       "video/*"
	//     ],
	//     "protocols": {
	//       "resumable": {
	//         "multipart": true,
	//         "path": "/resumable/upload/plusDomains/v1/people/{userId}/media/{collection}"
	//       },
	//       "simple": {
	//         "multipart": true,
	//         "path": "/upload/plusDomains/v1/people/{userId}/media/{collection}"
	//       }
	//     }
	//   },
	//   "parameterOrder": [
	//     "userId",
	//     "collection"
	//   ],
	//   "parameters": {
	//     "collection": {
	//       "enum": [
	//         "cloud"
	//       ],
	//       "enumDescriptions": [
	//         "Upload the media to share on Google+."
	//       ],
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "userId": {
	//       "description": "The ID of the user to create the activity on behalf of.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "people/{userId}/media/{collection}",
	//   "request": {
	//     "$ref": "Media"
	//   },
	//   "response": {
	//     "$ref": "Media"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.login",
	//     "https://www.googleapis.com/auth/plus.me",
	//     "https://www.googleapis.com/auth/plus.media.upload"
	//   ],
	//   "supportsMediaUpload": true
	// }

}

// method id "plusDomains.people.get":

type PeopleGetCall struct {
	s      *Service
	userId string
	opt_   map[string]interface{}
	ctx_   context.Context
}

// Get: Get a person's profile.
func (r *PeopleService) Get(userId string) *PeopleGetCall {
	c := &PeopleGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.userId = userId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PeopleGetCall) Fields(s ...googleapi.Field) *PeopleGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PeopleGetCall) IfNoneMatch(entityTag string) *PeopleGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PeopleGetCall) Context(ctx context.Context) *PeopleGetCall {
	c.ctx_ = ctx
	return c
}

func (c *PeopleGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "people/{userId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"userId": c.userId,
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

// Do executes the "plusDomains.people.get" call.
// Exactly one of *Person or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Person.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *PeopleGetCall) Do() (*Person, error) {
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
	ret := &Person{
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
	//   "description": "Get a person's profile.",
	//   "httpMethod": "GET",
	//   "id": "plusDomains.people.get",
	//   "parameterOrder": [
	//     "userId"
	//   ],
	//   "parameters": {
	//     "userId": {
	//       "description": "The ID of the person to get the profile for. The special value \"me\" can be used to indicate the authenticated user.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "people/{userId}",
	//   "response": {
	//     "$ref": "Person"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.login",
	//     "https://www.googleapis.com/auth/plus.me",
	//     "https://www.googleapis.com/auth/plus.profiles.read",
	//     "https://www.googleapis.com/auth/userinfo.email",
	//     "https://www.googleapis.com/auth/userinfo.profile"
	//   ]
	// }

}

// method id "plusDomains.people.list":

type PeopleListCall struct {
	s          *Service
	userId     string
	collection string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// List: List all of the people in the specified collection.
func (r *PeopleService) List(userId string, collection string) *PeopleListCall {
	c := &PeopleListCall{s: r.s, opt_: make(map[string]interface{})}
	c.userId = userId
	c.collection = collection
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of people to include in the response, which is used for
// paging. For any response, the actual number returned might be less
// than the specified maxResults.
func (c *PeopleListCall) MaxResults(maxResults int64) *PeopleListCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// OrderBy sets the optional parameter "orderBy": The order to return
// people in.
//
// Possible values:
//   "alphabetical" - Order the people by their display name.
//   "best" - Order people based on the relevence to the viewer.
func (c *PeopleListCall) OrderBy(orderBy string) *PeopleListCall {
	c.opt_["orderBy"] = orderBy
	return c
}

// PageToken sets the optional parameter "pageToken": The continuation
// token, which is used to page through large result sets. To get the
// next page of results, set this parameter to the value of
// "nextPageToken" from the previous response.
func (c *PeopleListCall) PageToken(pageToken string) *PeopleListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PeopleListCall) Fields(s ...googleapi.Field) *PeopleListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PeopleListCall) IfNoneMatch(entityTag string) *PeopleListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PeopleListCall) Context(ctx context.Context) *PeopleListCall {
	c.ctx_ = ctx
	return c
}

func (c *PeopleListCall) doRequest(alt string) (*http.Response, error) {
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
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "people/{userId}/people/{collection}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"userId":     c.userId,
		"collection": c.collection,
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

// Do executes the "plusDomains.people.list" call.
// Exactly one of *PeopleFeed or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *PeopleFeed.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PeopleListCall) Do() (*PeopleFeed, error) {
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
	ret := &PeopleFeed{
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
	//   "description": "List all of the people in the specified collection.",
	//   "httpMethod": "GET",
	//   "id": "plusDomains.people.list",
	//   "parameterOrder": [
	//     "userId",
	//     "collection"
	//   ],
	//   "parameters": {
	//     "collection": {
	//       "description": "The collection of people to list.",
	//       "enum": [
	//         "circled"
	//       ],
	//       "enumDescriptions": [
	//         "The list of people who this user has added to one or more circles."
	//       ],
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "100",
	//       "description": "The maximum number of people to include in the response, which is used for paging. For any response, the actual number returned might be less than the specified maxResults.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "orderBy": {
	//       "description": "The order to return people in.",
	//       "enum": [
	//         "alphabetical",
	//         "best"
	//       ],
	//       "enumDescriptions": [
	//         "Order the people by their display name.",
	//         "Order people based on the relevence to the viewer."
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageToken": {
	//       "description": "The continuation token, which is used to page through large result sets. To get the next page of results, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "userId": {
	//       "description": "Get the collection of people for the person identified. Use \"me\" to indicate the authenticated user.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "people/{userId}/people/{collection}",
	//   "response": {
	//     "$ref": "PeopleFeed"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.circles.read",
	//     "https://www.googleapis.com/auth/plus.login",
	//     "https://www.googleapis.com/auth/plus.me"
	//   ]
	// }

}

// method id "plusDomains.people.listByActivity":

type PeopleListByActivityCall struct {
	s          *Service
	activityId string
	collection string
	opt_       map[string]interface{}
	ctx_       context.Context
}

// ListByActivity: List all of the people in the specified collection
// for a particular activity.
func (r *PeopleService) ListByActivity(activityId string, collection string) *PeopleListByActivityCall {
	c := &PeopleListByActivityCall{s: r.s, opt_: make(map[string]interface{})}
	c.activityId = activityId
	c.collection = collection
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of people to include in the response, which is used for
// paging. For any response, the actual number returned might be less
// than the specified maxResults.
func (c *PeopleListByActivityCall) MaxResults(maxResults int64) *PeopleListByActivityCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The continuation
// token, which is used to page through large result sets. To get the
// next page of results, set this parameter to the value of
// "nextPageToken" from the previous response.
func (c *PeopleListByActivityCall) PageToken(pageToken string) *PeopleListByActivityCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PeopleListByActivityCall) Fields(s ...googleapi.Field) *PeopleListByActivityCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PeopleListByActivityCall) IfNoneMatch(entityTag string) *PeopleListByActivityCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PeopleListByActivityCall) Context(ctx context.Context) *PeopleListByActivityCall {
	c.ctx_ = ctx
	return c
}

func (c *PeopleListByActivityCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "activities/{activityId}/people/{collection}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"activityId": c.activityId,
		"collection": c.collection,
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

// Do executes the "plusDomains.people.listByActivity" call.
// Exactly one of *PeopleFeed or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *PeopleFeed.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PeopleListByActivityCall) Do() (*PeopleFeed, error) {
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
	ret := &PeopleFeed{
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
	//   "description": "List all of the people in the specified collection for a particular activity.",
	//   "httpMethod": "GET",
	//   "id": "plusDomains.people.listByActivity",
	//   "parameterOrder": [
	//     "activityId",
	//     "collection"
	//   ],
	//   "parameters": {
	//     "activityId": {
	//       "description": "The ID of the activity to get the list of people for.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "collection": {
	//       "description": "The collection of people to list.",
	//       "enum": [
	//         "plusoners",
	//         "resharers",
	//         "sharedto"
	//       ],
	//       "enumDescriptions": [
	//         "List all people who have +1'd this activity.",
	//         "List all people who have reshared this activity.",
	//         "List all people who this activity was shared to."
	//       ],
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "20",
	//       "description": "The maximum number of people to include in the response, which is used for paging. For any response, the actual number returned might be less than the specified maxResults.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The continuation token, which is used to page through large result sets. To get the next page of results, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "activities/{activityId}/people/{collection}",
	//   "response": {
	//     "$ref": "PeopleFeed"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.login",
	//     "https://www.googleapis.com/auth/plus.stream.read"
	//   ]
	// }

}

// method id "plusDomains.people.listByCircle":

type PeopleListByCircleCall struct {
	s        *Service
	circleId string
	opt_     map[string]interface{}
	ctx_     context.Context
}

// ListByCircle: List all of the people who are members of a circle.
func (r *PeopleService) ListByCircle(circleId string) *PeopleListByCircleCall {
	c := &PeopleListByCircleCall{s: r.s, opt_: make(map[string]interface{})}
	c.circleId = circleId
	return c
}

// MaxResults sets the optional parameter "maxResults": The maximum
// number of people to include in the response, which is used for
// paging. For any response, the actual number returned might be less
// than the specified maxResults.
func (c *PeopleListByCircleCall) MaxResults(maxResults int64) *PeopleListByCircleCall {
	c.opt_["maxResults"] = maxResults
	return c
}

// PageToken sets the optional parameter "pageToken": The continuation
// token, which is used to page through large result sets. To get the
// next page of results, set this parameter to the value of
// "nextPageToken" from the previous response.
func (c *PeopleListByCircleCall) PageToken(pageToken string) *PeopleListByCircleCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *PeopleListByCircleCall) Fields(s ...googleapi.Field) *PeopleListByCircleCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *PeopleListByCircleCall) IfNoneMatch(entityTag string) *PeopleListByCircleCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *PeopleListByCircleCall) Context(ctx context.Context) *PeopleListByCircleCall {
	c.ctx_ = ctx
	return c
}

func (c *PeopleListByCircleCall) doRequest(alt string) (*http.Response, error) {
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
	urls := googleapi.ResolveRelative(c.s.BasePath, "circles/{circleId}/people")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"circleId": c.circleId,
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

// Do executes the "plusDomains.people.listByCircle" call.
// Exactly one of *PeopleFeed or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *PeopleFeed.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *PeopleListByCircleCall) Do() (*PeopleFeed, error) {
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
	ret := &PeopleFeed{
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
	//   "description": "List all of the people who are members of a circle.",
	//   "httpMethod": "GET",
	//   "id": "plusDomains.people.listByCircle",
	//   "parameterOrder": [
	//     "circleId"
	//   ],
	//   "parameters": {
	//     "circleId": {
	//       "description": "The ID of the circle to get the members of.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "maxResults": {
	//       "default": "20",
	//       "description": "The maximum number of people to include in the response, which is used for paging. For any response, the actual number returned might be less than the specified maxResults.",
	//       "format": "uint32",
	//       "location": "query",
	//       "maximum": "100",
	//       "minimum": "1",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The continuation token, which is used to page through large result sets. To get the next page of results, set this parameter to the value of \"nextPageToken\" from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "circles/{circleId}/people",
	//   "response": {
	//     "$ref": "PeopleFeed"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/plus.circles.read",
	//     "https://www.googleapis.com/auth/plus.login"
	//   ]
	// }

}
